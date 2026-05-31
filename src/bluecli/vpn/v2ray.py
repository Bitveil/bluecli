"""V2Ray backend — full-tunnel via SOCKS5 + tun2socks.

V2Ray only acts as a SOCKS5 proxy. To force ALL traffic through it (the
way WireGuard would), we stack tun2socks on top: a TUN interface that
forwards every packet to v2ray's local SOCKS5 endpoint.

Bring-up sequence:

  1. v2ray boots, binds SOCKS5 on 127.0.0.1:<port>.
  2. Save the system default route so we can punch a hole through it
     for the dVPN node's own IP.
  3. Add a host route to the node IP via the original gateway —
     otherwise packets to the node loop back into the tunnel.
  4. tun2socks boots, creates the TUN device, forwards to the SOCKS.
  5. Install a split-default through the TUN (0.0.0.0/1 + 128.0.0.0/1).
     The system's real default route is left alone, so a crash recovers
     connectivity automatically.

Disconnect mirrors this in reverse, best-effort.

Required bundled binaries (in `bin/v2ray/`):
  - `v2ray` / `v2ray.exe` (v5.x), `tun2socks` / `tun2socks.exe`
    (xjasonlyu/tun2socks), and `wintun.dll` on Windows.
"""

from __future__ import annotations

import functools
import json
import os
import re
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..config import V2RAY_CONF_FILE, bin_path
from . import HandshakeResult, VpnError, fetch_node_credentials
from . import _routing

DEFAULT_SOCKS_PORT = 1080
TUN_NAME = "blue-tun"  # also used by tun2socks's -device flag
TUN_LOCAL_IP = "198.18.0.1"  # IP assigned to the TUN device on every OS


@dataclass
class V2Credentials:
    """Everything we need to bring up the V2Ray tunnel without re-asking
    the node (which would 409). Serializable to plain dicts for state.json."""

    uuid_hex: str  # 32 chars, the 16 raw UUID bytes hex-encoded
    handshake_node_addrs: list = field(default_factory=list)
    handshake_peer_data: dict = field(default_factory=dict)

    def to_state(self) -> dict:
        return {
            "v2_uuid_hex": self.uuid_hex,
            "handshake_node_addrs": list(self.handshake_node_addrs),
            "handshake_peer_data": dict(self.handshake_peer_data),
        }

    @classmethod
    def from_state(cls, state: dict) -> "V2Credentials":
        return cls(
            uuid_hex=state["v2_uuid_hex"],
            handshake_node_addrs=list(state.get("handshake_node_addrs", [])),
            handshake_peer_data=dict(state.get("handshake_peer_data", {})),
        )


@dataclass
class V2RayProxySession:
    pid: int                 # v2ray PID
    tun2socks_pid: int       # tun2socks PID
    socks_port: int
    config_path: str
    tun_iface: str
    node_ip: str             # so disconnect can drop the host route
    orig_gw: str             # original default-route gateway (for the host route)
    multihop: bool = False   # True → chained entry/exit (one v2ray, two outbounds)

    def to_state(self) -> dict:
        return {
            "backend": "v2ray-multihop" if self.multihop else "v2ray",
            "pid": self.pid,
            "tun2socks_pid": self.tun2socks_pid,
            "socks_port": self.socks_port,
            "config_path": self.config_path,
            "tun_iface": self.tun_iface,
            "node_ip": self.node_ip,
            "orig_gw": self.orig_gw,
        }


def fetch_creds(
    *, remote_url: str, session_id: int, private_key: bytes
) -> V2Credentials:
    """Do the chain-signed handshake. Generates a fresh UUID, posts to the
    node, returns the full picture. The caller MUST persist the result
    before calling bring_up() — the node won't accept a second handshake.
    """
    uid = uuid.uuid4()
    handshake = fetch_node_credentials(
        remote_url=remote_url,
        session_id=session_id,
        private_key=private_key,
        request_data={"uuid": list(uid.bytes)},
    )
    return V2Credentials(
        uuid_hex=uid.bytes.hex(),
        handshake_node_addrs=handshake.node_addrs,
        handshake_peer_data=handshake.peer_data,
    )


def bring_up(creds: V2Credentials, remote_url: str) -> V2RayProxySession:
    """Spawn v2ray + tun2socks, install routing. `remote_url` is only used
    to resolve the node's IP for the bypass host route — the handshake
    payload comes from `creds`."""
    v2_exe = bin_path("v2ray", "v2ray")
    tun_exe = bin_path("v2ray", "tun2socks")
    if not v2_exe.is_file():
        raise VpnError(f"Bundled binary missing: {v2_exe}.")
    if not tun_exe.is_file():
        raise VpnError(f"Bundled binary missing: {tun_exe}.")

    # Re-derive the canonical UUID string from the cached bytes.
    uid_bytes = bytes.fromhex(creds.uuid_hex)
    uid = uuid.UUID(bytes=uid_bytes)
    handshake_obj = HandshakeResult(
        node_addrs=creds.handshake_node_addrs,
        peer_data=creds.handshake_peer_data,
    )
    # Dump the raw metadata to disk before anything else: if the node only
    # offers transports our binary can't speak, this file is the evidence
    # we (and the user) need.
    try:
        (V2RAY_CONF_FILE.parent / "v2ray-metadata.json").write_text(
            json.dumps(creds.handshake_peer_data, indent=2), encoding="utf-8",
        )
    except OSError:
        pass  # Best-effort diagnostic; never blocks the connect path.

    server = _server_from_response(handshake_obj)

    # v2fly ≤ 4.33 doesn't know gRPC or VLESS; if the node only offers those,
    # v2ray exits at startup with "unknown transport protocol". Catch it
    # BEFORE writing the config so the user gets actionable guidance.
    v2_major = _detect_v2ray_major(v2_exe)
    unsupported = (
        "grpc" if (v2_major < 5 and server["transport"] == "grpc") else
        "vless" if (v2_major < 5 and server["proxy"] == "vless") else None
    )
    if unsupported:
        raise VpnError(
            f"This node uses {unsupported!r}, which requires v2fly v5+. "
            f"The bundled v2ray binary reports v{v2_major}.x and will reject "
            "the config. Either download v2fly v5.x from "
            "https://github.com/v2fly/v2ray-core/releases and replace the "
            "binary under bin/v2ray/, or pick a different node (most expose "
            "TCP/WebSocket endpoints)."
        )

    original = _routing.get_default_route()
    if original is None:
        raise VpnError("Could not determine the current default route.")
    # Resolve the endpoint v2ray will dial to an IP NOW, before the tunnel
    # owns the default route — and bypass exactly that IP. Dialing by IP avoids
    # the circular DNS that hangs nodes advertising a hostname; bypassing the
    # same IP guarantees v2ray's connection to the node doesn't loop into the
    # tunnel. (remote_url, the node's API host, may differ from the data
    # endpoint, so we key off the endpoint host, not remote_url.)
    node_ip = _resolve_endpoint_ip(server["host"])

    socks_port = _pick_free_port(preferred=DEFAULT_SOCKS_PORT)
    config = _build_v2ray_config(
        vmess_address=server["host"],
        vmess_port=server["port"],
        vmess_uid=str(uid),
        proxy=server.get("proxy", "vmess"),
        transport=server["transport"],
        security=server.get("security", ""),
        socks_port=socks_port,
        dial_address=node_ip,
    )
    config_path = str(V2RAY_CONF_FILE)
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

    v2_pid, tun_pid = _spawn_and_install_routing(
        v2_exe, tun_exe, config_path=config_path,
        socks_port=socks_port, bypass_ip=node_ip, original=original,
    )
    return V2RayProxySession(
        pid=v2_pid,
        tun2socks_pid=tun_pid,
        socks_port=socks_port,
        config_path=config_path,
        tun_iface=TUN_NAME,
        node_ip=node_ip,
        orig_gw=original.gateway,
    )


def _spawn_and_install_routing(
    v2_exe, tun_exe, *, config_path: str, socks_port: int, bypass_ip: str, original
):
    """Spawn v2ray + tun2socks and install split-default routing + DNS,
    bypassing `bypass_ip` (the node we connect to directly) via a host route.
    Rolls everything back and raises on any failure. Returns (v2_pid, tun_pid).

    Shared by single- and multi-hop bring-up: the only thing that differs
    between them is the config already written to `config_path` and which IP
    gets the bypass route (the single node, or the entry node of the chain).
    """
    v2_proc = _spawn_v2ray(v2_exe, config_path)
    time.sleep(1.5)
    if v2_proc.poll() is not None:
        msg = _read_log_tail("v2ray.log") or "(no output)"
        raise VpnError(f"V2Ray exited immediately. v2ray.log tail:\n{msg}")

    tun_proc: Optional[subprocess.Popen] = None
    routing_steps: list[str] = []
    try:
        _routing.add_host_route(bypass_ip, original)
        routing_steps.append("host_route")

        # Keep the chain gRPC endpoint OUT of the tunnel, so querying or ending
        # sessions — and tearing the tunnel down — never severs our path to the
        # chain.
        _routing.add_chain_bypass(original)
        routing_steps.append("chain_bypass")

        tun_proc = _spawn_tun2socks(tun_exe, socks_port=socks_port)
        time.sleep(1.5)
        if tun_proc.poll() is not None:
            msg = _read_log_tail("tun2socks.log") or "(no output)"
            raise VpnError(f"tun2socks exited immediately. tun2socks.log tail:\n{msg}")

        # Assign the TUN device an IP — required on ALL platforms. Without
        # this, the kernel can't route through the TUN: routes that name
        # the gateway 198.18.0.1 would fail to install (Linux) or silently
        # not direct traffic anywhere (Windows, where the route is added
        # but the gateway is not on-link).
        _routing.configure_tun(TUN_NAME, TUN_LOCAL_IP)
        routing_steps.append("tun_up")

        _routing.add_default_via_tun(TUN_NAME, TUN_LOCAL_IP)
        routing_steps.append("split_default")

        # Point DNS at a public resolver the exit node can reach. Without
        # this, a system configured with a PRIVATE nameserver (common behind
        # NAT) tunnels its DNS queries to the node, which can't route to that
        # private address — every lookup hangs and the tunnel looks dead.
        _routing.set_dns()
        routing_steps.append("dns")
    except Exception:
        _rollback_routing(routing_steps, bypass_ip)
        _kill_pid(tun_proc.pid if tun_proc else None)
        _kill_pid(v2_proc.pid)
        raise

    return v2_proc.pid, tun_proc.pid


def _require_tcp_endpoints(entry_server: dict, exit_server: dict) -> None:
    """The single conservative multihop requirement: TCP on both ends.
    mkcp/quic can't be carried over a chained TCP stream; ws/grpc are
    unverified. Raise VpnError with a clear message rather than spawn a
    config that would silently fail to route."""
    for role, srv in (("entry", entry_server), ("exit", exit_server)):
        if srv.get("transport") != "tcp":
            raise VpnError(
                f"Multihop requires TCP on both nodes, but the {role} node "
                f"negotiated {srv.get('transport')!r}. Pick a different {role} node."
            )


def bring_up_multihop(
    *, entry_creds: V2Credentials, exit_creds: V2Credentials,
) -> V2RayProxySession:
    """Bring up a single tunnel that chains entry -> exit.

    One v2ray process (two chained outbounds) + one tun2socks, exactly like
    single-hop — only the config differs. Both nodes MUST negotiate TCP
    transport (the conservative chaining requirement); we raise VpnError
    otherwise rather than spawn a config that would silently fail to route.

    Everything is derived from the two handshakes: the entry node is the sole
    direct connection from this host (so it's the only one whose endpoint we
    resolve up-front and bypass with a host route). The exit node's address
    comes from its handshake and is reached *through* the entry tunnel, so it
    needs neither resolution nor a host route here.

    Credentials for BOTH hops must already be persisted by the caller (the
    node won't accept a second handshake), same anti-burn contract as
    bring_up().
    """
    v2_exe = bin_path("v2ray", "v2ray")
    tun_exe = bin_path("v2ray", "tun2socks")
    if not v2_exe.is_file():
        raise VpnError(f"Bundled binary missing: {v2_exe}.")
    if not tun_exe.is_file():
        raise VpnError(f"Bundled binary missing: {tun_exe}.")

    entry_uid = uuid.UUID(bytes=bytes.fromhex(entry_creds.uuid_hex))
    exit_uid = uuid.UUID(bytes=bytes.fromhex(exit_creds.uuid_hex))
    entry_server = _server_from_response(HandshakeResult(
        node_addrs=entry_creds.handshake_node_addrs,
        peer_data=entry_creds.handshake_peer_data,
    ))
    exit_server = _server_from_response(HandshakeResult(
        node_addrs=exit_creds.handshake_node_addrs,
        peer_data=exit_creds.handshake_peer_data,
    ))

    # The single conservative requirement: TCP on both ends.
    _require_tcp_endpoints(entry_server, exit_server)

    # VLESS needs v2fly v5+ (same constraint single-hop enforces). gRPC isn't
    # a concern here — TCP is already required above.
    v2_major = _detect_v2ray_major(v2_exe)
    if v2_major < 5:
        for role, srv in (("entry", entry_server), ("exit", exit_server)):
            if srv.get("proxy") == "vless":
                raise VpnError(
                    f"The {role} node uses VLESS, which requires v2fly v5+. The "
                    f"bundled v2ray reports v{v2_major}.x. Replace the binary under "
                    "bin/v2ray/ with v5.x, or pick a different node."
                )

    original = _routing.get_default_route()
    if original is None:
        raise VpnError("Could not determine the current default route.")
    # Only the entry node is a direct connection from this host. Resolve its
    # endpoint to an IP up-front (same circular-DNS reason as single-hop), dial
    # it by IP and bypass that same IP. The exit is reached THROUGH the entry
    # tunnel, so the entry node resolves the exit's hostname for us — the exit
    # needs neither local resolution nor a host route.
    entry_ip = _resolve_endpoint_ip(entry_server["host"])
    entry_server["dial_address"] = entry_ip

    socks_port = _pick_free_port(preferred=DEFAULT_SOCKS_PORT)
    config = _build_v2ray_multihop_config(
        entry=entry_server, entry_uid=str(entry_uid),
        exit=exit_server, exit_uid=str(exit_uid),
        socks_port=socks_port,
    )
    config_path = str(V2RAY_CONF_FILE)
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

    v2_pid, tun_pid = _spawn_and_install_routing(
        v2_exe, tun_exe, config_path=config_path,
        socks_port=socks_port, bypass_ip=entry_ip, original=original,
    )
    return V2RayProxySession(
        pid=v2_pid,
        tun2socks_pid=tun_pid,
        socks_port=socks_port,
        config_path=config_path,
        tun_iface=TUN_NAME,
        node_ip=entry_ip,
        orig_gw=original.gateway,
        multihop=True,
    )


def disconnect(state: dict) -> None:
    """Tear down everything connect() set up. Best-effort: every step
    runs regardless of earlier failures, so a partially-bricked state
    still gets unwound."""
    tun_iface = state.get("tun_iface", TUN_NAME)
    node_ip = state.get("node_ip")

    # Routing first, so even if process kill fails the user has internet back.
    _routing.restore_dns()
    _routing.remove_default_via_tun(tun_iface, TUN_LOCAL_IP)
    if node_ip:
        _routing.remove_host_route(node_ip)
    _routing.remove_chain_bypass()

    for pid_key in ("tun2socks_pid", "pid"):
        _kill_pid(state.get(pid_key))


# --------------------------------------------------------------------------
# Internals
# --------------------------------------------------------------------------


# Sentinel nodes return v2ray metadata fields as enum INTEGERS, not strings.
# We must translate them back to v2ray's textual config values, or v2ray
# rejects the config with "unknown transport protocol: N". The numbers come
# from the protobuf enum order in sentinel-go-sdk.
_PROXY_PROTOCOL_ENUM = {1: "vless", 2: "vmess"}
_TRANSPORT_PROTOCOL_ENUM = {
    1: "domainsocket",
    2: "gun",
    3: "grpc",
    4: "http",
    5: "mkcp",
    6: "quic",
    7: "tcp",
    8: "websocket",
}
_TRANSPORT_SECURITY_ENUM = {1: "none", 2: "tls"}


def _decode_enum(raw, mapping: dict, default: str = "") -> str:
    """Translate a metadata field that can be int (enum), digit-string,
    or already-textual into the canonical v2ray string. Tolerates all
    three shapes because different nodes / SDK versions emit different
    ones."""
    if raw is None or isinstance(raw, bool):
        return default
    if isinstance(raw, int):
        return mapping.get(raw, default)
    text = str(raw).strip().lower()
    if not text:
        return default
    if text.isdigit():
        return mapping.get(int(text), default)
    return text


def _score_endpoint(transport: str, proxy: str, security: str) -> int:
    """Lower is better. We prefer the combinations that work on v2fly v4
    (the user's bundled binary may still be 4.31, which lacks gRPC/VLESS),
    and that match the security model of typical Sentinel nodes:
        tcp+tls > tcp > websocket+tls > websocket > everything else.
    grpc and vless are pushed to the end so any other usable combination
    is picked first.
    """
    score = 0
    # transport preference
    score += {"tcp": 0, "websocket": 20, "ws": 20, "h2": 40,
              "kcp": 50, "quic": 60, "grpc": 200,
              "domainsocket": 300, "http": 300, "gun": 400}.get(transport, 500)
    # security preference: prefer tls
    score += 0 if security == "tls" else 5
    # proxy preference: vmess is universally supported, vless requires v4.34+
    score += 0 if proxy == "vmess" else 100
    return score


def offered_transports(peer_data: dict) -> list:
    """The transports a node advertised in its handshake metadata, as
    canonical v2ray strings (e.g. ['tcp', 'websocket']). Feeds the transport
    cache so multihop can later filter for TCP-capable nodes without paying
    for a fresh handshake to each candidate."""
    metadata = (peer_data or {}).get("metadata") or []
    found = set()
    for item in metadata:
        if not isinstance(item, dict):
            continue
        transport = _decode_enum(
            item.get("transport_protocol"), _TRANSPORT_PROTOCOL_ENUM, default=""
        )
        if transport == "ws":
            transport = "websocket"
        if transport:
            found.add(transport)
    return sorted(found)


def _server_from_response(handshake) -> dict:
    """Pick the best v2ray endpoint from the node's handshake response.

    Sentinel nodes typically expose multiple endpoints (different
    transport + security combinations) in the metadata array. The first
    one isn't always the one our local v2ray can speak — e.g. FedNet
    lists gRPC first, but v2fly v4.31 (the binary bundled in many
    distributions) doesn't know gRPC and crashes with `unknown transport
    protocol: grpc`.

    We score every entry by `_score_endpoint` and return the lowest. tcp
    (with or without tls) wins; gRPC and VLESS lose unless they're the
    only thing on offer.
    """
    if not handshake.node_addrs:
        raise VpnError("Node didn't return a connectable address.")
    host = handshake.node_addrs[0].split(":", 1)[0]
    metadata = (handshake.peer_data or {}).get("metadata") or []
    if not metadata:
        raise VpnError("Node response is missing server metadata.")

    candidates: list[tuple[int, dict]] = []
    for item in metadata:
        if not isinstance(item, dict):
            continue
        port_raw = item.get("port")
        if port_raw in (None, ""):
            continue
        try:
            port = int(port_raw)
        except (TypeError, ValueError):
            continue

        proxy = _decode_enum(
            item.get("proxy_protocol"), _PROXY_PROTOCOL_ENUM, default="vmess"
        )
        transport = _decode_enum(
            item.get("transport_protocol"), _TRANSPORT_PROTOCOL_ENUM, default="tcp"
        )
        if transport == "ws":
            transport = "websocket"
        security = _decode_enum(
            item.get("transport_security"), _TRANSPORT_SECURITY_ENUM, default="none"
        )
        candidates.append((
            _score_endpoint(transport, proxy, security),
            {"host": host, "port": port,
             "proxy": proxy, "transport": transport, "security": security},
        ))

    if not candidates:
        raise VpnError("Node didn't return any usable endpoint metadata.")
    candidates.sort(key=lambda x: x[0])
    return candidates[0][1]


def _resolve_endpoint_ip(host: str) -> str:
    """Resolve a node's v2ray ENDPOINT host to an IPv4 literal (returns it
    unchanged if it's already an IP).

    This MUST run before the tunnel captures the default route. v2ray dials
    the node by this IP, so it never needs DNS at connect time. Otherwise, for
    a node that advertises a hostname (e.g. 'brazil.dvpn-x.com') instead of an
    IP, v2ray resolves the name only once the connect is under way — by which
    point the default route is already redirected into the TUN, and the lookup
    is trapped inside the very tunnel it's trying to build:
        resolve node -> DNS query -> default route -> TUN -> tun2socks
            -> v2ray SOCKS -> dial node -> resolve node ...
    a circular dependency that hangs every such connect ('lookup ...:
    operation was canceled' in v2ray.log). Resolving up-front breaks the loop.
    """
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        raise VpnError(f"Could not resolve node endpoint {host!r}: {e}") from e


def _pick_free_port(preferred: int = 0) -> int:
    """Try `preferred` first, fall back to a kernel-assigned port."""
    for port in ((preferred, 0) if preferred else (0,)):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return s.getsockname()[1]
            except OSError:
                continue
    raise VpnError("Could not find a free local port for the SOCKS5 proxy.")


def _build_outbound(
    *, server: dict, uid: str, tag: str, dial_through: Optional[str] = None
) -> dict:
    """Build one v2ray outbound from a resolved endpoint dict
    (host/port/proxy/transport/security).

    The streamSettings sub-blocks depend on the transport: tcp needs
    nothing extra, grpc needs grpcSettings, websocket needs wsSettings.
    For TLS we pin allowInsecure=true because Sentinel nodes use
    self-signed certs (the chain-side signature authenticates, not the cert).

    `dial_through`, when set, makes this outbound establish its connection
    THROUGH the outbound carrying that tag (proxySettings.tag) — the
    mechanism behind multihop chaining, supported by v2ray-core v4 and v5.
    """
    transport = server.get("transport") or "tcp"
    security = server.get("security", "")
    proxy = server.get("proxy", "vmess")

    # Dial by IP for a DIRECT connection (single-hop node or multihop entry):
    # resolving the hostname at connect time deadlocks once the tunnel owns the
    # default route (see _resolve_endpoint_ip). Endpoints reached THROUGH
    # another proxy (the multihop exit, dial_through set) keep their hostname —
    # the upstream node resolves it and has working DNS. TLS SNI always stays
    # the original hostname so the node's cert/vhost routing still matches.
    if dial_through is None:
        dial_address = server.get("dial_address") or server["host"]
    else:
        dial_address = server["host"]

    stream_settings: dict = {"network": transport}
    if security == "tls":
        stream_settings["security"] = "tls"
        stream_settings["tlsSettings"] = {
            "serverName": server["host"],
            "allowInsecure": True,
        }
    if transport == "grpc":
        stream_settings["grpcSettings"] = {}
    elif transport in ("websocket", "ws"):
        stream_settings["wsSettings"] = {}

    if proxy == "vless":
        user_settings = {"id": uid, "encryption": "none"}
    else:  # vmess (default)
        user_settings = {"id": uid, "alterId": 0}

    outbound = {
        "protocol": proxy,
        "settings": {
            "vnext": [
                {
                    "address": dial_address,
                    "port": server["port"],
                    "users": [user_settings],
                }
            ]
        },
        "streamSettings": stream_settings,
        "tag": tag,
    }
    if dial_through:
        outbound["proxySettings"] = {"tag": dial_through}
    return outbound


def _assemble_config(socks_port: int, outbounds: list) -> dict:
    """Wrap one or more outbounds with the standard socks inbound and the
    top-level transport defaults. The `transport` block lets v4 read default
    per-protocol settings (v5 ignores it); including it harms nothing and
    unblocks v4."""
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": True, "ip": "127.0.0.1"},
                "tag": "socks-in",
            }
        ],
        "outbounds": outbounds,
        "transport": {
            "tcpSettings": {},
            "grpcSettings": {},
            "wsSettings": {},
            "kcpSettings": {},
            "httpSettings": {},
            "quicSettings": {"security": "chacha20-poly1305"},
        },
    }


def _build_v2ray_config(
    *,
    vmess_address: str,
    vmess_port: int,
    vmess_uid: str,
    proxy: str = "vmess",
    transport: str,
    security: str,
    socks_port: int,
    dial_address: Optional[str] = None,
) -> dict:
    """Single-hop config: one outbound to the assigned peer. `dial_address` is
    the pre-resolved IP v2ray should dial (with `vmess_address` kept as the TLS
    SNI); falls back to the host when not supplied."""
    server = {
        "host": vmess_address, "port": vmess_port,
        "proxy": proxy, "transport": transport, "security": security,
        "dial_address": dial_address,
    }
    outbound = _build_outbound(server=server, uid=vmess_uid, tag=f"{proxy}-out")
    return _assemble_config(socks_port, [outbound])


def _build_v2ray_multihop_config(
    *, entry: dict, entry_uid: str, exit: dict, exit_uid: str, socks_port: int
) -> dict:
    """Two chained outbounds inside ONE v2ray process. The exit outbound
    dials THROUGH the entry outbound (proxySettings.tag), so the physical
    path is: this host -> entry node -> exit node -> internet.

    The exit is the default outbound (first in the list) because it carries
    the user's actual traffic. Only the ENTRY node needs a host-route bypass
    at the OS level — it's the sole direct connection from this host; the
    exit connection is carried inside the entry tunnel.
    """
    entry_tag, exit_tag = "entry-out", "exit-out"
    exit_ob = _build_outbound(
        server=exit, uid=exit_uid, tag=exit_tag, dial_through=entry_tag
    )
    entry_ob = _build_outbound(server=entry, uid=entry_uid, tag=entry_tag)
    return _assemble_config(socks_port, [exit_ob, entry_ob])


@functools.lru_cache(maxsize=4)
def _detect_v2ray_major(exe: Path) -> int:
    """Return the v2ray major version (4 or 5). Cached per binary path.

    v4 and v5 take incompatible CLI args:
      v4: `v2ray -c PATH`
      v5: `v2ray run -c PATH`

    Passing v5 syntax to v4 makes `run` a positional arg; Go's flag
    parser stops at the first non-flag, never sees `-c`, and v4 falls
    back to its default config search (which lands on bin/v2ray/config.json,
    the sample config from the distribution — which doesn't connect to
    our node, so v2ray exits and the tunnel never starts).

    Defaults to 5 if detection fails — modern syntax against an old
    binary fails loudly, but old syntax against a modern binary works
    too in most cases.
    """
    for argv in (["--version"], ["-version"], ["version"]):
        try:
            r = subprocess.run(
                [str(exe)] + argv, capture_output=True, timeout=3, text=True
            )
            m = re.search(r"V2Ray\s+(\d+)\.", (r.stdout or "") + "\n" + (r.stderr or ""))
            if m:
                return int(m.group(1))
        except (subprocess.TimeoutExpired, OSError, ValueError):
            continue
    return 5  # safest default if detection completely fails


# Windows: keep our spawned helpers detached from the parent console so
# Ctrl-C doesn't take them down before the routing rollback can run.
_DETACHED_FLAGS = 0x00000200 | 0x00000008 if os.name == "nt" else 0


def _popen_logged(
    args: list[str], log_name: str, *, cwd: str
) -> subprocess.Popen:
    """Spawn a child process and tee its combined output to data/<log_name>.

    Both v2ray and tun2socks survive in the background past Python's
    lifetime; we use the same launch shape for both so a missing exit
    code or a wedged write to either log gets diagnosed the same way.
    """
    log_file = open(V2RAY_CONF_FILE.parent / log_name, "wb")
    try:
        return subprocess.Popen(
            args,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            creationflags=_DETACHED_FLAGS,
            start_new_session=(os.name != "nt"),
            cwd=cwd,
        )
    finally:
        # The child inherited its own dup of the fd; the parent's copy would
        # otherwise leak (2 per connect) for the life of the CLI.
        log_file.close()


def _spawn_v2ray(exe: Path, config_path: str) -> subprocess.Popen:
    """Spawn v2ray with the right CLI for its major version.

    v2ray doesn't crash on outbound failures (wrong TLS, refused vmess,
    etc.), so data/v2ray.log is the only post-mortem we have. We also
    pin cwd to data/ rather than bin/v2ray/: a v4 binary that finds a
    `config.json` next to itself uses THAT instead of our -c argument.
    """
    major = _detect_v2ray_major(exe)
    args = [str(exe), "run", "-c", config_path] if major >= 5 else [str(exe), "-c", config_path]
    return _popen_logged(args, "v2ray.log", cwd=str(V2RAY_CONF_FILE.parent))


def _spawn_tun2socks(exe: Path, *, socks_port: int) -> subprocess.Popen:
    """xjasonlyu/tun2socks: -device tun://NAME -proxy socks5://127.0.0.1:port

    We deliberately don't pass `-interface` even though tun2socks accepts
    it. Its semantics are "bind the upstream socket to a named interface",
    and getting the name right is platform-dependent. Since our upstream
    is 127.0.0.1 the loopback route always wins anyway, and silently
    breaking when we passed the wrong value cost us a full debug session.

    cwd is the binary's own folder because tun2socks.exe loads wintun.dll
    from there on Windows.
    """
    args = [
        str(exe),
        "-device", f"tun://{TUN_NAME}",
        "-proxy", f"socks5://127.0.0.1:{socks_port}",
        "-loglevel", "info",
    ]
    return _popen_logged(args, "tun2socks.log", cwd=str(exe.parent))


def _read_log_tail(log_name: str, max_chars: int = 600) -> str:
    """Tail data/<log_name> so we can surface it in error messages."""
    try:
        log_path = V2RAY_CONF_FILE.parent / log_name
        if not log_path.exists():
            return ""
        text = log_path.read_bytes().decode("utf-8", errors="replace").strip()
        return "... " + text[-max_chars:] if len(text) > max_chars else text
    except OSError:
        return ""


def _kill_pid(pid) -> None:
    """Best-effort terminate. Accepts None / int / numeric string so the
    same call works for both live process pids and persisted state."""
    if not pid:
        return
    try:
        pid_int = int(pid)
    except (TypeError, ValueError):
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(pid_int), "/F", "/T"],
                check=False, capture_output=True,
            )
        else:
            os.kill(pid_int, 15)  # SIGTERM
    except (ProcessLookupError, PermissionError, ValueError, OSError):
        pass


def _rollback_routing(steps: list[str], node_ip: str) -> None:
    """Undo whatever portion of the routing setup succeeded before failure."""
    if "dns" in steps:
        _routing.restore_dns()
    if "split_default" in steps:
        _routing.remove_default_via_tun(TUN_NAME, TUN_LOCAL_IP)
    if "host_route" in steps:
        _routing.remove_host_route(node_ip)
    if "chain_bypass" in steps:
        _routing.remove_chain_bypass()
    # "tun_up" leaves no persistent state — tun device disappears when
    # tun2socks dies.
