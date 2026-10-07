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
import re
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..config import V2RAY_CONF_FILE, bin_path
from . import HandshakeResult, VpnError, fetch_node_credentials
from . import decode_enum as _decode_enum
from . import _routing
from . import socks_tunnel
from .socks_tunnel import (
    DEFAULT_SOCKS_PORT,
    TUN_NAME,
    pick_free_port as _pick_free_port,
    popen_logged as _popen_logged,
    resolve_endpoint_ip as _resolve_endpoint_ip,
)



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
    """Spawn v2ray + tun2socks and install the full-tunnel routing via the
    shared SOCKS engine. Returns (v2_pid, tun_pid).

    Shared by single- and multi-hop bring-up: the only thing that differs
    between them is the config already written to `config_path` and which IP
    gets the bypass route (the single node, or the entry node of the chain).
    """
    return socks_tunnel.spawn_and_route(
        lambda: _spawn_v2ray(v2_exe, config_path),
        core_name="V2Ray", core_log="v2ray.log",
        tun_exe=tun_exe, socks_port=socks_port,
        bypass_ip=bypass_ip, original=original,
    )


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
    """Tear down a V2Ray tunnel (single- or multi-hop) — the shared SOCKS
    teardown: routing first, then tun2socks and v2ray."""
    socks_tunnel.disconnect(state)


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
