"""Xray backend — full tunnel via the shared SOCKS engine.

The bundled `xray` core runs with a SOCKS5 inbound on 127.0.0.1 and one
outbound to the node; `socks_tunnel` turns that into a full tunnel with
tun2socks, exactly like V2Ray/Hysteria2.

Handshake (sentinel-go-sdk v2, xray package):
  request   {"uuid": <uuid.UUID>} — same field type as v2ray (byte array)
  response  {"metadata": [one entry per inbound]} with
            port, proxy_protocol, transport_protocol, transport_security,
            flow, method, key, tls_pin, reality_server_name,
            reality_short_id, reality_public_key, reality_fingerprint
Enums arrive as Go byte values and are NUMBERED DIFFERENTLY from v2ray's
(in xray 1 = tcp; in v2ray 7 = tcp) — never share the v2ray tables here.

Every per-user secret derives from the UUID we sent, as the node does:
  vless/vmess  id       = the UUID
  trojan       password = the UUID string
  ss-2022      password = "<server key>:<base64(sha256(uuid bytes))>"

TLS: nodes use self-signed certs, and Xray v26 has REMOVED `allowInsecure`
(its config loader refuses it), so TLS is verified by pinning the node's
certificate — `pinnedPeerCertSha256`, from the metadata. A TLS endpoint
without a pin is unusable and skipped.

Required bundled binary (in `bin/xray/`): `xray` / `xray.exe` (XTLS/Xray-core).
tun2socks and wintun.dll are shared from `bin/v2ray/`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from dataclasses import dataclass, field

from ..config import XRAY_CONF_FILE, bin_path
from . import HandshakeResult, VpnError, decode_enum, fetch_node_credentials
from . import _routing, socks_tunnel

BACKEND = "xray"

# Go byte enums from sentinel-go-sdk v2 `xray` package (iota order).
_PROXY_BY_ENUM = {1: "vless", 2: "vmess", 3: "trojan", 4: "shadowsocks-2022"}
_TRANSPORT_BY_ENUM = {1: "tcp", 2: "websocket", 3: "grpc", 4: "httpupgrade", 5: "xhttp"}
_SECURITY_BY_ENUM = {1: "none", 2: "tls", 3: "reality"}
_FLOW_BY_ENUM = {1: "none", 2: "xtls-rprx-vision"}

# Endpoint preference, lower is better. Security first (Reality and pinned
# TLS resist DPI and authenticate the node), then the simplest transport,
# then the lightest proxy. Only ranks endpoints that already passed
# validation — every one of them is connectable.
_SECURITY_RANK = {"reality": 0, "tls": 1, "none": 2}
_TRANSPORT_RANK = {"tcp": 0, "httpupgrade": 1, "websocket": 2, "grpc": 3, "xhttp": 4}
_PROXY_RANK = {"vless": 0, "trojan": 1, "vmess": 2, "shadowsocks-2022": 3}


@dataclass
class XrayCredentials:
    """Everything needed to bring the tunnel up without re-asking the node
    (which would 409). Serializable to plain dicts for state.json."""

    uuid_hex: str  # 32 chars, the 16 raw UUID bytes hex-encoded
    handshake_node_addrs: list = field(default_factory=list)
    handshake_peer_data: dict = field(default_factory=dict)

    def to_state(self) -> dict:
        return {
            "xray_uuid_hex": self.uuid_hex,
            "handshake_node_addrs": list(self.handshake_node_addrs),
            "handshake_peer_data": dict(self.handshake_peer_data),
        }

    @classmethod
    def from_state(cls, state: dict) -> "XrayCredentials":
        return cls(
            uuid_hex=state["xray_uuid_hex"],
            handshake_node_addrs=list(state.get("handshake_node_addrs", [])),
            handshake_peer_data=dict(state.get("handshake_peer_data", {})),
        )


def fetch_creds(
    *, remote_url: str, session_id: int, private_key: bytes
) -> XrayCredentials:
    """Do the chain-signed handshake with a fresh UUID. The caller MUST
    persist the result before bring_up() — the node won't accept a second
    handshake for the same session."""
    uid = uuid.uuid4()
    handshake = fetch_node_credentials(
        remote_url=remote_url,
        session_id=session_id,
        private_key=private_key,
        request_data={"uuid": list(uid.bytes)},
    )
    return XrayCredentials(
        uuid_hex=uid.bytes.hex(),
        handshake_node_addrs=handshake.node_addrs,
        handshake_peer_data=handshake.peer_data,
    )


def bring_up(creds: XrayCredentials) -> socks_tunnel.SocksSession:
    """Spawn xray + tun2socks and install routing."""
    xray_exe = bin_path("xray", "xray")
    tun_exe = bin_path("v2ray", "tun2socks")
    socks_tunnel.require_binary(xray_exe, "xray")
    socks_tunnel.require_binary(tun_exe, "tun2socks")

    # Keep the raw metadata on disk: if the node offers nothing we can use,
    # this file is the evidence. Best-effort, never blocks the connect.
    try:
        (XRAY_CONF_FILE.parent / "xray-metadata.json").write_text(
            json.dumps(creds.handshake_peer_data, indent=2), encoding="utf-8",
        )
    except OSError:
        pass

    uid = uuid.UUID(bytes=bytes.fromhex(creds.uuid_hex))
    server = _server_from_response(HandshakeResult(
        node_addrs=creds.handshake_node_addrs,
        peer_data=creds.handshake_peer_data,
    ))

    original = _routing.get_default_route()
    if original is None:
        raise VpnError("Could not determine the current default route.")
    # Dial by IP, resolved before the tunnel owns the default route — and
    # bypass exactly that IP (see socks_tunnel.resolve_endpoint_ip).
    node_ip = socks_tunnel.resolve_endpoint_ip(server["host"])

    socks_port = socks_tunnel.pick_free_port(preferred=socks_tunnel.DEFAULT_SOCKS_PORT)
    config = _build_config(server, uid=uid, socks_port=socks_port, dial_ip=node_ip)
    config_path = str(XRAY_CONF_FILE)
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

    args = [str(xray_exe), "run", "-c", config_path]
    core_pid, tun_pid = socks_tunnel.spawn_and_route(
        # cwd = data/, so xray never picks up a stray config next to itself.
        lambda: socks_tunnel.popen_logged(args, "xray.log", cwd=str(XRAY_CONF_FILE.parent)),
        core_name="Xray", core_log="xray.log",
        tun_exe=tun_exe, socks_port=socks_port,
        bypass_ip=node_ip, original=original,
    )
    return socks_tunnel.SocksSession(
        backend=BACKEND, pid=core_pid, tun2socks_pid=tun_pid,
        socks_port=socks_port, config_path=config_path,
        node_ip=node_ip, orig_gw=original.gateway,
    )


def disconnect(state: dict) -> None:
    """Tear down an Xray tunnel — the shared SOCKS teardown."""
    socks_tunnel.disconnect(state)


# --------------------------------------------------------------------------
# Internals
# --------------------------------------------------------------------------


def _server_from_response(handshake) -> dict:
    """Pick the best usable endpoint from the node's handshake metadata.

    Each entry is validated (see `_parse_endpoint`); unusable ones are
    skipped. Among the rest, the lowest (security, transport, proxy) rank
    wins.
    """
    if not handshake.node_addrs:
        raise VpnError("Node didn't return a connectable address.")
    host = str(handshake.node_addrs[0]).split(":", 1)[0].strip()
    if not host:
        raise VpnError("Node didn't return a connectable address.")
    metadata = (handshake.peer_data or {}).get("metadata") or []
    if not isinstance(metadata, list) or not metadata:
        raise VpnError("Node response is missing server metadata.")

    endpoints = [ep for ep in (_parse_endpoint(item, host) for item in metadata) if ep]
    if not endpoints:
        raise VpnError(
            "Node didn't return any usable Xray endpoint "
            "(see data/xray-metadata.json for what it offered)."
        )
    endpoints.sort(key=lambda ep: (
        _SECURITY_RANK[ep["security"]],
        _TRANSPORT_RANK[ep["transport"]],
        _PROXY_RANK[ep["proxy"]],
    ))
    return endpoints[0]


def _parse_endpoint(item, host: str):
    """One metadata entry → endpoint dict, or None if it isn't usable."""
    if not isinstance(item, dict):
        return None
    port = _parse_port(item.get("port"))
    proxy = decode_enum(item.get("proxy_protocol"), _PROXY_BY_ENUM)
    transport = decode_enum(item.get("transport_protocol"), _TRANSPORT_BY_ENUM)
    security = decode_enum(item.get("transport_security"), _SECURITY_BY_ENUM)
    if (port is None or proxy not in _PROXY_RANK
            or transport not in _TRANSPORT_RANK or security not in _SECURITY_RANK):
        return None
    flow = decode_enum(item.get("flow"), _FLOW_BY_ENUM, default="none")

    ep = {"host": host, "port": port, "proxy": proxy, "transport": transport,
          "security": security, "flow": flow if flow == "xtls-rprx-vision" else ""}

    if security == "tls":
        pin = _text(item.get("tls_pin"))
        if not pin:
            return None  # can't verify a self-signed cert without it (no allowInsecure in v26)
        ep["tls_pin"] = pin
    elif security == "reality":
        public_key = _text(item.get("reality_public_key"))
        server_name = _text(item.get("reality_server_name"))
        if not public_key or not server_name:
            return None
        ep["reality"] = {
            "public_key": public_key,
            "server_name": server_name,
            "short_id": _text(item.get("reality_short_id")),
            "fingerprint": _text(item.get("reality_fingerprint")) or "chrome",
        }

    if proxy == "shadowsocks-2022":
        method, key = _text(item.get("method")), _text(item.get("key"))
        if not method or not key:
            return None
        ep["method"], ep["key"] = method, key
    return ep


def _text(raw) -> str:
    return raw.strip() if isinstance(raw, str) else ""


def _parse_port(raw):
    """Port as int in 1..65535 from an int or a digit-string; None otherwise."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        port = raw
    elif isinstance(raw, str) and raw.strip().isdigit():
        port = int(raw.strip())
    else:
        return None
    return port if 0 < port < 65536 else None


def _ss2022_user_key(uid: uuid.UUID) -> str:
    """Per-user Shadowsocks-2022 PSK, derived like the node does:
    base64(sha256(the 16 raw UUID bytes))."""
    return base64.b64encode(hashlib.sha256(uid.bytes).digest()).decode("ascii")


def _build_outbound(server: dict, *, uid: uuid.UUID, dial_ip: str) -> dict:
    """The single outbound to the node (dialled by IP; SNI stays the host)."""
    proxy = server["proxy"]
    if proxy in ("vless", "vmess"):
        user: dict = {"id": str(uid)}
        if proxy == "vless":
            user["encryption"] = "none"
            if server.get("flow"):
                user["flow"] = server["flow"]
        else:
            user["alterId"] = 0
        settings = {"vnext": [{"address": dial_ip, "port": server["port"], "users": [user]}]}
    elif proxy == "trojan":
        settings = {"servers": [{"address": dial_ip, "port": server["port"],
                                 "password": str(uid)}]}
    else:  # shadowsocks-2022 — xray's protocol id is plain "shadowsocks"
        settings = {"servers": [{
            "address": dial_ip, "port": server["port"], "method": server["method"],
            "password": f"{server['key']}:{_ss2022_user_key(uid)}",
        }]}

    stream: dict = {"network": server["transport"], "security": server["security"]}
    if server["security"] == "tls":
        stream["tlsSettings"] = {
            "serverName": server["host"],
            "fingerprint": "chrome",
            "pinnedPeerCertSha256": server["tls_pin"],
        }
    elif server["security"] == "reality":
        r = server["reality"]
        stream["realitySettings"] = {
            "fingerprint": r["fingerprint"],
            "publicKey": r["public_key"],
            "serverName": r["server_name"],
            "shortId": r["short_id"],
        }
    return {
        "protocol": "shadowsocks" if proxy == "shadowsocks-2022" else proxy,
        "settings": settings,
        "streamSettings": stream,
        "tag": "proxy",
    }


def _build_config(server: dict, *, uid: uuid.UUID, socks_port: int, dial_ip: str) -> dict:
    """Full xray config: one SOCKS5 inbound (UDP on) and one outbound."""
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"udp": True, "ip": "127.0.0.1"},
            "tag": "socks-in",
        }],
        "outbounds": [_build_outbound(server, uid=uid, dial_ip=dial_ip)],
    }
