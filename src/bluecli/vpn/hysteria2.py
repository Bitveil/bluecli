"""Hysteria2 backend — full tunnel via the shared SOCKS engine.

The bundled `hysteria` binary runs in client mode with only a SOCKS5 inbound
on 127.0.0.1; `socks_tunnel` turns that into a full tunnel with tun2socks,
exactly like V2Ray/Xray. (Hysteria also has a native TUN mode, but reusing
the one routing path that's already proven on Linux and Windows means one
less TUN stack to get right per platform. UDP still works: tun2socks relays
it through SOCKS5 UDP-associate, which Hysteria supports.)

Handshake (sentinel-go-sdk v2, hysteria2 package):
  request   {"uuid": "<canonical UUID string>"}   — a STRING, unlike
            v2ray/xray where the field is a uuid.UUID (sent as a byte array)
  response  {"metadata": [{"port": 443, "tls_pin": "ab:cd:...",
                           "obfs_password": "..."}]}
The client authenticates with the UUID itself. `tls_pin` is the SHA-256 of
the node's self-signed certificate (colon-separated hex); `obfs_password`
enables Salamander obfuscation when non-empty.

Required bundled binary (in `bin/hysteria2/`): `hysteria` / `hysteria.exe`
(apernet/hysteria). tun2socks and wintun.dll are shared from `bin/v2ray/`.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field

from ..config import HY2_CONF_FILE, bin_path
from . import HandshakeResult, VpnError, fetch_node_credentials
from . import _routing, socks_tunnel

BACKEND = "hysteria2"


@dataclass
class Hy2Credentials:
    """Everything needed to bring the tunnel up without re-asking the node
    (which would 409). Serializable to plain dicts for state.json."""

    uuid: str  # canonical UUID string — also the Hysteria auth credential
    handshake_node_addrs: list = field(default_factory=list)
    handshake_peer_data: dict = field(default_factory=dict)

    def to_state(self) -> dict:
        return {
            "hy2_uuid": self.uuid,
            "handshake_node_addrs": list(self.handshake_node_addrs),
            "handshake_peer_data": dict(self.handshake_peer_data),
        }

    @classmethod
    def from_state(cls, state: dict) -> "Hy2Credentials":
        return cls(
            uuid=state["hy2_uuid"],
            handshake_node_addrs=list(state.get("handshake_node_addrs", [])),
            handshake_peer_data=dict(state.get("handshake_peer_data", {})),
        )


def fetch_creds(
    *, remote_url: str, session_id: int, private_key: bytes
) -> Hy2Credentials:
    """Do the chain-signed handshake with a fresh UUID. The caller MUST
    persist the result before bring_up() — the node won't accept a second
    handshake for the same session."""
    uid = str(uuid.uuid4())
    handshake = fetch_node_credentials(
        remote_url=remote_url,
        session_id=session_id,
        private_key=private_key,
        request_data={"uuid": uid},
    )
    return Hy2Credentials(
        uuid=uid,
        handshake_node_addrs=handshake.node_addrs,
        handshake_peer_data=handshake.peer_data,
    )


def bring_up(creds: Hy2Credentials) -> socks_tunnel.SocksSession:
    """Spawn hysteria (SOCKS5 client) + tun2socks and install routing."""
    hy_exe = bin_path("hysteria2", "hysteria")
    tun_exe = bin_path("v2ray", "tun2socks")
    socks_tunnel.require_binary(hy_exe, "hysteria")
    socks_tunnel.require_binary(tun_exe, "tun2socks")

    # Keep the raw metadata on disk: if the node sends something we can't
    # use, this file is the evidence. Best-effort, never blocks the connect.
    try:
        (HY2_CONF_FILE.parent / "hysteria2-metadata.json").write_text(
            json.dumps(creds.handshake_peer_data, indent=2), encoding="utf-8",
        )
    except OSError:
        pass

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
    config = _build_config(server, auth=creds.uuid, socks_port=socks_port, dial_ip=node_ip)
    config_path = str(HY2_CONF_FILE)
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

    # --disable-update-check: by default hysteria phones api.hy2.io on every
    # start — third-party traffic outside (and before) the tunnel.
    args = [str(hy_exe), "client", "-c", config_path, "--disable-update-check"]
    core_pid, tun_pid = socks_tunnel.spawn_and_route(
        lambda: socks_tunnel.popen_logged(args, "hysteria2.log", cwd=str(HY2_CONF_FILE.parent)),
        core_name="Hysteria2", core_log="hysteria2.log",
        tun_exe=tun_exe, socks_port=socks_port,
        bypass_ip=node_ip, original=original,
    )
    return socks_tunnel.SocksSession(
        backend=BACKEND, pid=core_pid, tun2socks_pid=tun_pid,
        socks_port=socks_port, config_path=config_path,
        node_ip=node_ip, orig_gw=original.gateway,
    )


def disconnect(state: dict) -> None:
    """Tear down a Hysteria2 tunnel — the shared SOCKS teardown."""
    socks_tunnel.disconnect(state)


# --------------------------------------------------------------------------
# Internals
# --------------------------------------------------------------------------


def _server_from_response(handshake) -> dict:
    """Pick the node's Hysteria2 endpoint from the handshake response.

    Returns {"host", "port", "tls_pin", "obfs_password"}. The first metadata
    entry with a valid port wins (nodes expose a single Hysteria2 listener);
    malformed entries are skipped rather than trusted.
    """
    if not handshake.node_addrs:
        raise VpnError("Node didn't return a connectable address.")
    host = str(handshake.node_addrs[0]).split(":", 1)[0].strip()
    if not host:
        raise VpnError("Node didn't return a connectable address.")
    metadata = (handshake.peer_data or {}).get("metadata") or []
    if not isinstance(metadata, list) or not metadata:
        raise VpnError("Node response is missing server metadata.")

    for item in metadata:
        if not isinstance(item, dict):
            continue
        port = _parse_port(item.get("port"))
        if port is None:
            continue
        pin = item.get("tls_pin") or ""
        obfs = item.get("obfs_password") or ""
        if not isinstance(pin, str) or not isinstance(obfs, str):
            continue
        return {"host": host, "port": port, "tls_pin": pin.strip(), "obfs_password": obfs}
    raise VpnError("Node didn't return any usable Hysteria2 endpoint.")


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


def _build_config(server: dict, *, auth: str, socks_port: int, dial_ip: str) -> dict:
    """The hysteria client config (JSON — hysteria picks the format from the
    file extension, so no YAML dependency is needed).

    Mirrors the node SDK's client template: TLS is verified by pinning the
    node's self-signed certificate (`insecure` only disables the CA/hostname
    check that a self-signed cert can't pass; the pin still authenticates
    it). SNI stays the node's original host.
    """
    config = {
        "server": f"{dial_ip}:{server['port']}",
        "auth": auth,
        "tls": {"sni": server["host"], "insecure": True},
        "socks5": {"listen": f"127.0.0.1:{socks_port}"},
    }
    if server.get("tls_pin"):
        config["tls"]["pinSHA256"] = server["tls_pin"]
    if server.get("obfs_password"):
        config["obfs"] = {
            "type": "salamander",
            "salamander": {"password": server["obfs_password"]},
        }
    return config
