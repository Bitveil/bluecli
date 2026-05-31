"""WireGuard backend.

The handshake with a Sentinel node REGISTERS the peer in the node's
database. The node returns 409 on any subsequent handshake for the same
session id — so we MUST keep the response, or the session is lost.

For that reason the flow is split in two:

  fetch_creds()  — chain-signed POST + Curve25519 keypair generation.
                   The caller MUST persist the returned WGCredentials
                   before calling bring_up; without that, a crash during
                   bring-up loses the only credentials the node will ever
                   give us for this session.

  bring_up()     — write the .conf from cached creds and bring the
                   interface up (wireguard.exe on Windows, wg-quick
                   elsewhere). Safe to retry after disconnect.
"""

from __future__ import annotations

import base64
import configparser
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from nacl.public import PrivateKey

from ..config import WG_CONF_FILE, WG_INTERFACE, bin_path
from . import HandshakeResult, VpnError, fetch_node_credentials
from . import _routing


@dataclass
class WGCredentials:
    """Everything we need to bring up the tunnel later, without re-asking
    the node. Serializable to plain dicts for state.json persistence."""

    keypair_privkey_b64: str
    keypair_pubkey_b64: str
    handshake_node_addrs: list = field(default_factory=list)
    handshake_peer_data: dict = field(default_factory=dict)

    def to_state(self) -> dict:
        return {
            "wg_privkey_b64": self.keypair_privkey_b64,
            "wg_pubkey_b64": self.keypair_pubkey_b64,
            "handshake_node_addrs": list(self.handshake_node_addrs),
            "handshake_peer_data": dict(self.handshake_peer_data),
        }

    @classmethod
    def from_state(cls, state: dict) -> "WGCredentials":
        return cls(
            keypair_privkey_b64=state["wg_privkey_b64"],
            keypair_pubkey_b64=state["wg_pubkey_b64"],
            handshake_node_addrs=list(state.get("handshake_node_addrs", [])),
            handshake_peer_data=dict(state.get("handshake_peer_data", {})),
        )


@dataclass
class WireguardSession:
    """State the disconnect path needs to undo the connection."""

    interface: str
    config_path: str

    def to_state(self) -> dict:
        return {
            "backend": "wireguard",
            "interface": self.interface,
            "config_path": self.config_path,
        }


def fetch_creds(
    *, remote_url: str, session_id: int, private_key: bytes
) -> WGCredentials:
    """Do the chain-signed handshake. Generates the keypair, posts to the
    node, and returns the full picture. The caller MUST persist the result
    before calling bring_up() — the node won't accept a second handshake.
    """
    keypair = _KeyPair()
    handshake = fetch_node_credentials(
        remote_url=remote_url,
        session_id=session_id,
        private_key=private_key,
        request_data={"public_key": keypair.pubkey_b64},
    )
    return WGCredentials(
        keypair_privkey_b64=keypair.privkey_b64,
        keypair_pubkey_b64=keypair.pubkey_b64,
        handshake_node_addrs=handshake.node_addrs,
        handshake_peer_data=handshake.peer_data,
    )


def bring_up(creds: WGCredentials) -> WireguardSession:
    """Write the WG config from cached creds and bring the interface up."""
    handshake = HandshakeResult(
        node_addrs=creds.handshake_node_addrs,
        peer_data=creds.handshake_peer_data,
    )
    peer = _peer_from_response(handshake)
    config_path = str(WG_CONF_FILE)
    _write_config(config_path, creds.keypair_privkey_b64, peer)
    _bring_up(config_path)
    return WireguardSession(interface=WG_INTERFACE, config_path=config_path)


def disconnect(state: dict) -> None:
    """Tear down a previous bring-up. `state` comes from save_state()."""
    config_path = state.get("config_path", str(WG_CONF_FILE))
    _bring_down(config_path)


# --------------------------------------------------------------------------
# Internals
# --------------------------------------------------------------------------


@dataclass
class _Peer:
    ipv4: str
    ipv6: str
    endpoint: str
    public_key: str


class _KeyPair:
    def __init__(self) -> None:
        self._private = PrivateKey.generate()

    @property
    def privkey_b64(self) -> str:
        return base64.b64encode(bytes(self._private)).decode("ascii")

    @property
    def pubkey_b64(self) -> str:
        return base64.b64encode(bytes(self._private.public_key)).decode("ascii")


def _peer_from_response(handshake) -> _Peer:
    """Translate a v8.x AddPeerResponse into something wg-quick understands.

    The response shape (after our base64+json decode):
        {
          "addrs":    ["10.x.y.z/32", "fd00::/128"],
          "metadata": [
              {"port": 51820, "public_key": "<base64 32-byte>"}, ...
          ]
        }

    The node may publish itself on several remote addresses
    (`handshake.node_addrs`); we pick the first reachable one for the
    Endpoint line. AllowedIPs stays 0.0.0.0/0, ::/0 — we want full-tunnel.
    """
    data = handshake.peer_data or {}
    addrs = data.get("addrs") or []
    if not addrs:
        raise VpnError("Node response is missing the peer addrs.")
    # Sort so IPv4 comes first; we still keep both in the config.
    ipv4 = next((a for a in addrs if ":" not in a), "")
    ipv6 = next((a for a in addrs if ":" in a), "")
    if not ipv4 and not ipv6:
        raise VpnError(f"Node addrs not understood: {addrs!r}")

    metadata = data.get("metadata") or []
    if not metadata or not isinstance(metadata[0], dict):
        raise VpnError("Node response is missing server metadata.")
    server = metadata[0]
    port = server.get("port")
    pubkey = server.get("public_key")
    if not port or not pubkey:
        raise VpnError("Node metadata is missing port or public_key.")

    if not handshake.node_addrs:
        raise VpnError("Node didn't return a connectable address.")
    host = handshake.node_addrs[0]
    # The node_addrs entries are often `IP:something` already, but Port in
    # metadata is the *WireGuard* listen port — different from the API port
    # we just hit. So we take the host part only and append the WG port.
    host_only = host.split(":", 1)[0]
    endpoint = f"{host_only}:{port}"

    return _Peer(
        ipv4=ipv4 or "",
        ipv6=ipv6 or "",
        endpoint=endpoint,
        public_key=pubkey,
    )


def _write_config(config_path: str, our_privkey: str, peer: _Peer) -> None:
    cfg = configparser.RawConfigParser()
    cfg.optionxform = lambda x: x  # preserve CamelCase keys
    addresses = ", ".join(a for a in (peer.ipv4, peer.ipv6) if a)
    interface = {
        "PrivateKey": our_privkey,
        "Address": addresses,
    }
    # DNS handling differs per OS:
    #   - Windows: the WireGuard service applies DNS from this line.
    #   - macOS: wg-quick configures DNS via scutil (always present).
    #   - Linux: we do NOT set DNS here. wg-quick's DNS path needs
    #     resolvconf (not always installed), and more importantly it would
    #     leave the system pointed at whatever resolver was configured —
    #     often a PRIVATE one the exit node can't reach, which silently
    #     breaks all name resolution through the tunnel. Instead we manage
    #     /etc/resolv.conf directly (see _routing.set_dns) after bring-up,
    #     pointing it at a public resolver the node can actually reach.
    if sys.platform != "linux":
        interface["DNS"] = "1.1.1.1, 1.0.0.1"
    cfg["Interface"] = interface
    cfg["Peer"] = {
        "PublicKey": peer.public_key,
        "Endpoint": peer.endpoint,
        "AllowedIPs": "0.0.0.0/0, ::/0",
        "PersistentKeepalive": "25",
    }
    with open(config_path, "w", encoding="utf-8") as f:
        cfg.write(f)


def _bring_up(config_path: str) -> None:
    if sys.platform == "win32":
        # Bundled WireGuard for Windows. Requires the terminal to run as Admin.
        exe = bin_path("wireguard", "wireguard")
        _require(exe)
        # Uninstall any stale instance from a previous run before installing.
        # /installtunnelservice fails if the tunnel name is already registered.
        subprocess.run(
            [str(exe), "/uninstalltunnelservice", WG_INTERFACE],
            check=False,
            capture_output=True,
        )

        # /installtunnelservice frequently fails on the FIRST attempt right
        # after an uninstall because the Windows Service Control Manager
        # hasn't fully released the prior instance yet. A short pause + one
        # retry resolves it in practice — without this the user sees a
        # "permission" error and gets the connection on their second try.
        result = subprocess.run(
            [str(exe), "/installtunnelservice", config_path],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            time.sleep(2)
            result = subprocess.run(
                [str(exe), "/installtunnelservice", config_path],
                capture_output=True, text=True,
            )
        if result.returncode != 0:
            raise VpnError(
                "Bundled wireguard.exe failed. Run BlueCLI as Administrator."
            )
        # Critical: /installtunnelservice returns IMMEDIATELY but the Windows
        # service then starts asynchronously, allocates the TUN adapter,
        # applies the routing table, and finally performs the peer handshake.
        # All of that takes 3–5 seconds. If we let the connect flow continue
        # before this is done, public-IP verification fires while traffic is
        # still going out via the original Wi-Fi interface and reports the
        # user's home IP — exactly the "tunnel is up but says my router IP"
        # bug. The reference implementation sleeps 5s here for the same
        # reason; we match it.
        time.sleep(5)
        return

    # Linux / macOS: bundled wg-quick script. `wg-quick down` is idempotent
    # for our purposes — if nothing was up, we just ignore the failure.
    _wg_quick("down", config_path, check=False)
    result = _wg_quick("up", config_path, check=False)
    if result.returncode != 0:
        raise VpnError(
            "wg-quick failed: " + (result.stderr.strip() or result.stdout.strip())
        )
    # On Linux, point the resolver at a public DNS the exit node can reach.
    # (No-op on macOS, where wg-quick already set DNS via scutil from the
    # config's DNS= line.) See _routing.set_dns for the full rationale.
    _routing.set_dns()


def _bring_down(config_path: str) -> None:
    if sys.platform == "win32":
        exe = bin_path("wireguard", "wireguard")
        if not exe.is_file():
            return
        subprocess.run(
            [str(exe), "/uninstalltunnelservice", WG_INTERFACE],
            check=False,
            capture_output=True,
        )
        return

    wg_quick = bin_path("wireguard", "wg-quick")
    if wg_quick.is_file():
        _wg_quick("down", config_path, check=False)
    # Undo the resolv.conf change from bring-up (no-op off Linux / if unset).
    _routing.restore_dns()


def _wg_quick(verb: str, config_path: str, *, check: bool) -> subprocess.CompletedProcess:
    """Run `wg-quick <verb> <config>` via sudo.

    Prefers `bin/wireguard/wg-quick` if bundled; otherwise falls back to
    the system's `wg-quick` (typically `/usr/bin/wg-quick` from the
    `wireguard-tools` package). Both cases preserve PATH so wg-quick
    finds `wg`, `ip`, etc. — for the bundled case we prepend the bundle
    directory so the bundled tools win, for the system case the existing
    PATH is enough.
    """
    bundled = bin_path("wireguard", "wg-quick")
    if bundled.is_file():
        exe = bundled
        env = os.environ.copy()
        env["PATH"] = f"{bundled.parent}{os.pathsep}{env.get('PATH', '')}"
    else:
        system_exe = shutil.which("wg-quick")
        if not system_exe:
            raise VpnError(
                "wg-quick not found. Either bundle wg-quick + wg under "
                "bin/wireguard/, or install your distro's wireguard-tools "
                "package (Debian/Ubuntu: `sudo apt install wireguard-tools`; "
                "Fedora: `sudo dnf install wireguard-tools`; "
                "Arch: `sudo pacman -S wireguard-tools`; "
                "macOS: `brew install wireguard-tools`)."
            )
        exe = Path(system_exe)
        env = os.environ.copy()
    return subprocess.run(
        ["sudo", "-E", str(exe), verb, config_path],
        check=check, capture_output=True, text=True, env=env,
    )


def _require(path) -> None:
    if not path.is_file():
        raise VpnError(
            f"Bundled binary missing: {path}. Reinstall BlueCLI to restore it."
        )
