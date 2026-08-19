"""AmneziaWG backend.

AmneziaWG is WireGuard with DPI-resistant obfuscation: on top of the usual
Curve25519 keypair + port + public key, the handshake carries per-connection
obfuscation parameters (S1-S4, H1-H4, I1-I5) that BOTH sides must agree on.

Two launch techniques, one per OS, chosen for click-and-run:

  Windows — `amneziawg.exe`, the official AmneziaWG Windows client (a fork
  of the WireGuard for Windows client): `/installtunnelservice <conf>`
  installs a service that creates the TUN, applies the conf (Address, DNS,
  MTU, obfuscation), routes and sets DNS. Mirrors the WireGuard backend.

  Linux   — userspace engine `amneziawg-go` (fork of wireguard-go): it
  creates the TUN itself and exposes the standard UAPI control socket
  (/var/run/amneziawg/<iface>.sock); `awg setconf` (from amneziawg-tools)
  programs the device over UAPI automatically. No kernel module, no
  driver install. Routing is done by BlueCLI itself with the same helpers
  as the V2Ray backend.

The handshake with a Sentinel node REGISTERS the peer in the node's
database; the node returns 409 on any subsequent handshake for the same
session id. So, exactly like the WireGuard backend:

  fetch_creds()  — chain-signed POST + keypair generation. The caller MUST
                   persist the returned AWGCredentials before bring_up.

  bring_up()     — write the .conf from cached creds, launch the tunnel,
                   install routing. Safe to retry after disconnect.
"""

from __future__ import annotations

import base64
import os
import random
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from nacl.public import PrivateKey

from ..config import AWG_CONF_FILE, AWG_INTERFACE, bin_path
from . import HandshakeResult, VpnError, fetch_node_credentials
from . import _routing


@dataclass
class AWGCredentials:
    """Everything we need to bring up the tunnel later, without re-asking
    the node. Serializable to plain dicts for state.json persistence."""

    keypair_privkey_b64: str
    keypair_pubkey_b64: str
    handshake_node_addrs: list = field(default_factory=list)
    handshake_peer_data: dict = field(default_factory=dict)

    def to_state(self) -> dict:
        return {
            "awg_privkey_b64": self.keypair_privkey_b64,
            "awg_pubkey_b64": self.keypair_pubkey_b64,
            "handshake_node_addrs": list(self.handshake_node_addrs),
            "handshake_peer_data": dict(self.handshake_peer_data),
        }

    @classmethod
    def from_state(cls, state: dict) -> "AWGCredentials":
        return cls(
            keypair_privkey_b64=state["awg_privkey_b64"],
            keypair_pubkey_b64=state["awg_pubkey_b64"],
            handshake_node_addrs=list(state.get("handshake_node_addrs", [])),
            handshake_peer_data=dict(state.get("handshake_peer_data", {})),
        )


@dataclass
class AmneziaWGSession:
    """State the disconnect path needs to undo the connection.

    On Windows the tunnel is owned by the installed service, not by a child
    process: `pid` is None there and teardown = /uninstalltunnelservice.
    """

    config_path: str
    tun_iface: str
    pid: Optional[int] = None
    node_ip: str = ""
    orig_gw: str = ""
    tun_local_ip: str = ""

    def to_state(self) -> dict:
        return {
            "backend": "amneziawg",
            "config_path": self.config_path,
            "tun_iface": self.tun_iface,
            "pid": self.pid,
            "node_ip": self.node_ip,
            "orig_gw": self.orig_gw,
            "tun_local_ip": self.tun_local_ip,
        }


def fetch_creds(
    *, remote_url: str, session_id: int, private_key: bytes
) -> AWGCredentials:
    """Do the chain-signed handshake. Generates the keypair, posts to the
    node, and returns the full picture. The caller MUST persist the result
    before calling bring_up() — the node won't accept a second handshake.
    The request body is identical to WireGuard's: the node keys the peer
    by our public key and answers with the obfuscation params."""
    keypair = _KeyPair()
    handshake = fetch_node_credentials(
        remote_url=remote_url,
        session_id=session_id,
        private_key=private_key,
        request_data={"public_key": keypair.pubkey_b64},
    )
    return AWGCredentials(
        keypair_privkey_b64=keypair.privkey_b64,
        keypair_pubkey_b64=keypair.pubkey_b64,
        handshake_node_addrs=handshake.node_addrs,
        handshake_peer_data=handshake.peer_data,
    )


def bring_up(creds: AWGCredentials) -> AmneziaWGSession:
    """Write the AWG config from cached creds and bring the tunnel up."""
    handshake = HandshakeResult(
        node_addrs=creds.handshake_node_addrs,
        peer_data=creds.handshake_peer_data,
    )
    peer = _peer_from_response(handshake)

    # Resolve the node BEFORE the tunnel is up: afterwards the system
    # resolver would send the query through the tunnel we're still
    # building. The resolved IP is also what we pin with a host route on
    # Linux so the tunnel never loops into itself.
    node_ip = _resolve_node_ip(peer.host)

    config_path = str(AWG_CONF_FILE)
    _write_config(
        config_path,
        our_privkey=creds.keypair_privkey_b64,
        peer=peer,
        junk=_generate_junk(),
        listen_port=_pick_free_port(),
    )
    return _bring_up(config_path, node_ip=node_ip, peer=peer)


def disconnect(state: dict) -> None:
    """Tear down a previous bring-up. `state` comes from save_state().

    Windows: uninstall the tunnel service (it owns the TUN, routes and
    DNS — nothing else to undo). Linux: DNS first, then routes, then the
    engine (killing it would make the TUN disappear and orphan the routes).
    """
    if sys.platform == "win32":
        exe = bin_path("amneziawg", "amneziawg")
        if exe.is_file():
            subprocess.run(
                [str(exe), "/uninstalltunnelservice", AWG_INTERFACE],
                check=False, capture_output=True,
            )
        return

    _routing.restore_dns()
    _routing.remove_default_via_tun(
        AWG_INTERFACE, state.get("tun_local_ip") or _DEFAULT_LOCAL_IP
    )
    node_ip = state.get("node_ip")
    if node_ip:
        _routing.remove_host_route(node_ip)
    _routing.remove_chain_bypass()
    _kill_pid(state.get("pid"))


# --------------------------------------------------------------------------
# Internals
# --------------------------------------------------------------------------

_DEFAULT_LOCAL_IP = "198.18.0.1"

# Obfuscation params the node sends in metadata[0]. S/H are uint16/uint32
# numbers, I are opaque strings (tag blobs like "<b 0x1f00>") and optional.
_OBFS_U16_KEYS = ("s1", "s2", "s3", "s4")
_OBFS_U32_KEYS = ("h1", "h2", "h3", "h4")
_OBFS_STR_KEYS = ("i1", "i2", "i3", "i4", "i5")

# Keys the Windows client understands but `awg setconf` (Linux) rejects
# with "Line unrecognized" — stripped into a dedicated file for setconf.
_SETCONF_DROP_KEYS = ("Address", "DNS", "MTU")


@dataclass
class _Peer:
    ipv4: str            # e.g. "10.0.0.5/32" or ""
    ipv6: str            # e.g. "fd00::5/128" or ""
    host: str            # node host from node_addrs[0]
    endpoint: str        # "<resolved-ip>:<awg-port>" (filled by bring_up)
    public_key: str
    obfs: dict = field(default_factory=dict)


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
    """Translate the AddPeerResponse into engine terms.

    Response shape (after our base64+json decode):
        {
          "addrs":    ["10.x.y.z/32", "fd00::/128"],
          "metadata": [
              {"port": 51820, "public_key": "<b64>",
               "s1": 13, ..., "h1": 28, ..., "i1": "<b 0x1f00>"}, ...
          ]
        }

    The port in metadata is the AmneziaWG listen port (different from the
    API port we handshook on); the host comes from node_addrs[0].
    """
    data = handshake.peer_data or {}
    addrs = data.get("addrs") or []
    if not addrs:
        raise VpnError("Node response is missing the peer addrs.")
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

    obfs: dict = {}
    for k in _OBFS_U16_KEYS + _OBFS_U32_KEYS:
        v = server.get(k)
        if not isinstance(v, int) or v < 0:
            raise VpnError(
                f"Node metadata is missing {k.upper()} (obfuscation param)."
            )
        obfs[k] = v
    for k in _OBFS_STR_KEYS:
        v = server.get(k)
        if v is not None and not isinstance(v, str):
            raise VpnError(f"Node metadata {k.upper()} must be a string.")
        if v:
            obfs[k] = v
    # Spec sanity (the node generates these itself; this only catches
    # misbehaving nodes before we hand garbage to the engine):
    if any(obfs[k] > 64 for k in ("s1", "s2", "s3")) or obfs["s4"] > 32:
        raise VpnError("Node sent out-of-range S obfuscation params.")
    if any(obfs[k] <= 4 for k in _OBFS_U32_KEYS):
        raise VpnError("Node sent out-of-range H obfuscation params.")
    if obfs["s1"] + 56 == obfs["s2"]:
        raise VpnError("Node sent conflicting S1/S2 obfuscation params.")

    if not handshake.node_addrs:
        raise VpnError("Node didn't return a connectable address.")
    host = handshake.node_addrs[0].split(":", 1)[0]

    return _Peer(
        ipv4=ipv4 or "",
        ipv6=ipv6 or "",
        host=host,
        endpoint=f"{host}:{port}",
        public_key=pubkey,
        obfs=obfs,
    )


def _generate_junk() -> dict:
    """Client-side obfuscation params, within the ranges the SDK accepts:
    Jc 0-10; Jmin/Jmax 64-1024 with Jmin < Jmax. Values are per-connection
    and meaningless to the server beyond the ranges — random is fine."""
    jc = random.randint(0, 10)
    jmin = random.randint(64, 1023)
    jmax = random.randint(jmin + 1, 1024)
    return {"jc": jc, "jmin": jmin, "jmax": jmax}


def _write_config(
    config_path: str, *, our_privkey: str, peer: _Peer, junk: dict, listen_port: int
) -> None:
    """Write the FULL client conf, mirroring the SDK's client.conf.tmpl:
    the Windows client (amneziawg.exe) needs Address/DNS/MTU; the Linux
    path strips them into a separate file for `awg setconf` (see
    _write_setconf_conf), which rejects unrecognized lines."""
    obfs = peer.obfs
    addresses = ", ".join(a for a in (peer.ipv4, peer.ipv6) if a)
    lines = [
        "[Interface]",
        f"Address = {addresses}",
    ]
    if sys.platform != "linux":
        # Windows: the service applies DNS from this line (like the WG
        # client). Linux: DNS is managed by _routing.set_dns instead, and
        # this line is stripped before setconf anyway.
        lines.append("DNS = 1.1.1.1, 1.0.0.1")
    lines += [
        f"ListenPort = {listen_port}",
        "MTU = 1420",
        f"PrivateKey = {our_privkey}",
        f"Jc = {junk['jc']}",
        f"Jmin = {junk['jmin']}",
        f"Jmax = {junk['jmax']}",
    ]
    for k in _OBFS_U16_KEYS + _OBFS_U32_KEYS:
        lines.append(f"{k.upper()} = {obfs[k]}")
    for k in _OBFS_STR_KEYS:
        if k in obfs:
            lines.append(f"{k.upper()} = {obfs[k]}")
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {peer.public_key}",
        f"Endpoint = {peer.endpoint}",
        "AllowedIPs = 0.0.0.0/0, ::/0",
        "PersistentKeepalive = 25",
        "",
    ]
    with open(config_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def _write_setconf_conf(full_path: str, out_path: str) -> None:
    """Strip the keys `awg setconf` rejects ("Line unrecognized: `Address
    = ...'") into a separate file; the remaining keys are accepted as-is."""
    keep = []
    with open(full_path, "r", encoding="utf-8") as f:
        for raw in f:
            key = raw.split("=", 1)[0].strip()
            if key in _SETCONF_DROP_KEYS:
                continue
            keep.append(raw)
    with open(out_path, "w", encoding="utf-8") as f:
        f.writelines(keep)


def _bring_up(config_path: str, *, node_ip: str, peer: _Peer) -> AmneziaWGSession:
    if sys.platform == "win32":
        _bring_up_windows(config_path)
        return AmneziaWGSession(
            config_path=config_path, tun_iface=AWG_INTERFACE
        )

    # --- Linux: userspace engine + awg setconf + our own routing ----------
    if not peer.ipv4:
        raise VpnError(
            "This node assigned only an IPv6 address to the tunnel; "
            "AmneziaWG support in BlueCLI is IPv4-only on Linux for now."
        )
    local_ip = peer.ipv4.split("/", 1)[0]

    engine_exe = bin_path("amneziawg", "amneziawg-go")
    awg_exe = bin_path("amneziawg", "awg")
    _require(engine_exe, "amneziawg-go")
    _require(awg_exe, "awg")

    original = _routing.get_default_route()
    if original is None:
        raise VpnError("Could not determine the current default gateway.")

    # A crashed previous run may have left the TUN (or a zombie engine)
    # behind; both would make amneziawg-go refuse to start. Removing the
    # interface kills the zombie engine too. Best-effort.
    _sudo_run(["ip", "link", "del", AWG_INTERFACE], check=False)

    proc = _spawn_engine(engine_exe)
    try:
        _wait_until_ready(awg_exe)
        setconf_path = str(AWG_CONF_FILE.with_name("awg-blue.setconf.conf"))
        _write_setconf_conf(config_path, setconf_path)
        _setconf(awg_exe, setconf_path)
        _wait_for_interface()
        _routing.add_host_route(node_ip, original)
        _routing.add_chain_bypass(original)
        _routing.configure_tun(AWG_INTERFACE, local_ip)
        _routing.add_default_via_tun(AWG_INTERFACE, local_ip)
        _routing.set_dns()
    except Exception:
        _rollback_after_failure(proc, node_ip)
        raise

    return AmneziaWGSession(
        pid=proc.pid,
        config_path=config_path,
        tun_iface=AWG_INTERFACE,
        node_ip=node_ip,
        orig_gw=original.gateway,
        tun_local_ip=local_ip,
    )


def _bring_up_windows(config_path: str) -> None:
    """Install the tunnel as a Windows service via the bundled
    amneziawg.exe client (fork of the WireGuard for Windows client).

    The service owns the TUN adapter, applies Address/DNS/MTU from the
    conf, installs routing and sets DNS — nothing else to do. Mirrors the
    WireGuard backend, including the one-retry for the Service Control
    Manager and the 5s settle before returning.
    """
    exe = bin_path("amneziawg", "amneziawg")
    _require(exe, "amneziawg.exe (AmneziaWG Windows client)")
    # Uninstall any stale instance from a previous run before installing.
    # /installtunnelservice fails if the tunnel name is already registered.
    subprocess.run(
        [str(exe), "/uninstalltunnelservice", AWG_INTERFACE],
        check=False, capture_output=True,
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
            "Bundled amneziawg.exe failed: "
            + (result.stderr.strip() or result.stdout.strip()
               or "run BlueCLI as Administrator and try again.")
        )
    # /installtunnelservice returns immediately; the service then starts
    # asynchronously, allocates the TUN adapter and applies routing. The
    # reference client sleeps 5s here for the same reason — match it.
    time.sleep(5)


def _spawn_engine(exe: Path) -> subprocess.Popen:
    """Start amneziawg-go in the foreground (so we keep its pid).

    `amneziawg-go -f awg-blue` via sudo -E, same shape as wg-quick in the
    WireGuard backend. (Windows never gets here: it uses the service
    client instead.)
    """
    args = ["sudo", "-E", str(exe), "-f", AWG_INTERFACE]
    return _popen_logged(args, "amneziawg.log", cwd=str(AWG_CONF_FILE.parent))


def _wait_until_ready(awg_exe: Path, timeout: float = 10.0) -> None:
    """Poll `awg show <iface>` until the engine's UAPI socket answers.

    `awg` auto-detects the userspace socket, so a non-zero exit here means
    the engine isn't listening yet (or died at startup) — OR that the probe
    itself can't run (e.g. a non-executable `awg`). Surface the probe's own
    stderr in the error: without it, a broken probe misleadingly points the
    blame at the (possibly healthy) engine and its harmless startup banner."""
    deadline = time.time() + timeout
    last: Optional[subprocess.CompletedProcess] = None
    while time.time() < deadline:
        last = _awg(awg_exe, "show", AWG_INTERFACE, check=False)
        if last.returncode == 0:
            return
        time.sleep(0.3)
    probe_err = ""
    if last is not None:
        probe_err = (last.stderr or last.stdout or "").strip()
    tail = _read_log_tail()
    raise VpnError(
        "amneziawg-go did not come up within 10s. "
        + (f"Last 'awg show' error: {probe_err}\n" if probe_err else "")
        + (f"Log tail:\n{tail}" if tail else "No log output — check that the "
          "binary runs (missing libc? wrong architecture?).")
    )


def _setconf(awg_exe: Path, config_path: str) -> None:
    result = _awg(awg_exe, "setconf", AWG_INTERFACE, config_path, check=False)
    if result.returncode != 0:
        raise VpnError(
            "awg setconf failed: "
            + (result.stderr.strip() or result.stdout.strip() or "unknown error")
        )


def _wait_for_interface(timeout: float = 5.0) -> None:
    """The TUN is created by the engine; make sure it exists before we try
    to assign an address to it. (Windows polls inside configure_tun, but
    the Windows path never gets here.)"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = _sudo_run(["ip", "link", "show", AWG_INTERFACE], check=False)
        if result.returncode == 0:
            return
        time.sleep(0.2)
    raise VpnError(
        f"TUN interface {AWG_INTERFACE!r} did not appear within {timeout:.0f}s. "
        "Check data/amneziawg.log."
    )


def _rollback_after_failure(proc: subprocess.Popen, node_ip: str) -> None:
    """Best-effort undo of whatever routing/process state we created before
    the failure. Never raises — we're already unwinding an error."""
    try:
        _routing.remove_default_via_tun(AWG_INTERFACE, _DEFAULT_LOCAL_IP)
    except Exception:
        pass
    try:
        _routing.remove_host_route(node_ip)
    except Exception:
        pass
    try:
        _routing.remove_chain_bypass()
    except Exception:
        pass
    _kill_pid(proc.pid)


def _awg(awg_exe: Path, *args: str, check: bool) -> subprocess.CompletedProcess:
    """Run the awg tool via sudo -E (the UAPI socket is root-owned)."""
    return _sudo_run([str(awg_exe), *args], check=check)


def _sudo_run(args: list[str], *, check: bool) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["sudo", "-E", *args], check=check, capture_output=True, text=True
    )


def _require(path: Path, name: str) -> None:
    if not path.is_file():
        raise VpnError(
            f"Bundled binary missing: {path}. Put {name} under bin/amneziawg/"
            " — see bin/README.md for the exact download/build instructions, "
            "then reinstall or re-copy BlueCLI."
        )
    if sys.platform != "win32" and not os.access(path, os.X_OK):
        # Zips made on Windows lose POSIX execute bits; without this check
        # the failure surfaces later as a cryptic "command not found" from
        # sudo. Tell the user the actual problem and the one-line fix.
        raise VpnError(
            f"Bundled binary is not executable: {path}. "
            f"Fix it with: chmod +x {path}"
        )


def _resolve_node_ip(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except OSError as e:
        raise VpnError(f"Could not resolve node address {host!r}: {e}") from e


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# Keep our spawned engine detached from the parent console so Ctrl-C
# doesn't take it down before the routing rollback can run.
_DETACHED_FLAGS = 0x00000200 | 0x00000008 if os.name == "nt" else 0


def _popen_logged(
    args: list[str], log_name: str, *, cwd: str
) -> subprocess.Popen:
    """Spawn the engine and tee its combined output to data/<log_name>."""
    log_file = open(AWG_CONF_FILE.parent / log_name, "wb")
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
        # otherwise leak (1 per connect) for the life of the CLI.
        log_file.close()


def _read_log_tail(log_name: str = "amneziawg.log", max_chars: int = 600) -> str:
    """Tail data/<log_name> so we can surface it in error messages."""
    try:
        log_path = AWG_CONF_FILE.parent / log_name
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
