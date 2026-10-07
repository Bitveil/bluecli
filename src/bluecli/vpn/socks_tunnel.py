"""Shared full-tunnel engine for SOCKS-based backends (V2Ray, Xray, Hysteria2).

All three cores do the same job from BlueCLI's point of view: they open a
SOCKS5 proxy on 127.0.0.1 that forwards to the dVPN node. Turning that proxy
into a full tunnel is identical for every one of them, so it lives here once:

  1. the core boots and binds SOCKS5 on 127.0.0.1:<port> (caller-supplied);
  2. a host route sends the node's own IP via the original gateway, so the
     core's connection to the node never loops back into the tunnel;
  3. the chain gRPC endpoint is bypassed too, so querying/ending sessions
     keeps working while the tunnel is up;
  4. tun2socks creates the TUN device and forwards every packet to the SOCKS;
  5. a split default (0.0.0.0/1 + 128.0.0.0/1) goes through the TUN — the
     system's real default route is never touched, so a crash recovers
     connectivity on its own — and DNS is pointed at a public resolver.

Disconnect undoes this in reverse, best-effort. Backends differ only in how
they build their config and spawn their core; see `spawn_and_route`.

tun2socks (and wintun.dll on Windows) is shared by all SOCKS backends and
lives in `bin/v2ray/`.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from ..config import CONFIG_DIR
from . import VpnError
from . import _routing

DEFAULT_SOCKS_PORT = 1080
TUN_NAME = "blue-tun"  # also used by tun2socks's -device flag
TUN_LOCAL_IP = "198.18.0.1"  # IP assigned to the TUN device on every OS


@dataclass
class SocksSession:
    """Runtime of a SOCKS-core tunnel. Persisted to state.json with the same
    keys V2Ray uses (all listed in config._RUNTIME_STATE_KEYS), so stripping
    and teardown (`disconnect`) work identically for every SOCKS backend."""

    backend: str             # "xray" / "hysteria2"
    pid: int                 # core PID
    tun2socks_pid: int
    socks_port: int
    config_path: str
    node_ip: str             # so disconnect can drop the host route
    orig_gw: str             # original default-route gateway
    tun_iface: str = TUN_NAME

    def to_state(self) -> dict:
        return {
            "backend": self.backend,
            "pid": self.pid,
            "tun2socks_pid": self.tun2socks_pid,
            "socks_port": self.socks_port,
            "config_path": self.config_path,
            "tun_iface": self.tun_iface,
            "node_ip": self.node_ip,
            "orig_gw": self.orig_gw,
        }


def require_binary(path: Path, name: str) -> None:
    """Fail early, and clearly, if a bundled binary is missing or — on POSIX —
    present but not executable (zips made on Windows drop the execute bit, and
    the failure would otherwise surface later as a cryptic spawn error)."""
    if not path.is_file():
        raise VpnError(
            f"Bundled binary missing: {path}. Put {name} back under "
            f"{path.parent} (see bin/README.md), or re-extract BlueCLI."
        )
    if sys.platform != "win32" and not os.access(path, os.X_OK):
        raise VpnError(
            f"Bundled binary is not executable: {path}. "
            f"Fix it with: chmod +x {path}"
        )


def spawn_and_route(
    spawn_core: Callable[[], subprocess.Popen],
    *,
    core_name: str,
    core_log: str,
    tun_exe: Path,
    socks_port: int,
    bypass_ip: str,
    original,
) -> tuple[int, int]:
    """Spawn the SOCKS core + tun2socks and install split-default routing + DNS,
    bypassing `bypass_ip` (the node the core dials directly) via a host route.
    Rolls everything back and raises on any failure. Returns (core_pid, tun_pid).

    `spawn_core` must start the core with its config already written and its
    SOCKS5 inbound on 127.0.0.1:`socks_port`; `core_log` is the data/ log file
    it writes to, surfaced verbatim if the core dies at startup.
    """
    core_proc = spawn_core()
    time.sleep(1.5)
    if core_proc.poll() is not None:
        msg = read_log_tail(core_log) or "(no output)"
        raise VpnError(f"{core_name} exited immediately. {core_log} tail:\n{msg}")

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

        tun_proc = spawn_tun2socks(tun_exe, socks_port=socks_port)
        time.sleep(1.5)
        if tun_proc.poll() is not None:
            msg = read_log_tail("tun2socks.log") or "(no output)"
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
        rollback_routing(routing_steps, bypass_ip)
        kill_pid(tun_proc.pid if tun_proc else None)
        kill_pid(core_proc.pid)
        raise

    return core_proc.pid, tun_proc.pid


def disconnect(state: dict) -> None:
    """Tear down everything spawn_and_route() set up. Best-effort: every step
    runs regardless of earlier failures, so a partially-bricked state still
    gets unwound. `state` is the persisted session (pid, tun2socks_pid, ...)."""
    tun_iface = state.get("tun_iface", TUN_NAME)
    node_ip = state.get("node_ip")

    # Routing first, so even if process kill fails the user has internet back.
    _routing.restore_dns()
    _routing.remove_default_via_tun(tun_iface, TUN_LOCAL_IP)
    if node_ip:
        _routing.remove_host_route(node_ip)
    _routing.remove_chain_bypass()

    for pid_key in ("tun2socks_pid", "pid"):
        kill_pid(state.get(pid_key))


def resolve_endpoint_ip(host: str) -> str:
    """Resolve a node's data ENDPOINT host to an IPv4 literal (returns it
    unchanged if it's already an IP).

    This MUST run before the tunnel captures the default route. The core
    dials the node by this IP, so it never needs DNS at connect time.
    Otherwise, for a node that advertises a hostname instead of an IP, the
    core resolves the name only once the connect is under way — by which
    point the default route is already redirected into the TUN, and the
    lookup is trapped inside the very tunnel it's trying to build:
        resolve node -> DNS query -> default route -> TUN -> tun2socks
            -> core SOCKS -> dial node -> resolve node ...
    a circular dependency that hangs every such connect. Resolving up-front
    breaks the loop, and the same IP gets the bypass host route.
    """
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        raise VpnError(f"Could not resolve node endpoint {host!r}: {e}") from e


def pick_free_port(preferred: int = 0) -> int:
    """Try `preferred` first, fall back to a kernel-assigned port."""
    for port in ((preferred, 0) if preferred else (0,)):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return s.getsockname()[1]
            except OSError:
                continue
    raise VpnError("Could not find a free local port for the SOCKS5 proxy.")


# Windows: keep our spawned helpers detached from the parent console so
# Ctrl-C doesn't take them down before the routing rollback can run.
_DETACHED_FLAGS = 0x00000200 | 0x00000008 if os.name == "nt" else 0


def popen_logged(
    args: list[str], log_name: str, *, cwd: str
) -> subprocess.Popen:
    """Spawn a child process and tee its combined output to data/<log_name>.

    Every core and tun2socks survive in the background past Python's
    lifetime; we use the same launch shape for all of them so a missing
    exit code or a wedged write to any log gets diagnosed the same way.
    """
    log_file = open(CONFIG_DIR / log_name, "wb")
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


def spawn_tun2socks(exe: Path, *, socks_port: int) -> subprocess.Popen:
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
    return popen_logged(args, "tun2socks.log", cwd=str(exe.parent))


def read_log_tail(log_name: str, max_chars: int = 600) -> str:
    """Tail data/<log_name> so we can surface it in error messages."""
    try:
        log_path = CONFIG_DIR / log_name
        if not log_path.exists():
            return ""
        text = log_path.read_bytes().decode("utf-8", errors="replace").strip()
        return "... " + text[-max_chars:] if len(text) > max_chars else text
    except OSError:
        return ""


def kill_pid(pid) -> None:
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


def rollback_routing(steps: list[str], node_ip: str) -> None:
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
