"""Cross-platform routing helpers used to make V2Ray seamless.

V2Ray exposes a local SOCKS5 proxy; tun2socks forwards a TUN/wintun
interface into it. For all traffic to actually flow through that path
we have to:

  1. Discover the current default gateway + interface, so we can punch
     a host route through it for the dVPN node's own IP (otherwise
     packets to the node loop into the tunnel they're hosting).
  2. Install a default route through the TUN at low metric, leaving the
     system default intact so a crash recovers connectivity by itself.

Disconnect runs all of this in reverse, best-effort. All commands go
through subprocess — no extra Python dependencies.
"""

from __future__ import annotations

import ipaddress
import json
import platform
import re
import socket
import subprocess
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class DefaultRoute:
    gateway: str   # e.g. "192.168.1.1"
    interface: str  # e.g. "eth0", "en0", or on Windows the interface name


def is_windows() -> bool:
    return platform.system() == "Windows"


def is_macos() -> bool:
    return platform.system() == "Darwin"


def is_linux() -> bool:
    return platform.system() == "Linux"


def _run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command; raise RuntimeError with the actual stderr on failure
    so the user sees something they can act on."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError as e:
        raise RuntimeError(
            f"Command not found: {cmd[0]!r}. "
            "Install the required system tools (iproute2 on Linux, "
            "route is standard on Windows/macOS)."
        ) from e
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(cmd)}\n  stdout: {proc.stdout.strip()}\n  stderr: {proc.stderr.strip()}"
        )
    return proc


# ---------------------------------------------------------------------------
# Default-route discovery
# ---------------------------------------------------------------------------


def get_default_route() -> Optional[DefaultRoute]:
    try:
        if is_linux():
            return _get_default_route_linux()
        if is_macos():
            return _get_default_route_macos()
        if is_windows():
            return _get_default_route_windows()
    except RuntimeError:
        return None
    return None


def _get_default_route_linux() -> Optional[DefaultRoute]:
    proc = _run(["ip", "route", "show", "default"], check=False)
    # Output: "default via 192.168.1.1 dev wlan0 ..."
    m = re.search(r"default via (\S+) dev (\S+)", proc.stdout)
    if not m:
        return None
    return DefaultRoute(gateway=m.group(1), interface=m.group(2))


def _get_default_route_macos() -> Optional[DefaultRoute]:
    proc = _run(["route", "-n", "get", "default"], check=False)
    gw = iface = None
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("gateway:"):
            gw = line.split(":", 1)[1].strip()
        elif line.startswith("interface:"):
            iface = line.split(":", 1)[1].strip()
    if not gw or not iface:
        return None
    return DefaultRoute(gateway=gw, interface=iface)


def _get_default_route_windows() -> Optional[DefaultRoute]:
    # `route print 0.0.0.0` lines look like:
    #   0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.42     25
    proc = _run(["route", "print", "0.0.0.0"], check=False)
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            return DefaultRoute(gateway=parts[2], interface=parts[3])  # iface here is the local IP
    return None


# ---------------------------------------------------------------------------
# Host route for the dVPN node IP (so we don't tunnel into ourselves)
# ---------------------------------------------------------------------------


def add_host_route(node_ip: str, original: DefaultRoute) -> None:
    if is_linux():
        _run(["ip", "route", "add", f"{node_ip}/32", "via", original.gateway, "dev", original.interface])
    elif is_macos():
        _run(["route", "-n", "add", "-host", node_ip, original.gateway])
    elif is_windows():
        _run(["route", "add", node_ip, "mask", "255.255.255.255", original.gateway])


def remove_host_route(node_ip: str) -> None:
    """Best-effort; never raises (we're cleaning up, errors here mustn't block disconnect)."""
    if is_linux():
        _run(["ip", "route", "del", f"{node_ip}/32"], check=False)
    elif is_macos():
        _run(["route", "-n", "delete", "-host", node_ip], check=False)
    elif is_windows():
        _run(["route", "delete", node_ip], check=False)


# --------------------------------------------------------------------------
# Chain endpoint bypass
# --------------------------------------------------------------------------
#
# The chain gRPC endpoint must stay reachable over the REAL network whether or
# not a tunnel is up. If its traffic went through the tunnel, then connecting,
# ending the session that carries the tunnel, or tearing the tunnel down would
# all cut us off from the chain — leaving sessions impossible to query or end
# until the app is restarted (and even then it can wedge). So while a tunnel is
# up we pin the endpoint's IP(s) to the original gateway with /32 host routes
# (more specific than the tunnel's split-default), exactly like the node's own
# bypass. The IPs we routed are recorded in a small file so teardown can undo
# them; everything is best-effort — failure just means "no bypass", never a
# crash.


def _chain_bypass_path():
    from .. import config
    return config.CONFIG_DIR / "chain_bypass.json"


def _resolve_chain_ips() -> list[str]:
    """The chain gRPC endpoint's IP(s), resolved over the current network.
    Empty on any failure, so a resolution problem simply skips the bypass."""
    from .. import config
    cfg = config.load_config()
    host = (cfg.get("grpc_host") or "").strip()
    if not host:
        return []
    try:
        ipaddress.ip_address(host)
        return [host]  # already a literal IP — nothing to resolve
    except ValueError:
        pass
    try:
        port = int(cfg.get("grpc_port", 9090))
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (OSError, ValueError):
        return []
    ips: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips


def add_chain_bypass(original: DefaultRoute) -> None:
    """Pin the chain endpoint to the original gateway so its traffic skips the
    tunnel. Clears any stale bypass from a previous (crashed) session first."""
    remove_chain_bypass()
    added: list[str] = []
    for ip in _resolve_chain_ips():
        try:
            add_host_route(ip, original)
            added.append(ip)
        except Exception:
            pass  # already routed / transient — skip this IP, keep the rest
    if added:
        _write_chain_bypass(added)


def remove_chain_bypass() -> None:
    """Undo add_chain_bypass. Idempotent; safe when nothing is set."""
    for ip in _read_chain_bypass():
        try:
            remove_host_route(ip)
        except Exception:
            pass
    _clear_chain_bypass()


def _read_chain_bypass() -> list[str]:
    try:
        with _chain_bypass_path().open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    return [x for x in data if isinstance(x, str)] if isinstance(data, list) else []


def _write_chain_bypass(ips: list[str]) -> None:
    from .. import config
    try:
        config._atomic_write_json(_chain_bypass_path(), ips)
    except OSError:
        pass


def _clear_chain_bypass() -> None:
    try:
        _chain_bypass_path().unlink()
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Split default route via the TUN interface
# ---------------------------------------------------------------------------


def configure_tun(tun_iface: str, local_ip: str = "198.18.0.1") -> None:
    """Assign an IP to the TUN device and bring it up.

    Required on every OS: without an IP on the device, the kernel cannot
    route through it (any `route add ... <gateway>` whose gateway sits
    inside the TUN subnet would silently fail because the gateway is
    not on-link).

    On Linux/macOS we use the standard ip / ifconfig commands. On
    Windows we use `netsh` AFTER polling for the wintun adapter to
    appear (wintun creates the adapter asynchronously when tun2socks
    starts, so it may not be there yet when we get here).
    """
    if is_linux():
        _run(["ip", "addr", "add", f"{local_ip}/30", "dev", tun_iface])
        _run(["ip", "link", "set", tun_iface, "up"])
    elif is_macos():
        # macOS utun is point-to-point; the peer endpoint is fictitious.
        peer_ip = "198.18.0.2"
        _run(["ifconfig", tun_iface, "inet", local_ip, peer_ip, "up"])
    elif is_windows():
        _configure_tun_windows(tun_iface, local_ip)


def _configure_tun_windows(tun_iface: str, local_ip: str) -> None:
    """Configure the wintun adapter that tun2socks just created.

    Follows the official xjasonlyu/tun2socks Windows wiki sequence:
      https://github.com/xjasonlyu/tun2socks/wiki/Examples#windows

    Steps:
      1. Poll for the wintun adapter to appear (wintun creation is async).
      2. Assign an IPv4 address (without this, every `add route` that names
         this IP as gateway silently no-ops because Windows can't determine
         the egress interface).
      3. Verify the address actually shows up via PowerShell Get-NetIPAddress
         — `netsh show addresses` hides IPs on adapters in 'media
         disconnected' state, which wintun stays in until tun2socks reads
         packets (chicken-and-egg with the routes we haven't added yet).
         The PowerShell cmdlet queries the IP store directly and doesn't
         care about media state.
      4. If verification still fails, fall back to `New-NetIPAddress` —
         it uses a different code path that bypasses some antivirus hooks
         and netsh quirks.
      5. Set DNS on the wintun so DNS via the tunnel works.
    """
    deadline = time.time() + 5.0
    while time.time() < deadline:
        proc = _run(["netsh", "interface", "show", "interface"], check=False)
        if tun_iface in proc.stdout:
            break
        time.sleep(0.3)
    else:
        raise RuntimeError(
            f"wintun adapter {tun_iface!r} did not appear within 5s. "
            "tun2socks may have failed to create it — check its stderr log."
        )

    # netsh first — fastest path and historically reliable on installs
    # without aggressive AV.
    _run([
        "netsh", "interface", "ipv4", "set", "address",
        f"name={tun_iface}", "source=static",
        f"addr={local_ip}", "mask=255.255.255.0",
    ], check=False)

    # Wait a beat then verify via PowerShell (see docstring for why netsh
    # show-addresses doesn't work here).
    time.sleep(0.8)
    if not _wintun_ip_present(tun_iface, local_ip):
        # Likely netsh got hooked by AV and silently dropped the change.
        # Retry with New-NetIPAddress, which uses a different code path.
        _run([
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            (
                f"Remove-NetIPAddress -InterfaceAlias '{tun_iface}' "
                f"-AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue; "
                f"New-NetIPAddress -InterfaceAlias '{tun_iface}' "
                f"-IPAddress {local_ip} -PrefixLength 24 -ErrorAction SilentlyContinue "
                f"| Out-Null"
            ),
        ], check=False)
        time.sleep(1.0)
        if not _wintun_ip_present(tun_iface, local_ip):
            raise RuntimeError(
                f"Could not assign {local_ip} to {tun_iface!r}. Both netsh "
                "and PowerShell New-NetIPAddress failed. Most likely cause: "
                "antivirus or Windows Defender Firewall is blocking changes "
                "to network adapter configuration. Add an exception for the "
                "BlueCLI folder and try again."
            )

    # DNS on the wintun. Without this, browsers' DNS leaks to the LAN router.
    _run([
        "netsh", "interface", "ipv4", "set", "dnsservers",
        f"name={tun_iface}", "static", "address=8.8.8.8",
        "register=none", "validate=no",
    ], check=False)


def _wintun_ip_present(tun_iface: str, local_ip: str) -> bool:
    """Return True if `local_ip` is currently assigned to `tun_iface`,
    using PowerShell Get-NetIPAddress which queries the IP store directly.

    We deliberately don't use `netsh show addresses` for this check: on
    Windows, wintun adapters stay in 'media disconnected' state until a
    user-mode process (tun2socks here) actively reads packets, and netsh
    hides IPs on disconnected adapters even when they're correctly
    persisted in the store. PowerShell's cmdlet has no such quirk.
    """
    proc = _run([
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        (
            f"if (Get-NetIPAddress -InterfaceAlias '{tun_iface}' "
            f"-IPAddress '{local_ip}' -AddressFamily IPv4 "
            f"-ErrorAction SilentlyContinue) {{ 'OK' }}"
        ),
    ], check=False)
    return "OK" in (proc.stdout or "")


def add_default_via_tun(tun_iface: str, gateway_ip: str = "198.18.0.1") -> None:
    """Install a default route through the TUN at the lowest metric.

    On Windows we use `netsh interface ipv4 add route` (NOT `route add`):
    `route add` infers the interface from the gateway IP and silently
    picks the wrong one when multiple interfaces share a subnet. The
    netsh form names the interface explicitly. Metric=1 makes this route
    win over the system default (typically metric 5-25).
    """
    if is_linux():
        for net in ("0.0.0.0/1", "128.0.0.0/1"):
            _run(["ip", "route", "add", net, "dev", tun_iface])
    elif is_macos():
        for net in ("0.0.0.0/1", "128.0.0.0/1"):
            _run(["route", "-n", "add", "-net", net, "-interface", tun_iface])
    elif is_windows():
        _run([
            "netsh", "interface", "ipv4", "add", "route",
            "0.0.0.0/0", tun_iface, gateway_ip, "metric=1", "store=active",
        ])


def remove_default_via_tun(tun_iface: str, gateway_ip: str = "198.18.0.1") -> None:
    """Best-effort cleanup, mirrors add_default_via_tun."""
    if is_linux():
        for net in ("0.0.0.0/1", "128.0.0.0/1"):
            _run(["ip", "route", "del", net, "dev", tun_iface], check=False)
    elif is_macos():
        for net in ("0.0.0.0/1", "128.0.0.0/1"):
            _run(["route", "-n", "delete", "-net", net, "-interface", tun_iface], check=False)
    elif is_windows():
        _run([
            "netsh", "interface", "ipv4", "delete", "route",
            "0.0.0.0/0", tun_iface, gateway_ip, "store=active",
        ], check=False)


# --------------------------------------------------------------------------
# DNS (Linux only)
# --------------------------------------------------------------------------
#
# Why this exists: when the default route is redirected into the tunnel, the
# system's DNS queries also go through it. If /etc/resolv.conf points at a
# PRIVATE resolver (very common — DHCP hands out 10.x / 172.16-31.x / 192.168.x
# nameservers), the exit node can't reach that address, so every lookup hangs
# and the tunnel looks dead even though routing is fine. We sidestep that by
# pointing the resolver at a public DNS the exit node can actually reach while
# connected, and restoring the original on disconnect.
#
# On Windows the WireGuard service and our netsh calls already set DNS; on
# macOS wg-quick uses scutil. So this is scoped to Linux.

import os  # noqa: E402  (kept local to the DNS section for clarity)

_RESOLV_CONF = "/etc/resolv.conf"
_PUBLIC_NAMESERVERS = ("1.1.1.1", "1.0.0.1")


def _connected_resolv_conf(nameservers=_PUBLIC_NAMESERVERS) -> str:
    """The resolv.conf body to install while the tunnel is up.

    `options use-vc` forces glibc to resolve over TCP. UDP datagrams don't
    reliably survive the tun2socks -> SOCKS -> (proxy chain) -> node path on
    every node — but TCP does (the tunnel already carries HTTPS fine). Without
    this, name resolution can fail through an otherwise-working tunnel, which
    looks exactly like 'connected but nothing loads'. TCP DNS is slightly
    slower but correct everywhere it matters.
    """
    return (
        "".join(f"nameserver {ns}\n" for ns in nameservers)
        + "options use-vc edns0 trust-ad\n"
    )


def _dns_backup_path():
    # Imported lazily to avoid a circular import (config imports nothing from
    # us, but keeping this local makes the dependency direction obvious).
    from .. import config
    return config.CONFIG_DIR / "resolv.conf.bluecli-bak"


def set_dns(nameservers=_PUBLIC_NAMESERVERS) -> None:
    """Point /etc/resolv.conf at public nameservers while connected.

    Backs up the original first. No-op off Linux. Best-effort: if we
    can't write resolv.conf we leave DNS alone rather than abort the
    whole bring-up (the user may simply get no DNS, which is no worse
    than today). If a backup already exists, a previous session didn't
    clean up — we keep that (real) original and just rewrite resolv.conf.
    """
    if not is_linux():
        return
    backup = _dns_backup_path()
    try:
        if not backup.exists():
            backup.parent.mkdir(parents=True, exist_ok=True)
            if os.path.islink(_RESOLV_CONF):
                backup.write_text("#SYMLINK#" + os.readlink(_RESOLV_CONF) + "\n")
            elif os.path.exists(_RESOLV_CONF):
                backup.write_text(_read_file(_RESOLV_CONF))
            else:
                backup.write_text("#NONE#\n")
        _replace_resolv_conf(_connected_resolv_conf(nameservers))
    except OSError:
        # DNS will be whatever it was; tunnel still up. Don't crash bring-up.
        pass


def restore_dns() -> None:
    """Undo set_dns: put the original /etc/resolv.conf back. Idempotent."""
    if not is_linux():
        return
    backup = _dns_backup_path()
    if not backup.exists():
        return
    try:
        saved = backup.read_text()
        if saved.startswith("#SYMLINK#"):
            target = saved[len("#SYMLINK#"):].strip()
            _remove_path(_RESOLV_CONF)
            os.symlink(target, _RESOLV_CONF)
        elif saved.startswith("#NONE#"):
            _remove_path(_RESOLV_CONF)
        else:
            _replace_resolv_conf(saved)
        backup.unlink()
    except OSError:
        # Leave resolv.conf pointing at the public resolver; it still works
        # without the tunnel (1.1.1.1 is reachable normally), so this is a
        # benign fallback rather than a broken-DNS state.
        pass


def _read_file(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _remove_path(path: str) -> None:
    if os.path.islink(path) or os.path.exists(path):
        os.remove(path)


def _replace_resolv_conf(contents: str) -> None:
    """Replace /etc/resolv.conf atomically-ish: drop any symlink, write a
    plain file. (Writing through a systemd-resolved symlink would edit the
    stub file, which gets regenerated; replacing the symlink is what we want.)"""
    _remove_path(_RESOLV_CONF)
    with open(_RESOLV_CONF, "w", encoding="utf-8") as f:
        f.write(contents)


