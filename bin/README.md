# Bundled binaries

BlueCLI uses ONLY binaries from this folder. Bundled files for every
supported OS live side-by-side; the launcher picks the right one
automatically.

## Windows
```
bin/wireguard/wireguard.exe       — WireGuard for Windows
bin/v2ray/v2ray.exe               — v2fly v5.x
bin/v2ray/tun2socks.exe           — xjasonlyu/tun2socks
bin/v2ray/wintun.dll              — WinTUN driver
bin/amneziawg/amneziawg.exe       — AmneziaWG Windows client (service-based)
```
Run `bluecli.bat` as Administrator (it auto-elevates).

## Linux x86-64
```
bin/wireguard/wg                  — wireguard-tools v1.0.20210914 (static glibc)
bin/wireguard/wg-quick            — upstream bash script
bin/v2ray/v2ray                   — v2fly v5.x
bin/v2ray/tun2socks               — xjasonlyu/tun2socks
bin/amneziawg/amneziawg-go        — AmneziaWG userspace engine
bin/amneziawg/awg                 — amneziawg-tools CLI (setconf)
```
All executables must have the `+x` bit set. Run `./bluecli.sh` (it
auto-elevates via sudo).

## AmneziaWG binaries (both OSes)
BlueCLI connects to AmneziaWG nodes with two different, per-OS launch
techniques (both fully bundled — no kernel module, no driver install):

**Windows — `amneziawg.exe`, the official AmneziaWG Windows client** (a
fork of the WireGuard for Windows client, so `wintun` is embedded):
- https://github.com/amnezia-vpn/amneziawg-windows-client/releases
- Place `amneziawg.exe` as `bin/amneziawg/amneziawg.exe`.
- BlueCLI calls it like the WG client: `/installtunnelservice <conf>` on
  connect, `/uninstalltunnelservice awg-blue` on disconnect.

**Linux — userspace engine `amneziawg-go` + CLI tool `awg`**:
1. `amneziawg-go` — the engine (fork of wireguard-go). It has NO official
   releases; build from source (Go >= 1.22 required):
   ```
   git clone https://github.com/amnezia-vpn/amneziawg-go
   cd amneziawg-go
   make                                   # → amneziawg-go
   ```
2. `awg` — the CLI tool, from the `amneziawg-tools` release assets:
   https://github.com/amnezia-vpn/amneziawg-tools/releases
   (latest: v3.1.20260812, asset `ubuntu-22.04-amneziawg-tools.zip`)
   — `awg` auto-detects the userspace engine over its UAPI socket
   (/var/run/amneziawg/<iface>.sock), so no kernel module is needed.

Place them as:
```
bin/amneziawg/amneziawg-go        (Linux)
bin/amneziawg/awg                 (Linux)
```

If wg-quick can't find `resolvconf` on your system, BlueCLI silently omits
the DNS line from the WireGuard config — the tunnel still works, but DNS
lookups go to your normal resolver (not over the tunnel). To eliminate
this leak, install resolvconf: `sudo apt install resolvconf` on Debian/
Ubuntu, or it's part of systemd on most modern distros.

## Linux ARM64 / macOS
The same layout. The user has to drop in v2ray + tun2socks for their arch
from the upstream releases:
- v2ray: https://github.com/v2fly/v2ray-core/releases
- tun2socks: https://github.com/xjasonlyu/tun2socks/releases

For AmneziaWG on other arches, build `amneziawg-go` for the target
(`GOOS=... GOARCH=... go build`) and grab the matching `awg` asset from
amneziawg-tools (e.g. `alpine-3.19-amneziawg-tools.zip` for aarch64/ARM).

For WireGuard on macOS or Linux ARM64, install `wireguard-tools` via the
system package manager (it's a tiny package, and our copy is x86-64
specific):
- macOS: `brew install wireguard-tools`
- Debian arm64: `sudo apt install wireguard-tools`

Then either delete `bin/wireguard/wg` and `bin/wireguard/wg-quick` (so
BlueCLI falls back to `$PATH`) or replace them with the arch-correct
binaries.

## Shared assets
```
bin/v2ray/geoip.dat               — used by v2ray at runtime
bin/v2ray/geosite.dat             — used by v2ray at runtime
```
