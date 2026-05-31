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
```
Run `bluecli.bat` as Administrator (it auto-elevates).

## Linux x86-64
```
bin/wireguard/wg                  — wireguard-tools v1.0.20210914 (static glibc)
bin/wireguard/wg-quick            — upstream bash script
bin/v2ray/v2ray                   — v2fly v5.x
bin/v2ray/tun2socks               — xjasonlyu/tun2socks
```
All four executables must have the `+x` bit set. Run `./bluecli.sh` (it
auto-elevates via sudo).

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
