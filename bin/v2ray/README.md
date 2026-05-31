# V2Ray binaries

Put platform-specific binaries here. BlueCLI needs:

- `v2ray` / `v2ray.exe` — the proxy
  - **Recommended: v2fly v5.x** from https://github.com/v2fly/v2ray-core/releases
  - v4.x (e.g. 4.31.0) also works — BlueCLI detects the major version at startup
    and uses the appropriate CLI syntax (`-c <path>` for v4, `run -c <path>` for v5).

- `tun2socks` / `tun2socks.exe` — makes V2Ray full-tunnel
  - https://github.com/xjasonlyu/tun2socks/releases

- `wintun.dll` — **Windows only**, the kernel-mode TUN driver
  - https://www.wintun.net/  (extract `bin/amd64/wintun.dll` and put it here)

On Windows, all three (`v2ray.exe`, `tun2socks.exe`, `wintun.dll`) go in this folder.
On Linux/macOS only `v2ray` and `tun2socks` are needed.

**Note**: do NOT keep a stray `config.json` in this folder if you're using v2ray v4.
v4 falls back to reading it as the default config when CLI args don't parse cleanly.
BlueCLI generates its own config under `data/v2ray.json` and points v2ray at it.
