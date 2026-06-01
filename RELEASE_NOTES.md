# BlueCLI v1.0.1

A minimal, self-contained command-line client for the [Sentinel](https://sentinel.co) decentralised VPN network: create or import a wallet, browse dVPN nodes, and route your traffic through **WireGuard** or **V2Ray** as a full tunnel — with multi-hop and on-chain session management.

## Fixed in this release

- **Connection no longer fails with a false “no traffic reached the internet.”** The post-connect check used to depend entirely on reaching Cloudflare (`1.1.1.1`), which many networks and exit nodes block even while routing everything else — so a perfectly good node was torn down. The check now confirms the exit IP through a hostname-based fallback too, and accepts the tunnel if either path sees traffic.

## Highlights

- WireGuard and V2Ray connections, both full-tunnel
- Multi-hop V2Ray chaining (entry → exit)
- Wallet create/import (AES-GCM encrypted) with pay-per-gigabyte or per-hour sessions
- Session browsing, retry, and teardown; automatic cleanup of expired sessions
- Self-contained: bundled WireGuard / V2Ray / tun2socks — the only system requirement is **Python 3.10+**
- No installation, no services, no telemetry; everything lives in the unpacked folder

## Download

| Platform | File |
|---|---|
| Linux x86-64 | `bluecli-1.0.1-linux-x64.tar.gz` |
| Windows x64 | `bluecli-1.0.1-windows-x64.zip` |

## Install

**Linux**
```bash
tar xzf bluecli-1.0.1-linux-x64.tar.gz
cd bluecli-linux-x64
./bluecli.sh
```

**Windows** — unzip and double-click `bluecli.bat`.

The first launch builds a local Python virtual environment inside the folder (~30 seconds, once). See the [README](README.md) for the full guide.

## Verify your download

Each archive ships with a matching `.sha256` sidecar; verify before running:

```bash
sha256sum -c bluecli-1.0.1-linux-x64.tar.gz.sha256
```

## Notes

- Requires **Python 3.10+** on `PATH` and administrator/root (the launcher elevates for you).
- **Back up your 24-word mnemonic.** It is the only way to recover your wallet.
- Supported platforms: Linux x86-64 and Windows x64.

Full history in the [CHANGELOG](CHANGELOG.md).
