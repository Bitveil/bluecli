# BlueCLI v1.4.0

A minimal, self-contained command-line client for the [Sentinel](https://sentinel.co) decentralised VPN network: create or import a wallet, browse active dVPN nodes, and route your traffic through **WireGuard**, **AmneziaWG**, **V2Ray**, **Xray**, or **Hysteria2** — all as a seamless full tunnel, with multi-hop and on-chain session management.

## What's new in this release

- **Xray support.** Connect to Xray nodes with all the combinations they offer — VLESS (incl. XTLS-Vision), VMess, Trojan and Shadowsocks-2022, over TCP, WebSocket, gRPC, HTTPUpgrade or XHTTP, secured with TLS or Reality. BlueCLI automatically picks the strongest endpoint the node offers.
- **Hysteria2 support.** Connect to Hysteria2 (QUIC) nodes, including those using Salamander obfuscation.
- Both are fully bundled on Linux and Windows and behave like every other protocol: pay, connect, reconnect after a restart, disconnect cleanly.
- **TLS gRPC endpoints work.** Any Sentinel gRPC endpoint can now be set in Settings, including TLS ones on port 443 (e.g. publicnode): BlueCLI tests it and picks TLS or plaintext automatically.
- **No more crash on a pending transaction.** If your wallet still has a previous transaction pending on the chain, BlueCLI now tells you so (nothing is charged) instead of crashing.

## Highlights

- WireGuard, AmneziaWG, V2Ray, Xray, and Hysteria2 connections, all full-tunnel
- Multi-hop V2Ray chaining (entry → exit)
- Wallet create/import (AES-GCM encrypted) with pay-per-gigabyte or per-hour sessions
- Session browsing, retry, and teardown; automatic cleanup of expired sessions
- Self-contained: bundled WireGuard / AmneziaWG / V2Ray / Xray / Hysteria2 / tun2socks — the only system requirement is **Python 3.10–3.14**
- No installation, no services, no telemetry; everything lives in the unpacked folder

## Download

| Platform | File |
|---|---|
| Linux x86-64 | `bluecli-1.4.0-linux-x64.tar.gz` |
| Windows x64 | `bluecli-1.4.0-windows-x64.zip` |

## Install

**Linux**
```bash
tar xzf bluecli-1.4.0-linux-x64.tar.gz
cd bluecli-linux-x64
./bluecli.sh
```

**Windows** — unzip and double-click `bluecli.bat`.

The first launch builds a local Python virtual environment inside the folder (~30 seconds, once). See the [README](README.md) for the full guide.

## Verify your download

Each archive ships with a matching `.sha256` sidecar; verify before running:

```bash
sha256sum -c bluecli-1.4.0-linux-x64.tar.gz.sha256
```

## Notes

- Requires **Python 3.10–3.14** on `PATH` and administrator/root (the launcher elevates for you).
- **Back up your 24-word mnemonic.** It is the only way to recover your wallet.
- Supported platforms: Linux x86-64 and Windows x64.

Full history in the [CHANGELOG](CHANGELOG.md).
