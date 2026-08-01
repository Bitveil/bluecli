# BlueCLI v1.2.0

A minimal, self-contained command-line client for the [Sentinel](https://sentinel.co) decentralised VPN network: create or import a wallet, browse dVPN nodes, and route your traffic through **WireGuard** or **V2Ray** as a full tunnel — with multi-hop and on-chain session management.

## What's new in this release

- **Native multihop eligibility on dvpnx 9.0.0+ nodes.** Nodes on the new node software declare their V2Ray transports publicly, and BlueCLI now picks that up automatically while refreshing the node list — before any paid handshake. Result: up-to-date nodes are multihop candidates immediately, even if you've never connected to them.
- **Older nodes keep working.** For nodes still on pre-9.0.0 software, eligibility works exactly as before: connect to them once and BlueCLI learns what they offer. The two sources combine, so the candidate pool only ever grows.

## Highlights

- WireGuard and V2Ray connections, both full-tunnel
- Multi-hop V2Ray chaining (entry → exit)
- Wallet create/import (AES-GCM encrypted) with pay-per-gigabyte or per-hour sessions
- Session browsing, retry, and teardown; automatic cleanup of expired sessions
- Self-contained: bundled WireGuard / V2Ray / tun2socks — the only system requirement is **Python 3.10–3.14**
- No installation, no services, no telemetry; everything lives in the unpacked folder

## Download

| Platform | File |
|---|---|
| Linux x86-64 | `bluecli-1.2.0-linux-x64.tar.gz` |
| Windows x64 | `bluecli-1.2.0-windows-x64.zip` |

## Install

**Linux**
```bash
tar xzf bluecli-1.2.0-linux-x64.tar.gz
cd bluecli-linux-x64
./bluecli.sh
```

**Windows** — unzip and double-click `bluecli.bat`.

The first launch builds a local Python virtual environment inside the folder (~30 seconds, once). See the [README](README.md) for the full guide.

## Verify your download

Each archive ships with a matching `.sha256` sidecar; verify before running:

```bash
sha256sum -c bluecli-1.2.0-linux-x64.tar.gz.sha256
```

## Notes

- Requires **Python 3.10–3.14** on `PATH` and administrator/root (the launcher elevates for you).
- **Back up your 24-word mnemonic.** It is the only way to recover your wallet.
- Supported platforms: Linux x86-64 and Windows x64.

Full history in the [CHANGELOG](CHANGELOG.md).
