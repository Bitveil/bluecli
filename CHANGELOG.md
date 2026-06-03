# Changelog

All notable changes to BlueCLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-06-03

### Changed

- **Token ticker is now `P2P`** (was `DVPN`) everywhere it is shown to the
  user — node prices, balance, connection and multi-hop confirmations, and
  funding prompts — following the network's rebrand. The on-chain base
  denomination is unchanged.

### Added

- **Per-hour price in the node browser.** The node list now shows each node's
  hourly price next to its per-gigabyte price, so duration-based plans are
  visible at a glance.
- **Manual refresh in the node browser.** Press `r` to refresh the node list on
  demand. It is mutually exclusive with the automatic background refresh: if a
  refresh is already running you are told to wait, otherwise yours runs — the
  two never overlap.

### Documentation

- Supported Python versions corrected to **3.10–3.14** (the range for which all
  native dependencies publish prebuilt wheels) instead of the over-broad
  "3.10+".

## [1.0.1] - 2026-06-01

### Fixed

- Connection verification no longer reports a false "no traffic reached the
  internet through this node" when the tunnel is actually working. The route
  check previously depended entirely on reaching Cloudflare (`1.1.1.1`), which
  many networks and exit nodes block or hijack even while routing everything
  else — so a healthy node was torn down. The check now falls back to a
  hostname-based public-IP lookup: if the exit IP is confirmed by either path,
  the tunnel is correctly accepted.

## [1.0.0] - 2026-05-31

First public release.

### Added

- **WireGuard and V2Ray connections**, both as a seamless full tunnel — once
  connected, all traffic egresses through the chosen node.
- **Multi-hop**: chain two V2Ray nodes (entry → exit) from a single proxy
  process so neither endpoint sees both sides of the connection.
- **Wallet**: create or import a 24-word Sentinel/Cosmos wallet, stored
  AES-GCM-encrypted on disk and unlocked with a password.
- **On-chain sessions**: pay per gigabyte or per hour; browse, retry, and end
  sessions from the CLI.
- **Ephemeral-session reconciliation**: expired sessions drop out of the list
  automatically, and a tunnel left running on an expired session is detected
  and torn down so normal connectivity is restored.
- **Background node refresh**: the active-node list is fetched and kept fresh
  in the background for instant browsing.
- **Resilient chain access**: the chain gRPC endpoint is reached outside the
  tunnel, so connecting, disconnecting, or switching nodes never strands the
  client from the chain.
- **Install-free, self-contained packaging** for Linux x86-64 and Windows x64:
  bundled WireGuard, V2Ray, and tun2socks binaries; the only system
  requirement is Python 3.10+. No system install, services, or residue.
- **Startup splash and persistent banner** for a bit of polish.

[1.0.1]: https://github.com/YOUR-ORG/bluecli/releases/tag/v1.0.1
[1.0.0]: https://github.com/YOUR-ORG/bluecli/releases/tag/v1.0.0
