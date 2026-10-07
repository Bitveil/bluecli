# Changelog

All notable changes to BlueCLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-10-06

### Added

- **Xray support.** Connect to Xray nodes with every combination they offer:
  VLESS (incl. XTLS-Vision), VMess, Trojan and Shadowsocks-2022 over TCP,
  WebSocket, gRPC, HTTPUpgrade or XHTTP, secured with TLS or Reality. BlueCLI
  picks the best endpoint the node advertises (Reality, then TLS, then plain)
  and verifies TLS by pinning the node's certificate.
- **Hysteria2 support.** Connect to Hysteria2 (QUIC) nodes, including those
  using Salamander obfuscation, with the node's certificate pinned.
- Both run fully bundled on Linux and Windows (official Xray-core v26.9.30
  and Hysteria v2.13.0 binaries) and work like the other protocols:
  sessions, reconnect after restart, clean teardown and emergency cleanup.

### Changed

- The default chain gRPC endpoint is now `grpc-sentinel.busurnode.com:443` (TLS).
  Installs that never changed the endpoint pick it up automatically; a
  custom endpoint set in the settings menu is kept.

### Fixed

- Starting or ending a session while a previous transaction from the same
  wallet was still pending on the chain crashed with a raw gRPC traceback
  ("account sequence mismatch"). It now shows a clear message: nothing was
  charged, wait a minute and try again.
- **TLS gRPC endpoints (e.g. `:443`) could not be used.** The settings menu
  only stored host and port, so every endpoint was dialled in plaintext and
  TLS endpoints such as `sentinel-grpc.publicnode.com:443` were reported as
  unreachable. Changing the endpoint now tests it — TLS first on port 443,
  plaintext first elsewhere — and stores the mode that answers; an endpoint
  that answers in neither mode is not saved. Pasted URLs (`https://…:443/`)
  are accepted, and switching only the TLS mode now reconnects correctly.
- The pending-transaction message now shows the sequence numbers the node
  reported and suggests switching endpoint if it persists.
- `packaging/build_windows.bat` did not copy the AmneziaWG client into the
  archive it builds (the CI build was unaffected).

### Internal

- The SOCKS + tun2socks full-tunnel engine is now shared by V2Ray, Xray and
  Hysteria2 (`vpn/socks_tunnel.py`), with V2Ray's behaviour unchanged.
- Native transport metadata from the node list is now read only for V2Ray
  nodes: other services number their enums differently.

## [1.3.0] - 2026-08-19

### Added

- **AmneziaWG support.** Connect to AmneziaWG nodes (DPI-resistant WireGuard)
  with the same click-and-run experience as the other protocols. On Windows
  the bundled official AmneziaWG client runs the tunnel as a service; on
  Linux the bundled `amneziawg-go` userspace engine is used together with
  the `awg` tool — no kernel module, no driver install. The node's
  obfuscation parameters (S1-S4, H1-H4, optional I1-I5) are taken from the
  handshake and validated against the protocol's ranges before use; junk
  parameters are generated per connection. Sessions, reconnect after
  restart, teardown, and emergency cleanup work exactly as for WireGuard
  and V2Ray.

### Improved

- Clearer errors on Linux when a bundled binary has lost its execute bit
  (a one-line `chmod +x` fix is suggested), and the AmneziaWG readiness
  check now reports the probe's own error instead of misattributing the
  failure to the engine.

## [1.2.0] - 2026-07-30

### Added

- **Native multihop eligibility (dvpnx 9.0.0+).** Nodes running dvpnx 9.0.0
  or newer declare their V2Ray transports on their public info endpoint;
  BlueCLI now reads that declaration during the regular node-list probe —
  before and without any paid handshake — so those nodes qualify for
  multihop chaining out of the box. The handshake-learned transport cache
  remains solely as a fallback for nodes still on older versions (their
  transports are only revealed by connecting once), and is confined to a
  single, documented seam so it can be removed once the network has fully
  migrated.

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
