# Changelog

All notable changes to BlueCLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.0]: https://github.com/YOUR-ORG/bluecli/releases/tag/v1.0.0
