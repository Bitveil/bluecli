"""Local cache of each V2Ray node's offered transports — LEGACY FALLBACK.

Nodes on dvpnx >= 9.0.0 declare their v2ray transports on the public info
endpoint, which BlueCLI reads for free during the regular node probe — that
declaration is the primary eligibility source for multihop (see
menus._multihop_eligible). This cache covers the nodes that predate it
(dvpnx <= 8.3.1), whose transport is only revealed by a paid handshake: every
time BlueCLI handshakes a V2Ray node we record the transports it offered, so
legacy nodes the user has touched become multihop candidates too.

Once the network has fully migrated to declaring nodes, delete this module
and its record()/eligible_addresses() call sites — nothing else gates on it.

Everything here is best-effort: a missing or unreadable cache simply means
"no known legacy candidates", never a crash on the connect path.
"""

from __future__ import annotations

import json
import time

from . import config

_CACHE_FILE = config.CONFIG_DIR / "transport_cache.json"


def _load() -> dict:
    try:
        with _CACHE_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def record(node_address: str, transports) -> None:
    """Remember the transports `node_address` offers. Last-write-wins, so a
    node that changed its config is corrected next time we handshake it."""
    normalized = sorted({str(t).lower() for t in transports if t})
    if not node_address or not normalized:
        return
    data = _load()
    data[node_address] = {"transports": normalized, "ts": int(time.time())}
    try:
        config._atomic_write_json(_CACHE_FILE, data)
    except OSError:
        pass  # cache is an optimisation; never break a connect over it


def eligible_addresses(required: str = "tcp") -> set:
    """Set of node addresses known to offer `required` transport — i.e. the
    multihop-eligible candidates we've learned about so far."""
    data = _load()
    return {
        addr
        for addr, entry in data.items()
        if isinstance(entry, dict) and required in (entry.get("transports") or [])
    }
