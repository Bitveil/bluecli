"""Local cache of each V2Ray node's offered transports.

Why this exists: multihop chaining needs both nodes to offer a TCP endpoint
(the conservative compatibility requirement), but a node's transport is only
revealed by a paid handshake — it's absent from both the chain node list and
the node's public status endpoint. So we record what we learn for free: every
time BlueCLI handshakes a V2Ray node (single- or multi-hop), we cache the set
of transports that node offered. Over normal use the cache fills with the
nodes the user actually touches, and multihop can then offer them as
entry/exit candidates without a fresh paid probe.

Source-of-truth ordering: this cache is the *fallback*. When the community
API lands it becomes the primary source and this stays as the offline
fallback. Both will expose the same `eligible_addresses()` shape, so the menu
layer never has to know which one answered.

Everything here is best-effort: a missing or unreadable cache simply means
"no known candidates", never a crash on the connect path.
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
