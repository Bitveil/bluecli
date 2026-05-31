"""Durable memory of the multihop chains the user has established.

A multihop chain is purely a client-side construct: two independent Sentinel
sessions wired together (entry -> exit). The pairing is recorded nowhere on
chain, so the *only* place it exists is here. Without it, the moment the live
tunnel state is replaced — a disconnect, or connecting to another node — the
sessions menu can no longer tell the two hops belong together, and they show
up as unrelated single sessions.

So we remember each chain — the full pair of hop dicts, same shape as
state['hops'], credentials included — for as long as BOTH hop sessions stay
active. Keeping the creds means a remembered chain can also be resumed from
cache without re-paying, exactly like the live chain. The list is pruned to
active-only every time the sessions menu loads, so it never grows without
bound and never resurrects a chain whose sessions are gone.

Everything is best-effort: a missing or corrupt file just means "no remembered
chains", never a crash on any path. The file carries session credentials, so
it is written owner-only (0600) on POSIX, like state.json.
"""

from __future__ import annotations

import json
import time
from typing import Any

from . import config

_CACHE_FILE = config.CONFIG_DIR / "multihop_cache.json"


def hop_session_ids(hops: Any) -> list:
    """The two session ids of a hop-pair, or [] when it isn't a well-formed
    two-hop chain with integer session ids."""
    if not isinstance(hops, list) or len(hops) != 2:
        return []
    ids = [h.get("session_id") for h in hops if isinstance(h, dict)]
    if len(ids) == 2 and all(isinstance(i, int) for i in ids):
        return ids
    return []


def _load() -> list:
    try:
        with _CACHE_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    return data if isinstance(data, list) else []


def _save(chains: list) -> None:
    try:
        config._atomic_write_json(_CACHE_FILE, chains, mode=0o600)
    except OSError:
        pass  # best-effort; never break a connect/list over the cache


def remember(hops: list) -> None:
    """Record (or refresh) the chain made of `hops` (entry, exit), keyed by its
    unordered session-id pair so re-establishing the same chain never
    duplicates it. No-op for a malformed hop-pair."""
    ids = hop_session_ids(hops)
    if not ids:
        return
    key = set(ids)
    chains = [
        c for c in _load() if set(hop_session_ids(c.get("hops"))) != key
    ]
    chains.append({"hops": list(hops), "ts": int(time.time())})
    _save(chains)


def all_chains() -> list:
    """Every remembered chain's hop-pair (each a list [entry_hop, exit_hop]),
    newest first. Malformed entries are skipped."""
    out: list = []
    for c in sorted(_load(), key=lambda c: c.get("ts", 0) if isinstance(c, dict) else 0,
                    reverse=True):
        hops = c.get("hops") if isinstance(c, dict) else None
        if hop_session_ids(hops):
            out.append(list(hops))
    return out


def prune_to(active_ids) -> None:
    """Drop any remembered chain that doesn't have BOTH of its hop sessions in
    `active_ids` — i.e. a hop ended or expired. Keeps the file bounded and
    stops a stale pairing from grouping unrelated sessions."""
    active = set(active_ids)
    chains = _load()
    kept = []
    for c in chains:
        ids = set(hop_session_ids(c.get("hops") if isinstance(c, dict) else None))
        if ids and ids <= active:
            kept.append(c)
    if len(kept) != len(chains):
        _save(kept)


def forget(session_ids) -> None:
    """Remove any chain that includes any of `session_ids` (e.g. just ended)."""
    drop = set(session_ids)
    chains = _load()
    kept = [
        c for c in chains
        if not (set(hop_session_ids(c.get("hops") if isinstance(c, dict) else None)) & drop)
    ]
    if len(kept) != len(chains):
        _save(kept)
