"""Background-refreshed cache of active dVPN nodes.

Probing every active node on the network on every `browse_nodes` call
takes 30-60 seconds and is wasteful: the list barely changes minute to
minute. Instead we:

  1. On startup, a daemon thread runs `list_active_nodes`.
  2. The result is written to disk (`data/nodes_cache.json`) and held in
     memory.
  3. `browse_nodes` reads from memory immediately; if memory is still
     empty (first launch, refresh in flight) it waits for the in-flight
     refresh to land.
  4. The thread refreshes every REFRESH_INTERVAL seconds.

Disk cache survives restarts so a fresh launch usually has nodes ready
on the very first `browse_nodes` call, before the new refresh completes.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict
from typing import Callable, Optional

from .chain import NodeInfo
from . import config as cfg

DISK_CACHE_TTL = 30 * 60   # 30 minutes
REFRESH_INTERVAL = 5 * 60  # 5 minutes between background refreshes
_CACHE_FILE = cfg.CONFIG_DIR / "nodes_cache.json"


class NodeCache:
    """Holds the active-node list and refreshes it in the background."""

    def __init__(self, fetch: Callable[[], list[NodeInfo]]) -> None:
        self._fetch = fetch
        self._lock = threading.Lock()
        # Serializes the actual fetch so a user-triggered refresh and the
        # background refresh never run at the same time — exactly one at a time.
        self._refresh_lock = threading.Lock()
        # `_done` is set whenever a refresh ATTEMPT completes — whether it
        # found nodes, found nothing, or raised. Callers waiting on .get()
        # are released either way so we never hang on an empty network or
        # a chain RPC failure.
        self._done = threading.Event()
        self._nodes: list[NodeInfo] = []
        self._last_refresh: float = 0.0
        self._last_error: Optional[str] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    # -- Public API --------------------------------------------------------

    def start(self) -> None:
        """Load the disk cache (if fresh) and start the background refresher."""
        self._load_from_disk()
        self._thread = threading.Thread(
            target=self._loop, name="bluecli-node-cache", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def set_fetch(self, fetch: Callable[[], list[NodeInfo]]) -> None:
        """Re-point the background refresher at a new fetch source WITHOUT
        discarding the cached node list. Used when the chain client is rebuilt
        (e.g. the gRPC endpoint changed in settings): the active-node list is
        chain state, identical on any endpoint for the same chain, so there's
        nothing to invalidate — we keep the warm list and just refresh from the
        new client next cycle. A plain assignment is enough: `_loop` re-reads
        `self._fetch` each cycle and the swap is atomic."""
        self._fetch = fetch

    def get(self, *, wait_timeout: float = 60.0) -> list[NodeInfo]:
        """Return the cached node list.

        Blocks up to `wait_timeout` seconds for the first refresh attempt
        to complete. After that returns whatever we have (possibly empty).
        """
        with self._lock:
            if self._nodes:
                return list(self._nodes)
        self._done.wait(timeout=wait_timeout)
        with self._lock:
            return list(self._nodes)

    def last_error(self) -> Optional[str]:
        with self._lock:
            return self._last_error

    def last_refresh(self) -> float:
        """Epoch seconds of the most recent successful refresh (live fetch or
        seeded disk cache), or 0.0 if we have no data yet. Lets the UI show
        the user how fresh the node list is — purely informational."""
        with self._lock:
            return self._last_refresh

    def refresh_now(self) -> bool:
        """Run a refresh immediately, IN THE CALLING THREAD, if one isn't
        already running. Returns True if the refresh ran (cache updated), or
        False if a refresh — background or manual — was already in flight, in
        which case the caller should tell the user to wait. The shared
        `_refresh_lock` guarantees this never overlaps the background loop:
        exactly one fetch runs at a time."""
        if not self._refresh_lock.acquire(blocking=False):
            return False  # a refresh is already in progress
        try:
            self._refresh_once()
        finally:
            self._refresh_lock.release()
        return True

    # -- Internals ---------------------------------------------------------

    def _loop(self) -> None:
        while not self._stop.is_set():
            # Hold the refresh lock for the whole fetch so a user-triggered
            # refresh can't overlap this one (and vice versa).
            with self._refresh_lock:
                self._refresh_once()
            self._stop.wait(REFRESH_INTERVAL)

    def _refresh_once(self) -> None:
        """One fetch + state update + disk save. The CALLER must hold
        `_refresh_lock` (the background loop and `refresh_now` both do), so
        only one of these runs at any moment."""
        err = None
        fresh: Optional[list[NodeInfo]] = None
        try:
            fresh = self._fetch()
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
        with self._lock:
            if fresh is not None:
                self._nodes = list(fresh)
                self._last_refresh = time.time()
            self._last_error = err
        if fresh:
            self._save_to_disk(fresh)
        # ALWAYS signal "attempt complete" — even on error or empty —
        # so callers blocked in .get() don't sit on the timeout.
        self._done.set()

    def _load_from_disk(self) -> None:
        if not _CACHE_FILE.is_file():
            return
        try:
            with _CACHE_FILE.open("r", encoding="utf-8") as f:
                blob = json.load(f)
        except (OSError, json.JSONDecodeError):
            return
        ts = blob.get("ts", 0)
        if time.time() - ts > DISK_CACHE_TTL:
            return  # too old to seed memory; let the live refresh fill us
        items = blob.get("nodes", [])
        nodes: list[NodeInfo] = []
        for item in items:
            try:
                nodes.append(NodeInfo(**item))
            except TypeError:
                continue
        with self._lock:
            self._nodes = nodes
            self._last_refresh = ts
        if nodes:
            self._done.set()

    def _save_to_disk(self, nodes: list[NodeInfo]) -> None:
        payload = {
            "ts": time.time(),
            "nodes": [asdict(n) for n in nodes],
        }
        try:
            # Reuse the shared atomic writer (temp file + replace) so the disk
            # cache can never be left half-written. The node list is public
            # data, so no special file mode is needed.
            cfg._atomic_write_json(_CACHE_FILE, payload)
        except OSError:
            # Cache-on-disk is a nice-to-have; if it fails just keep going.
            pass
