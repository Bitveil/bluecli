"""Configuration and persistent state.

BlueCLI is fully self-contained: everything lives inside the unzipped
project folder. There's no `~/.bluecli/`, no registry change, no system
service. Removing the folder removes the software in its entirety.

Layout at runtime:
  bluecli/
  ├── bin/{wireguard,v2ray}/    bundled binaries (prepopulated)
  ├── data/                      created on first launch, holds:
  │   ├── wallet.enc             encrypted wallet
  │   ├── config.json            network/preferences
  │   ├── state.json             current connection (only while connected)
  │   ├── wg-blue.conf           active WireGuard config (only while connected)
  │   └── v2ray.json             active V2Ray config (only while connected)
  └── venv/                      created on first launch by the start script

The project root is discovered from the BLUECLI_HOME env var (set by the
launch scripts) and falls back to walking up from this file — that fallback
covers the case where someone runs `python -m bluecli` directly from a
checkout, e.g. during development.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Optional


def _resolve_project_dir() -> Path:
    env = os.environ.get("BLUECLI_HOME")
    if env:
        return Path(env).resolve()
    # src/bluecli/config.py → src/bluecli → src → project root
    return Path(__file__).resolve().parent.parent.parent


PROJECT_DIR = _resolve_project_dir()
CONFIG_DIR = PROJECT_DIR / "data"
BIN_DIR = PROJECT_DIR / "bin"

WALLET_FILE = CONFIG_DIR / "wallet.enc"
CONFIG_FILE = CONFIG_DIR / "config.json"
STATE_FILE = CONFIG_DIR / "state.json"
WG_CONF_FILE = CONFIG_DIR / "wg-blue.conf"
V2RAY_CONF_FILE = CONFIG_DIR / "v2ray.json"


def bin_path(tool: str, name: str) -> Path:
    """Resolve the absolute path to a bundled binary.

    `tool` is the subfolder (e.g. "wireguard", "v2ray"); `name` is the
    basename without extension. On Windows we append `.exe`.
    """
    suffix = ".exe" if sys.platform == "win32" else ""
    return BIN_DIR / tool / f"{name}{suffix}"


# Hard-coded chain defaults. The user can change the gRPC endpoint via the
# settings menu; everything else is fixed by the Sentinel chain itself.
DEFAULT_CONFIG: dict[str, Any] = {
    "grpc_host": "grpc.sentinel.co",
    "grpc_port": 9090,
    "grpc_ssl": False,
    "chain_id": "sentinelhub-2",
    "denom": "udvpn",
    "language": "en",
}

# WireGuard interface name we always use. Predictable name = predictable cleanup.
WG_INTERFACE = "wg-blue"


def ensure_dir() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def _atomic_write_json(path: Path, data: Any, *, mode: Optional[int] = None) -> None:
    """Write JSON via a temp file + atomic replace, so a crash mid-write can
    never leave a half-written (and thus unreadable) file behind. This
    matters most for state.json: a corrupt state means lost handshake
    credentials, and the node won't re-issue them for an already-paid
    session. `mode` (POSIX) restricts the final file's permissions.
    """
    ensure_dir()
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    if mode is not None:
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass  # best-effort; Windows ignores POSIX modes anyway
    tmp.replace(path)


def load_config() -> dict[str, Any]:
    ensure_dir()
    if not CONFIG_FILE.is_file():
        return dict(DEFAULT_CONFIG)
    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return dict(DEFAULT_CONFIG)
    merged = dict(DEFAULT_CONFIG)
    merged.update(cfg)
    return merged


def save_config(cfg: dict[str, Any]) -> None:
    _atomic_write_json(CONFIG_FILE, cfg)


def load_state() -> dict[str, Any]:
    if not STATE_FILE.is_file():
        return {}
    try:
        with STATE_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def save_state(state: dict[str, Any]) -> None:
    # 0600: state.json carries the per-session WireGuard private key and the
    # cached node handshake credentials in cleartext — keep it owner-only on
    # shared POSIX hosts (no-op on Windows).
    _atomic_write_json(STATE_FILE, state, mode=0o600)


def clear_state() -> None:
    if STATE_FILE.is_file():
        STATE_FILE.unlink()


# Keys in state.json that describe the LIVE tunnel (processes, interface
# names, routing artifacts). Removed on a normal disconnect; the rest of
# state — session_id, node info, cached handshake credentials — survives
# so a later reconnect can skip the chain-side handshake (the node won't
# accept a second one for the same session).
_RUNTIME_STATE_KEYS = (
    "backend", "interface", "config_path",
    "pid", "tun2socks_pid", "socks_port",
    "tun_iface", "node_ip", "orig_gw",
)


def strip_runtime_state() -> None:
    """Remove only the tunnel-runtime keys from state.json, preserving the
    session/credential keys. Used by disconnect (menu) and by the atexit
    hook on abrupt program exit."""
    state = load_state()
    if not state:
        return
    for k in _RUNTIME_STATE_KEYS:
        state.pop(k, None)
    save_state(state)


def active_session_ids(state: dict[str, Any]) -> list[int]:
    """Every session id the current tunnel depends on.

    Single-hop has exactly one (`session_id`); a multihop chain has one per
    hop (in `hops`, entry first). Ending ANY of them breaks the tunnel, so
    teardown logic uses this to tear the whole thing down if a match is
    ended — single- and multi-hop go through the same code path."""
    hops = state.get("hops")
    if isinstance(hops, list) and hops:
        return [
            h["session_id"] for h in hops
            if isinstance(h, dict) and isinstance(h.get("session_id"), int)
        ]
    sid = state.get("session_id")
    return [sid] if isinstance(sid, int) else []
