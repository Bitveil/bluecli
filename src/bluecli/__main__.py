"""Entry point — both `python -m bluecli` and the installed `bluecli` script land here."""

from __future__ import annotations

import atexit
import os
import sys

# Suppress gRPC's C++ INFO/DEBUG logs (lines like
# "I0527 ... ssl_transport_security.cc:..."). They surface every TLS retry
# during transient outages and overwhelm the CLI output. Must be set BEFORE
# the grpc library is loaded, hence before any other import below.
os.environ.setdefault("GRPC_VERBOSITY", "ERROR")


def _emergency_cleanup() -> None:
    """Best-effort tunnel teardown on abrupt exit (window close, Ctrl+C).

    On abrupt exits the user loses connectivity if we don't undo the
    split-default routes and kill the helper processes — so we do that.

    What we DO NOT do: wipe the chain-session state. The cached handshake
    credentials must survive the process exit so the next launch can
    reconnect to the same session without a (forbidden) re-handshake.
    We only strip the runtime-only keys, mirroring menus.disconnect().
    """
    try:
        from . import config as cfg
        state = cfg.load_state()
        if not state.get("backend"):
            return  # nothing to tear down
        if state["backend"] in ("v2ray", "v2ray-multihop"):
            from .vpn import v2ray
            v2ray.disconnect(state)
        elif state["backend"] == "wireguard":
            from .vpn import wireguard
            wireguard.disconnect(state)
        cfg.strip_runtime_state()
    except Exception:
        pass


def main() -> int:
    atexit.register(_emergency_cleanup)
    from .app import run

    try:
        return run()
    except KeyboardInterrupt:
        print()
        return 130


if __name__ == "__main__":
    sys.exit(main())
