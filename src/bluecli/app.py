"""Main application loop.

Lifecycle:
  1. Load language; ensure config dir exists.
  2. If no wallet, run the wallet setup menu.
  3. Otherwise, prompt for password to unlock.
  4. Loop on the main menu until exit.
"""

from __future__ import annotations

from typing import Optional

from . import __version__, config as cfg, menus, node_cache, ui, wallet
from .chain import ChainClient
from .i18n import set_language, t


def run() -> int:
    cfg.ensure_dir()
    set_language(cfg.load_config().get("language", "en"))

    ui.intro()
    ui.header(t("app.title") + f" v{__version__}")
    ui.info(ui.dim(t("app.tagline")))

    # Outer loop so that deleting the wallet from the wallet menu sends us
    # back to setup rather than out of the program.
    while True:
        unlocked = _unlock_or_setup()
        if unlocked is None:
            ui.info(t("app.bye"))
            return 0

        outcome = _session_loop(unlocked)
        if outcome == "exit":
            return 0
        # outcome == "wallet_deleted" → next iteration of the outer loop
        # prompts setup again.


def _session_loop(unlocked: wallet.Wallet) -> str:
    """Inner loop. Returns 'exit' to quit, 'wallet_deleted' to restart."""
    client: Optional[ChainClient] = None
    try:
        client = ChainClient(address=unlocked.address)
    except Exception as e:
        # Connection issues here are non-fatal; we still let the user manage
        # their wallet and tweak settings. Chain-dependent menus will retry.
        ui.error(t("common.error", str(e)))

    # Kick off the background node-list refresh so it's ready (or close to
    # it) by the time the user picks "Browse nodes".
    cache: Optional[node_cache.NodeCache] = None
    if client is not None:
        cache = node_cache.NodeCache(fetch=client.list_active_nodes)
        cache.start()

    try:
        while True:
            _print_main_menu(unlocked, client)
            choice = ui.prompt("> ")
            if choice == "1":
                client, cache = _ensure_client_cache(unlocked, client, cache)
                if client is not None:
                    menus.browse_nodes(unlocked, client, cache)
            elif choice.lower() == "m":
                client, cache = _ensure_client_cache(unlocked, client, cache)
                if client is not None:
                    menus.multihop_menu(unlocked, client, cache)
            elif choice == "2":
                if client is None:
                    client = _retry_client(unlocked)
                if client is not None:
                    menus.sessions_menu(unlocked, client, cache)
            elif choice == "3":
                menus.wallet_menu(unlocked, client)
                if not wallet.exists():
                    return "wallet_deleted"
            elif choice == "4":
                if menus.settings_menu():
                    # The gRPC endpoint changed: rebuild the client against it.
                    # Keep the node cache — the active-node list is chain state,
                    # identical on any endpoint for this chain — and just point
                    # its background refresh at the new client. No refetch.
                    client = _retry_client(unlocked)
                    if client is not None and cache is not None:
                        cache.set_fetch(client.list_active_nodes)
            elif choice == "5":
                menus.disconnect(unlocked, client)
                ui.info(t("app.bye"))
                return "exit"
            elif choice.lower() == "d":
                menus.disconnect(unlocked, client)
            elif choice == "":
                # A bare Enter just redraws the menu. Exiting on Enter is too
                # easy to trigger by accident — leaving requires typing "5".
                continue
            else:
                ui.error(t("common.invalid_choice"))
    finally:
        if cache is not None:
            cache.stop()


# --------------------------------------------------------------------------
# Internals
# --------------------------------------------------------------------------


def _unlock_or_setup() -> Optional[wallet.Wallet]:
    if not wallet.exists():
        return menus.wallet_setup_menu()
    wrong = False
    for _ in range(3):
        ui.header(t("app.title") + f" v{__version__}")
        if wrong:
            ui.error(t("wallet.error.wrong_password"))
        pw = ui.password(t("wallet.prompt.password_unlock"))
        if not pw:
            return None
        try:
            return wallet.unlock(pw)
        except wallet.WrongPassword:
            wrong = True
    return None


def _print_main_menu(unlocked: wallet.Wallet, client: Optional[ChainClient]) -> None:
    state = cfg.load_state()
    ui.header(t("main.menu.title"))
    ui.info(f"{t('common.address')}: {ui.cyan(unlocked.address)}")
    if state.get("backend"):
        ui.info(ui.green(t("main.label.status_connected", menus.connected_label(state))))
        ui.info(ui.dim(t("main.label.keep_open_hint")))
    else:
        ui.info(ui.dim(t("main.label.status_disconnected")))
    ui.info("")
    ui.info("1. " + t("main.menu.browse"))
    ui.info("m. " + t("main.menu.multihop"))
    ui.info("2. " + t("main.menu.sessions"))
    ui.info("3. " + t("main.menu.wallet"))
    ui.info("4. " + t("main.menu.settings"))
    if state.get("backend"):
        ui.info("d. " + t("main.menu.disconnect"))
    ui.info("5. " + t("main.menu.exit"))


def _retry_client(unlocked: wallet.Wallet) -> Optional[ChainClient]:
    try:
        return ChainClient(address=unlocked.address)
    except Exception as e:
        ui.error(t("common.error", str(e)))
        ui.pause(t("common.press_enter"))
        return None


def _ensure_client_cache(
    unlocked: wallet.Wallet,
    client: Optional[ChainClient],
    cache: Optional[node_cache.NodeCache],
) -> tuple[Optional[ChainClient], Optional[node_cache.NodeCache]]:
    """Lazily (re)connect the chain client and start the node-cache refresher
    if they aren't up yet. Shared by the two node-listing entry points (browse
    and multihop) so the retry-and-warm-the-cache logic lives in one place.
    Returns the (possibly newly created) client and cache."""
    if client is None:
        client = _retry_client(unlocked)
        if client is not None and cache is not None:
            # Client was rebuilt (e.g. after a drop) — keep the existing cache's
            # data but refresh it from the new client going forward.
            cache.set_fetch(client.list_active_nodes)
    if client is not None and cache is None:
        cache = node_cache.NodeCache(fetch=client.list_active_nodes)
        cache.start()
    return client, cache
