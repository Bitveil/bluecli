"""Interactive menus.

Kept deliberately flat: each function corresponds to one screen the user
sees, and returns when the user picks "back". No state machines, no event
loops — just nested function calls following the user's choices.
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Optional

from . import config as cfg, multihop_cache, node_cache, transport_cache
from . import ui, wallet
from .chain import (
    ChainClient,
    ChainError,
    NODE_TYPE_V2RAY,
    NODE_TYPE_WIREGUARD,
    NodeInfo,
    WalletNotOnChainError,
)
from .i18n import t
from .vpn import NodeHandshakeError, VpnError, v2ray, wireguard

SATOSHI = 1_000_000  # 1 P2P = 1_000_000 udvpn (base denom stays "udvpn")
TICKER = "P2P"       # display symbol for the token (was "DVPN" before the rebrand)


def _pause() -> None:
    """Short alias for the most common pause prompt."""
    ui.pause(t("common.press_enter"))


def _already_connected_guard() -> bool:
    """Return True (and warn) if there's already a live tunnel.

    Both new connections and reconnects go through this. Without it, the
    user would pay for a fresh session, then the new bring-up would step
    on the routes of the existing one and leave the system in a confused
    half-tunneled state. We ask the user to disconnect explicitly first
    — they keep their cached credentials, so reconnecting later is one
    menu step away.
    """
    state = cfg.load_state()
    if not state.get("backend"):
        return False
    ui.warn(t("connect.already_connected", connected_label(state)))
    ui.info(t("connect.disconnect_first"))
    _pause()
    return True


def connected_label(state: dict) -> str:
    """A human-readable label for the active connection.

    Single-hop composes `<moniker> (<country>) — <backend>` from the saved
    state. A multihop chain (state has `hops`) renders `entry \u2192 exit —
    v2ray-multihop`. Each component is optional and falls back gracefully:
    missing moniker degrades to the tail of the sentnode address, missing
    country drops just the parens, missing backend drops the suffix.
    Forward-compatible with state.json files from older versions.
    """
    backend = (state.get("backend") or "").strip()

    hops = state.get("hops")
    if isinstance(hops, list) and hops:
        chain = " \u2192 ".join(_hop_label(h) for h in hops)
        return f"{chain} \u2014 {backend}" if backend else chain

    head = _hop_label(state)
    return f"{head} \u2014 {backend}" if backend else head


def _hop_label(node_state: dict) -> str:
    """Short label for one node from its saved moniker/country/address."""
    moniker = (node_state.get("node_moniker") or "").strip()
    country = (node_state.get("node_country") or "").strip()
    if moniker and country:
        return f"{moniker} ({country})"
    if moniker:
        return moniker
    addr = node_state.get("node_address") or "?"
    return addr[-16:] if len(addr) > 16 else addr

# --------------------------------------------------------------------------
# Wallet menu
# --------------------------------------------------------------------------


def wallet_setup_menu() -> Optional[wallet.Wallet]:
    """Shown when no wallet exists yet. Returns the unlocked wallet or None on exit."""
    while True:
        ui.header(t("wallet.menu.title"))
        ui.info("1. " + t("wallet.menu.create"))
        ui.info("2. " + t("wallet.menu.import"))
        ui.info("3. " + t("main.menu.exit"))
        choice = ui.prompt("> ")
        if choice == "1":
            w = _do_create()
            if w:
                return w
        elif choice == "2":
            w = _do_import()
            if w:
                return w
        elif choice == "3":
            return None
        else:
            ui.error(t("common.invalid_choice"))


def wallet_menu(unlocked: wallet.Wallet, client: Optional[ChainClient]) -> None:
    """Shown to a user with an unlocked wallet — read-only utilities only."""
    while True:
        ui.header(t("wallet.menu.title"))
        ui.info(f"{t('common.address')}: {ui.cyan(unlocked.address)}")
        balance = _format_balance(client) if client else "—"
        ui.info(f"{t('common.balance')}: {balance}")
        ui.info("")
        ui.info("1. " + t("wallet.menu.show"))
        ui.info("2. " + t("wallet.menu.export"))
        ui.info("3. " + t("wallet.menu.delete"))
        ui.info("4. " + t("common.back"))
        choice = ui.prompt("> ")
        if choice == "1":
            _pause()
        elif choice == "2":
            _do_export()
        elif choice == "3":
            if _do_delete():
                return
        elif choice == "4":
            return
        else:
            ui.error(t("common.invalid_choice"))


def _do_create() -> Optional[wallet.Wallet]:
    if wallet.exists():
        ui.error(t("wallet.error.already_exists"))
        return None
    password = _prompt_new_password()
    if not password:
        return None
    w = wallet.create(password)
    ui.success(t("wallet.ok.created"))
    ui.info(f"{t('common.address')}: {ui.cyan(w.address)}")
    ui.info(f"{t('wallet.label.mnemonic')}:")
    ui.info(ui.bold(w.mnemonic))
    ui.warn(t("wallet.warn.write_mnemonic"))
    _pause()
    return w


def _do_import() -> Optional[wallet.Wallet]:
    if wallet.exists():
        ui.error(t("wallet.error.already_exists"))
        return None
    mnemonic = ui.prompt(t("wallet.prompt.mnemonic"))
    if not mnemonic:
        return None
    password = _prompt_new_password()
    if not password:
        return None
    try:
        w = wallet.import_from_mnemonic(mnemonic, password)
    except wallet.InvalidMnemonic:
        ui.error(t("wallet.error.invalid_mnemonic"))
        return None
    ui.success(t("wallet.ok.imported"))
    ui.info(f"{t('common.address')}: {ui.cyan(w.address)}")
    _pause()
    return w


def _prompt_new_password() -> Optional[str]:
    """Prompt for a new password twice and confirm they match.

    Returns the validated password, or None if the user gave an empty
    one or the two attempts didn't agree. Errors are printed before
    returning so callers can just bail with `return` on None.
    """
    pw1 = ui.password(t("wallet.prompt.password_new"))
    if not pw1:
        ui.error(t("wallet.error.password_empty"))
        return None
    pw2 = ui.password(t("wallet.prompt.password_confirm"))
    if pw1 != pw2:
        ui.error(t("wallet.error.password_mismatch"))
        return None
    return pw1


def _do_export() -> None:
    pw = ui.password(t("wallet.prompt.password_unlock"))
    try:
        w = wallet.unlock(pw)
    except wallet.WrongPassword:
        ui.error(t("wallet.error.wrong_password"))
        return
    ui.info(f"{t('wallet.label.mnemonic')}:")
    ui.info(ui.bold(w.mnemonic))
    _pause()


def _do_delete() -> bool:
    answer = ui.prompt(t("wallet.prompt.confirm_delete")).lower()
    if answer != "delete":
        ui.info(t("common.cancel"))
        return False
    wallet.delete()
    ui.success(t("wallet.ok.deleted"))
    _pause()
    return True


# --------------------------------------------------------------------------
# Node browsing & connect
# --------------------------------------------------------------------------


def _clamp_page(requested: int, total_pages: int) -> int:
    """Map a 1-indexed page request to a valid 0-indexed page, clamped into
    [0, total_pages-1]. Out-of-range jumps snap to the nearest end instead of
    erroring — friendlier for a quick 'go to page N'."""
    return min(max(requested - 1, 0), max(total_pages - 1, 0))


def browse_nodes(
    unlocked: wallet.Wallet,
    client: ChainClient,
    cache: "Optional[node_cache.NodeCache]" = None,
) -> None:
    nodes = _load_browseable_nodes(client, cache)
    if nodes is None:
        return  # already reported the error and paused

    denom = client.denom  # wallet's denom — picks which listed price we show
    per_page = 20
    filter_text = ""
    visible = nodes
    page = 0
    while True:
        total_pages = max(1, (len(visible) + per_page - 1) // per_page)
        page = min(page, total_pages - 1)
        chunk = visible[page * per_page : (page + 1) * per_page]
        ui.header(t("main.menu.browse"))
        if cache is not None:
            age_label = _node_list_age_label(cache.last_refresh(), time.time())
            if age_label:
                ui.info(ui.dim(age_label))
        if filter_text:
            ui.info(ui.dim(t("nodes.filter_active", filter_text, len(visible))))
        ui.info(t("nodes.header"))
        for i, n in enumerate(chunk, start=page * per_page + 1):
            ui.info(_format_node_row(i, n, denom))
        ui.info("")
        ui.info(t("nodes.page", page + 1, total_pages))
        choice = ui.prompt(t("nodes.prompt.choice"))
        choice_lc = choice.lower().strip()
        if choice_lc == "n":
            page = min(page + 1, total_pages - 1)
        elif choice_lc == "p":
            page = max(page - 1, 0)
        elif choice_lc in ("r", "refresh"):
            nodes = _refresh_node_list(cache, client, nodes)
            visible = _filter_nodes(nodes, filter_text) if filter_text else nodes
            page = 0
        elif choice_lc.startswith("g"):
            # `g<n>` (or bare `g` then a prompt) jumps straight to page n,
            # so long lists don't have to be paged through one at a time.
            target = choice_lc[1:].strip()
            if not target:
                target = ui.prompt(t("nodes.prompt.goto_page")).strip()
            if target.isdigit():
                page = _clamp_page(int(target), total_pages)
            else:
                ui.error(t("common.invalid_choice"))
        elif choice_lc in ("b", "back", ""):
            return
        elif choice.startswith("/"):
            # `/<text>` sets the filter; `/` alone clears it.
            filter_text = choice[1:].strip().lower()
            visible = _filter_nodes(nodes, filter_text) if filter_text else nodes
            page = 0
            if filter_text and not visible:
                ui.warn(t("nodes.filter_none", filter_text))
                # Keep the (empty) filter in place; user can type / to clear.
        elif choice_lc.isdigit():
            idx = int(choice_lc) - 1
            if 0 <= idx < len(visible):
                _connect_to(unlocked, client, visible[idx])
                return
            ui.error(t("common.invalid_choice"))
        else:
            ui.error(t("common.invalid_choice"))


def _load_browseable_nodes(
    client: ChainClient,
    cache: "Optional[node_cache.NodeCache]",
) -> Optional[list[NodeInfo]]:
    """Resolve the node list for browse_nodes, with error reporting.

    Tries cache (instant) → cache.get(wait=90s) → synchronous fetch.
    Returns None if the user should be sent back to the main menu
    (errors are already shown and a pause has been consumed). Returns
    an empty list only if there genuinely are no connectable nodes.
    """
    nodes: list = []
    if cache is not None:
        nodes = cache.get(wait_timeout=0.0)

    if not nodes:
        ui.info(t("nodes.loading"))
        if cache is not None:
            nodes = cache.get(wait_timeout=90.0)
            if not nodes:
                err = cache.last_error()
                ui.error(t("nodes.loading_failed_with_error", err) if err
                         else t("nodes.loading_empty"))
                _pause()
                return None
        else:
            # No cache provided (defensive fallback) → synchronous fetch.
            try:
                nodes = client.list_active_nodes()
            except Exception as e:
                ui.error(t("common.error", str(e)))
                _pause()
                return None
            if not nodes:
                ui.error(t("nodes.loading_empty"))
                _pause()
                return None

    browseable = _browseable(nodes)
    if not browseable:
        ui.warn(t("nodes.none"))
        _pause()
        return None
    return browseable


def _browseable(nodes: list) -> list:
    """Keep only nodes the user can actually connect to (WireGuard/V2Ray that
    advertise a remote URL), sorted by country then moniker. Shared by the
    initial load and the manual refresh so both present an identical list."""
    out = [
        n for n in nodes
        if n.node_type in (NODE_TYPE_WIREGUARD, NODE_TYPE_V2RAY) and n.remote_url
    ]
    out.sort(key=lambda n: (n.country, n.moniker))
    return out


def _refresh_node_list(
    cache: "Optional[node_cache.NodeCache]",
    client: ChainClient,
    current: list,
) -> list:
    """Handle a user-requested refresh from the browser. Mutually exclusive with
    the background refresh: if one is already running, tell the user to wait and
    keep the current list; otherwise run it now (in this thread) and return the
    fresh, browseable list. Returns `current` unchanged on a busy or failed
    refresh."""
    ui.info(t("nodes.refreshing"))
    if cache is not None:
        if not cache.refresh_now():
            ui.warn(t("nodes.refresh_in_progress"))
            _pause()
            return current
        return _browseable(cache.get(wait_timeout=0.0)) or current
    # No cache (defensive fallback): synchronous one-off fetch.
    try:
        fresh = client.list_active_nodes()
    except Exception as e:
        ui.error(t("common.error", str(e)))
        _pause()
        return current
    return _browseable(fresh) or current


def _filter_nodes(nodes: list, query: str) -> list:
    """Substring match against moniker, country, and type name.

    Cheap and case-insensitive. We deliberately don't try anything
    fancier (no fuzzy match, no field-prefix syntax) — the lists are
    small enough that a plain substring covers every realistic search.
    """
    q = query.lower()
    return [
        n for n in nodes
        if q in (n.moniker or "").lower()
        or q in (n.country or "").lower()
        or q in n.type_name.lower()
    ]


def _node_list_age_label(ts: float, now: float) -> Optional[str]:
    """Human 'node list updated N ago' line, or None when we have no
    timestamp (so we never show a misleading 'just now' for unknown data).
    Pure + injectable `now` so it's testable without the clock."""
    if not ts:
        return None
    age = max(0, int(now - ts))
    if age < 60:
        return t("nodes.updated_just_now")
    return t("nodes.updated_ago", ui.format_duration(age))


def _connect_to(unlocked: wallet.Wallet, client: ChainClient, node: NodeInfo) -> None:
    # 0) Refuse if we're already tunneling. Without this the user would
    #    pay for a new session and then watch the new bring-up clobber
    #    the routes of the existing one.
    if _already_connected_guard():
        return

    # 1) Ask the user what they want to pay for.
    qty_type = ui.prompt(t("nodes.prompt.duration_type")).lower()
    by_hours = qty_type.startswith("h")
    raw = ui.prompt(t("nodes.prompt.hours" if by_hours else "nodes.prompt.gigabytes"))
    amount = int(raw) if raw.isdigit() and int(raw) > 0 else 1

    # 2) Quote the price in udvpn from the node's own price list.
    denom = client.denom
    price = node.price_for(denom, by_hours=by_hours)
    if price is None:
        ui.error(t("connect.no_matching_price", denom))
        _pause()
        return
    try:
        cost_udvpn = int(price["quote_value"]) * amount
    except (TypeError, ValueError):
        ui.error(t("connect.bad_price"))
        _pause()
        return
    cost_dvpn = cost_udvpn / SATOSHI

    # 3) Pre-flight balance check — saves the user a doomed gas-burning tx.
    balance = client.get_balance()
    if balance is None:
        ui.error(t("connect.wallet_not_funded", unlocked.address))
        _pause()
        return
    if balance < cost_udvpn:
        ui.error(
            t("connect.insufficient_balance", f"{cost_dvpn:.6f}", f"{balance / SATOSHI:.6f}")
        )
        _pause()
        return

    # 4) Confirm with the user, showing the exact cost.
    duration = f"{amount} {'hours' if by_hours else 'GB'}"
    label = node.moniker or node.address[-10:]
    if not ui.yes_no(t("nodes.confirm", label, duration, f"{cost_dvpn:.6f}")):
        ui.info(t("common.cancel"))
        return

    # 5) Broadcast the start-session tx.
    ui.info(t("connect.starting_session"))
    try:
        session_id = client.start_session(
            unlocked.secret,
            node,
            gigabytes=0 if by_hours else amount,
            hours=amount if by_hours else 0,
        )
    except WalletNotOnChainError:
        ui.error(t("connect.wallet_not_funded", unlocked.address))
        _pause()
        return
    except ChainError as e:
        ui.error(t("connect.failed", str(e)))
        _pause()
        return
    ui.success(t("connect.session_ok", session_id))

    try:
        _bring_up_tunnel(unlocked, client, node, session_id)
    except VpnError as e:
        ui.error(t("connect.failed", str(e)))
        # The session is paid for on chain. We save the orphan id so the
        # user can retry or explicitly end it from "My active sessions".
        state = cfg.load_state()
        state["orphan_session_id"] = session_id
        cfg.save_state(state)
        ui.warn(t("connect.orphan_session", session_id))
        _pause()


def _bring_up_tunnel(
    unlocked: wallet.Wallet,
    client: ChainClient,
    node,
    session_id: int,
) -> None:
    """Bring up the local tunnel for `session_id` against `node`.

    Credential lifecycle: if state.json already has creds for THIS
    session, reuse them — the node accepts only ONE handshake per
    session (409 otherwise). Otherwise do a fresh handshake and
    persist BEFORE bring-up so a crash there doesn't burn the session.

    Raises VpnError on failure.
    """
    state = cfg.load_state()
    same_session = state.get("session_id") == session_id
    priv = wallet.derive_private_key(unlocked.mnemonic)

    # Pre-connect IP as the baseline against which to compare the
    # post-tunnel IP; without it, the verify can't distinguish "tunnel
    # is active" from "tunnel isn't routing yet, still showing home IP".
    pre_connect_ip = _fetch_public_ip(timeout=2.5)

    if node.node_type == NODE_TYPE_WIREGUARD:
        creds = _get_or_fetch_creds(
            state, same_session, node, session_id, priv,
            cls=wireguard.WGCredentials, marker_key="wg_privkey_b64",
            fetch=wireguard.fetch_creds,
        )
        ui.info(t("connect.bringing_up_wg"))
        runtime = wireguard.bring_up(creds).to_state()
    else:
        creds = _get_or_fetch_creds(
            state, same_session, node, session_id, priv,
            cls=v2ray.V2Credentials, marker_key="v2_uuid_hex",
            fetch=v2ray.fetch_creds,
        )
        # Learn this node's transports for free while we have the handshake —
        # feeds the multihop eligibility cache without a dedicated paid probe.
        transport_cache.record(node.address, v2ray.offered_transports(creds.handshake_peer_data))
        ui.info(t("connect.bringing_up_v2ray"))
        runtime = v2ray.bring_up(creds, remote_url=node.remote_url).to_state()

    # Bring-up succeeded → mark not-orphan and save the runtime fields.
    state = cfg.load_state()  # re-read: _get_or_fetch_* may have written
    state.update(runtime)
    state.pop("orphan_session_id", None)
    cfg.save_state(state)
    # Verify the tunnel carries traffic and resolves names. A failure here does
    # NOT tear the tunnel down: the check endpoints are often blocked on the
    # user's own network even when the node routes fine, so we keep the tunnel
    # up and just warn — the user tests it and decides, or disconnects.
    status = _verify_public_ip(pre_connect_ip=pre_connect_ip)
    if status == "ok":
        ui.success(t("connect.success", node.moniker or node.address[-10:]))
    else:
        _warn_after_unverified(status)
    _pause()


_PUBLIC_IP_ENDPOINTS = (
    "https://api.ipify.org/",
    "https://ifconfig.me/ip",
    "https://icanhazip.com/",
)

# IP-LITERAL endpoints (Cloudflare's trace) — fetched with no DNS lookup, so
# they confirm the tunnel routes and reveal the exit IP even when name
# resolution through the tunnel is broken. https first, http as a fallback in
# case IP-SAN TLS verification trips on some OpenSSL builds (we're only reading
# our own public IP, so plain http is acceptable here).
_TRACE_ENDPOINTS_NO_DNS = (
    "https://1.1.1.1/cdn-cgi/trace",
    "https://1.0.0.1/cdn-cgi/trace",
    "http://1.1.1.1/cdn-cgi/trace",
    "http://1.0.0.1/cdn-cgi/trace",
)


def _looks_like_ip(s: str) -> bool:
    return bool(s) and (":" in s or s.replace(".", "").isdigit())


def _fetch_public_ip(timeout: float) -> Optional[str]:
    """One pass through the hostname endpoint list. Returns the first valid IP
    or None. Needs working DNS — used only as a fallback display source."""
    for endpoint in _PUBLIC_IP_ENDPOINTS:
        try:
            with urllib.request.urlopen(endpoint, timeout=timeout) as f:
                body = f.read().decode("utf-8", errors="replace").strip()
            ip = body.splitlines()[0].strip() if body else ""
            if _looks_like_ip(ip):
                return ip
        except (urllib.error.URLError, TimeoutError, OSError):
            continue
    return None


def _dbg(msg: str) -> None:
    """Verbose verify diagnostics to stderr when BLUECLI_DEBUG is set — used to
    chase a connection failure on a hostile network. A no-op otherwise."""
    if os.environ.get("BLUECLI_DEBUG"):
        print(f"[bluecli debug] {msg}", file=sys.stderr, flush=True)


def _fetch_public_ip_bounded(timeout: float) -> Optional[str]:
    """`_fetch_public_ip` (hostname-based) hard-bounded in a daemon thread.
    getaddrinfo ignores socket timeouts and can hang on a broken resolver, so
    we never call the hostname fetch inline in the verify loop — we cap it here
    and treat an overrun as 'no IP'."""
    result: dict = {"ip": None}

    def _run() -> None:
        try:
            result["ip"] = _fetch_public_ip(timeout=timeout)
        except Exception:
            pass

    th = threading.Thread(target=_run, daemon=True)
    th.start()
    th.join(timeout + 1.0)
    return result["ip"]


def _parse_trace_ip(body: str) -> Optional[str]:
    """Pull the `ip=...` line out of a Cloudflare cdn-cgi/trace body."""
    for line in body.splitlines():
        if line.startswith("ip="):
            ip = line[3:].strip()
            if _looks_like_ip(ip):
                return ip
    return None


def _fetch_public_ip_no_dns(timeout: float) -> Optional[str]:
    """Public IP via an IP-literal endpoint — no DNS. This is what lets us
    tell 'tunnel isn't routing' apart from 'routing, but DNS is down', instead
    of hanging silently on a hostname lookup."""
    for endpoint in _TRACE_ENDPOINTS_NO_DNS:
        try:
            with urllib.request.urlopen(endpoint, timeout=timeout) as f:
                body = f.read().decode("utf-8", errors="replace")
            ip = _parse_trace_ip(body)
            if ip:
                return ip
        except (urllib.error.URLError, TimeoutError, OSError):
            continue
    return None


def _dns_resolves(host: str = "one.one.one.one", timeout: float = 4.0) -> bool:
    """Bounded test of the SYSTEM resolver (what curl/browsers use).
    getaddrinfo ignores socket timeouts and can hang on a broken resolver, so
    we run it in a daemon thread and treat a hang as failure."""
    result = {"ok": False}

    def _resolve():
        try:
            socket.getaddrinfo(host, 443)
            result["ok"] = True
        except OSError:
            pass

    th = threading.Thread(target=_resolve, daemon=True)
    th.start()
    th.join(timeout)
    return result["ok"]


def _verify_status(reachable: bool, exit_ip: Optional[str],
                   pre_connect_ip: Optional[str], dns_ok: bool) -> str:
    """Pure classification used by _verify_public_ip.
        'no_route' — tunnel isn't carrying traffic (dead/unreachable node)
        'dns'      — traffic flows but name resolution is broken
        'ok'       — traffic flows and DNS resolves
    """
    if not reachable or not exit_ip:
        return "no_route"
    if pre_connect_ip is not None and exit_ip == pre_connect_ip:
        return "no_route"
    return "ok" if dns_ok else "dns"


def _verify_public_ip(pre_connect_ip: Optional[str] = None, *, budget: float = 30.0) -> str:
    """Confirm the tunnel actually works, returning 'ok' | 'dns' | 'no_route'.

    A DNS-FREE probe runs first so a DNS problem is reported as a DNS problem
    rather than as a silent hang. That probe targets Cloudflare by IP, though,
    and plenty of networks/nodes can't reach 1.1.1.1 even while routing
    everything else (1.1.1.1 is widely blocked or hijacked). So if it comes up
    empty we fall back to a hostname lookup: a changed exit IP there proves
    routing AND DNS both work. Only when neither path sees the tunnel carry
    traffic — across the whole budget — do we call it 'no_route'.
    """
    deadline = time.time() + budget
    while time.time() < deadline:
        # 1) DNS-free probe (Cloudflare IP literal): tells routing apart from DNS.
        exit_ip = _fetch_public_ip_no_dns(timeout=4.0)
        _dbg(f"verify: dns-free probe -> {exit_ip!r} (pre={pre_connect_ip!r})")
        if exit_ip and (pre_connect_ip is None or exit_ip != pre_connect_ip):
            # Tunnel routes. Show the exit IP now, then give DNS a few seconds.
            ui.info(t("connect.public_ip", exit_ip))
            dns_deadline = min(deadline, time.time() + 8.0)
            dns_ok = False
            while time.time() < dns_deadline:
                if _dns_resolves(timeout=4.0):
                    dns_ok = True
                    break
                time.sleep(1.0)
            return _verify_status(True, exit_ip, pre_connect_ip, dns_ok)

        # 2) Cloudflare unreachable — but the node may route everything else.
        # Fetch the public IP BY HOSTNAME (bounded in a thread, so a broken
        # resolver can't hang us): a changed IP proves routing AND DNS both
        # work. We must NOT gate this on first resolving a Cloudflare name —
        # that tied the fallback back to the very thing we're working around,
        # and a slow/blocked cold resolver during tunnel warm-up was skipping
        # this path entirely, turning a working tunnel into a bogus "no route".
        exit_ip = _fetch_public_ip_bounded(timeout=4.0)
        _dbg(f"verify: hostname probe -> {exit_ip!r}")
        if exit_ip and (pre_connect_ip is None or exit_ip != pre_connect_ip):
            ui.info(t("connect.public_ip", exit_ip))
            return "ok"

        time.sleep(2.0)
    _dbg("verify: budget exhausted -> no_route")
    return "no_route"


def _warn_after_unverified(status: str) -> None:
    """The tunnel came up but our connectivity check couldn't confirm it works.
    We deliberately do NOT tear it down: the check endpoints are often blocked
    on the very network the user is on (corporate firewalls love to drop
    1.1.1.1 and friends), which says nothing about whether the node itself
    routes. So we keep the tunnel up and warn — the user can test it and decide,
    or disconnect from the menu if it really isn't working. The message differs
    between the DNS and no-route cases."""
    ui.warn(t("connect.verify_dns_unconfirmed" if status == "dns"
              else "connect.verify_unconfirmed"))


def _get_or_fetch_creds(
    state: dict, same_session: bool, node, session_id: int, priv: bytes,
    *, cls, marker_key: str, fetch,
):
    """Return cached creds when state.json already has them for THIS
    session; otherwise do a fresh handshake and persist before returning.

    `cls` is the credentials dataclass (WGCredentials or V2Credentials),
    `marker_key` is the state-json field whose presence means "we already
    have creds for this session" (e.g. "wg_privkey_b64"), and `fetch` is
    the protocol-specific handshake (wireguard.fetch_creds / v2ray.fetch_creds).
    """
    if same_session and marker_key in state and "handshake_peer_data" in state:
        ui.info(t("connect.using_cached_creds"))
        return cls.from_state(state)

    ui.info(t("connect.fetching_creds"))
    try:
        creds = fetch(
            remote_url=node.remote_url, session_id=session_id, private_key=priv,
        )
    except NodeHandshakeError as e:
        if e.status_code == 409:
            raise VpnError(t("connect.session_already_registered", session_id)) from e
        raise

    # Persist BEFORE bring-up so a crash there doesn't burn the session.
    # moniker + country are saved purely for display in the main menu
    # status line; nothing inside the bring-up / disconnect paths reads
    # them, so a missing or wrong value is cosmetic only.
    state.update({
        "session_id": session_id,
        "node_address": node.address,
        "node_type": node.node_type,
        "node_moniker": node.moniker or "",
        "node_country": node.country or "",
    })
    state.update(creds.to_state())
    # Single-hop and multihop states are mutually exclusive: committing to a
    # single-hop session drops any chain left cached from a prior multihop
    # disconnect. Without this, stale `hops` would keep winning in
    # active_session_ids() and the live single-hop tunnel wouldn't tear down
    # when its session is ended.
    state.pop("hops", None)
    cfg.save_state(state)
    return creds


# --------------------------------------------------------------------------
# Multihop (V2Ray chain: entry -> exit)
# --------------------------------------------------------------------------


def _chain_sessions_alive(hops: Any, active_ids) -> bool:
    """True iff `hops` is a well-formed two-hop chain whose BOTH session ids are
    in `active_ids`. Used to decide whether a cached chain can still be resumed
    (vs. one whose sessions have ended/expired and should be dropped)."""
    ids = set(multihop_cache.hop_session_ids(hops))
    return bool(ids) and ids <= set(active_ids)


def _multihop_eligible(n: NodeInfo, cached_tcp_addrs: set) -> bool:
    """TCP eligibility for chaining, native-first.

    Nodes on dvpnx >= 9.0.0 declare their v2ray transports on the public
    info endpoint — fetched for free by the regular node probe, before any
    handshake — so for them the declaration alone decides (it's fresher
    than anything a past handshake taught us). The handshake-learned
    transport cache is consulted ONLY for legacy nodes that don't declare
    (dvpnx <= 8.3.1). Once the network has fully migrated, delete the
    fallback branch below and transport_cache with it — nothing else
    gates on the cache.
    """
    if n.declared_transports is not None:
        return "tcp" in n.declared_transports
    return n.address in cached_tcp_addrs


def multihop_menu(
    unlocked: wallet.Wallet,
    client: ChainClient,
    cache: "Optional[node_cache.NodeCache]" = None,
) -> None:
    """Build a two-hop V2Ray chain (entry -> exit).

    A node qualifies if it's V2Ray and offers a TCP endpoint (the
    conservative chaining requirement). That's decided natively from the
    node's own declaration when it provides one (dvpnx >= 9.0.0), with the
    handshake-learned transport cache as the fallback for older nodes —
    see _multihop_eligible.
    """
    if _already_connected_guard():
        return

    # After a plain disconnect we deliberately keep the hop creds in state so a
    # chain can be resumed without re-paying. But only offer that if BOTH hop
    # sessions are still active on chain — otherwise the cached chain is dead
    # (ended or expired) and resuming would just fail, so we drop the stale
    # state instead of nagging about a session that no longer exists.
    state = cfg.load_state()
    hops = state.get("hops")
    if isinstance(hops, list) and len(hops) == 2 and not state.get("backend"):
        chain_ids = set(multihop_cache.hop_session_ids(hops))
        try:
            active = {s.id for s in client.my_active_sessions()}
            alive = _chain_sessions_alive(hops, active)
        except Exception:
            alive = None  # couldn't verify (transient) — don't discard creds
        if alive is False:
            cfg.clear_state()
            multihop_cache.forget(chain_ids)
        elif ui.yes_no(t("multihop.resume_prompt", connected_label(state))):
            _resume_multihop(state)
            return

    nodes = _load_browseable_nodes(client, cache)
    if nodes is None:
        return
    cached_tcp = transport_cache.eligible_addresses("tcp")
    eligible = [
        n for n in nodes
        if n.node_type == NODE_TYPE_V2RAY and _multihop_eligible(n, cached_tcp)
    ]
    if len(eligible) < 2:
        ui.warn(t("multihop.not_enough_nodes"))
        _pause()
        return

    denom = client.denom
    ui.header(t("multihop.title"))
    ui.info(ui.dim(t("multihop.intro")))
    entry = _pick_multihop_node(eligible, "multihop.prompt.entry", denom)
    if entry is None:
        return
    remaining = [n for n in eligible if n.address != entry.address]
    exit_node = _pick_multihop_node(remaining, "multihop.prompt.exit", denom)
    if exit_node is None:
        return

    # One duration spec applied to both hops (symmetric); the cost is summed.
    qty_type = ui.prompt(t("nodes.prompt.duration_type")).lower()
    by_hours = qty_type.startswith("h")
    raw = ui.prompt(t("nodes.prompt.hours" if by_hours else "nodes.prompt.gigabytes"))
    amount = int(raw) if raw.isdigit() and int(raw) > 0 else 1

    _bring_up_multihop(unlocked, client, entry, exit_node, by_hours=by_hours, amount=amount)


def _pick_multihop_node(nodes: list, prompt_key: str, denom: str):
    """List the candidates and return the picked NodeInfo, or None to abort."""
    for i, n in enumerate(nodes, start=1):
        ui.info(_format_node_row(i, n, denom))
    raw = ui.prompt(t(prompt_key)).strip().lower()
    if raw in ("b", "back", ""):
        return None
    if raw.isdigit() and 1 <= int(raw) <= len(nodes):
        return nodes[int(raw) - 1]
    ui.error(t("common.invalid_choice"))
    return None


def _quote_cost(node: NodeInfo, denom: str, by_hours: bool, amount: int):
    """Cost in udvpn for `amount` units on `node`, or None if it has no price
    in `denom`. Same formula as single-hop connect."""
    price = node.price_for(denom, by_hours=by_hours)
    if price is None:
        return None
    return int(price["quote_value"]) * amount


def _v2ray_handshake(node: NodeInfo, session_id: int, priv: bytes) -> v2ray.V2Credentials:
    """Handshake a v2ray node, mapping a 409 (already registered) to a clear
    VpnError — same contract as the single-hop credential path."""
    try:
        return v2ray.fetch_creds(
            remote_url=node.remote_url, session_id=session_id, private_key=priv,
        )
    except NodeHandshakeError as e:
        if e.status_code == 409:
            raise VpnError(t("connect.session_already_registered", session_id)) from e
        raise


def _bring_up_multihop(
    unlocked: wallet.Wallet, client: ChainClient,
    entry_node: NodeInfo, exit_node: NodeInfo, *, by_hours: bool, amount: int,
) -> None:
    """Start a session on each node, handshake both (persisting creds before
    bring-up, anti-burn), then bring up the single chained tunnel."""
    denom = client.denom
    costs = []
    for node in (entry_node, exit_node):
        cost = _quote_cost(node, denom, by_hours, amount)
        if cost is None:
            ui.error(t("connect.no_matching_price", denom))
            _pause()
            return
        costs.append(cost)
    total = sum(costs)
    total_dvpn = total / SATOSHI

    balance = client.get_balance()
    if balance is None:
        ui.error(t("connect.wallet_not_funded", unlocked.address))
        _pause()
        return
    if balance < total:
        ui.error(t("connect.insufficient_balance",
                   f"{total_dvpn:.6f}", f"{balance / SATOSHI:.6f}"))
        _pause()
        return

    duration = f"{amount} {'hours' if by_hours else 'GB'}"
    entry_lbl = entry_node.moniker or entry_node.address[-10:]
    exit_lbl = exit_node.moniker or exit_node.address[-10:]
    if not ui.yes_no(t("multihop.confirm", entry_lbl, exit_lbl, duration, f"{total_dvpn:.6f}")):
        ui.info(t("common.cancel"))
        return

    priv = wallet.derive_private_key(unlocked.mnemonic)
    pre_connect_ip = _fetch_public_ip(timeout=2.5)
    state: dict = {"hops": []}
    try:
        for role, node in (("entry", entry_node), ("exit", exit_node)):
            ui.info(t("multihop.starting_hop", role, node.moniker or node.address[-10:]))
            session_id = client.start_session(
                unlocked.secret, node,
                gigabytes=0 if by_hours else amount,
                hours=amount if by_hours else 0,
            )
            # The session is paid the instant start_session returns. Record it
            # as an orphan BEFORE the handshake, so a handshake failure still
            # surfaces the paid session in the partial notice — the same
            # anti-burn net single-hop's _connect_to has. Cleared once the hop
            # is fully persisted into `hops` just below.
            state["orphan_session_id"] = session_id
            cfg.save_state(state)
            creds = _v2ray_handshake(node, session_id, priv)
            transport_cache.record(node.address, v2ray.offered_transports(creds.handshake_peer_data))
            hop = {
                "role": role,
                "session_id": session_id,
                "node_address": node.address,
                "node_moniker": node.moniker or "",
                "node_country": node.country or "",
            }
            hop.update(creds.to_state())
            state["hops"].append(hop)
            state.pop("orphan_session_id", None)  # now tracked inside `hops`
            cfg.save_state(state)  # persist BEFORE bring-up so a crash can't burn it
        # Both hops are paid and persisted: remember the pairing durably so the
        # sessions menu keeps the chain grouped even after a later
        # disconnect/connect, for as long as both sessions stay active.
        multihop_cache.remember(state["hops"])
    except WalletNotOnChainError:
        ui.error(t("connect.wallet_not_funded", unlocked.address))
        _multihop_partial_notice(state)
        _pause()
        return
    except (ChainError, NodeHandshakeError, VpnError) as e:
        ui.error(t("connect.failed", str(e)))
        _multihop_partial_notice(state)
        _pause()
        return

    if not _bring_up_chain_from_state(state, pre_connect_ip):
        _multihop_partial_notice(state)
        _pause()


def _resume_multihop(state: dict) -> None:
    """Re-establish a chain from cached credentials — no new sessions, no
    re-handshake, no extra cost."""
    pre_connect_ip = _fetch_public_ip(timeout=2.5)
    if not _bring_up_chain_from_state(state, pre_connect_ip):
        _pause()


def _bring_up_chain_from_state(state: dict, pre_connect_ip) -> bool:
    """Bring up the chained tunnel from the two persisted hops. On success,
    saves runtime + verifies; returns False (and leaves creds cached for a
    retry) on VpnError."""
    hops = state["hops"]
    try:
        runtime = v2ray.bring_up_multihop(
            entry_creds=v2ray.V2Credentials.from_state(hops[0]),
            exit_creds=v2ray.V2Credentials.from_state(hops[1]),
        ).to_state()
    except VpnError as e:
        ui.error(t("connect.failed", str(e)))
        return False
    state.update(runtime)
    state.pop("orphan_session_id", None)
    cfg.save_state(state)
    status = _verify_public_ip(pre_connect_ip=pre_connect_ip)
    if status == "ok":
        ui.success(t("multihop.connected", connected_label(state)))
    else:
        # The chain is up but the check couldn't confirm it (often the user's
        # network blocking the check endpoints). Keep it up and warn — it's
        # connected as far as we can tell, so we report success to the caller.
        _warn_after_unverified(status)
    _pause()
    return True


def _multihop_partial_notice(state: dict) -> None:
    """A chain bring-up left paid sessions on chain. They stay visible in
    'My active sessions' (end them there) and their creds remain cached so
    'Multihop' can resume without re-paying. Also surfaces an orphan session
    whose handshake failed after it was already paid for, so the user is told
    about every session they were charged for."""
    sids = list(cfg.active_session_ids(state))
    orphan = state.get("orphan_session_id")
    if isinstance(orphan, int) and orphan not in sids:
        sids.append(orphan)
    if sids:
        ui.warn(t("multihop.partial", ", ".join(str(s) for s in sids)))


# --------------------------------------------------------------------------
# Disconnect (called from app.py)
# --------------------------------------------------------------------------


def _teardown_tunnel(state: dict) -> None:
    """Kill the local VPN processes and restore routing/DNS for whatever
    backend `state` records. Does not touch state.json — the caller decides
    what to persist afterward. Shared by the disconnect menu and by ending
    the currently-active session."""
    backend = state.get("backend")
    if backend == "wireguard":
        try:
            wireguard.disconnect(state)
        except VpnError as e:
            ui.error(t("common.error", str(e)))
    elif backend in ("v2ray", "v2ray-multihop"):
        # Multihop is one v2ray process + one tun2socks, same as single-hop —
        # the teardown is identical; only the chain config differed.
        v2ray.disconnect(state)


def disconnect(unlocked: Optional[wallet.Wallet], client: Optional[ChainClient]) -> None:
    """Tear down the local tunnel but KEEP the chain session alive and
    the cached handshake credentials in state.json — that's what lets a
    later reconnect skip the (forbidden) re-handshake. To end the
    session for good, the user picks `<num>e` in the sessions menu.
    """
    state = cfg.load_state()
    if not state or not state.get("backend"):
        ui.info(t("disconnect.no_active"))
        return
    ui.info(t("disconnect.starting", connected_label(state)))
    _teardown_tunnel(state)

    # Strip runtime-only keys; preserve session+creds so a later reconnect
    # can skip the (forbidden) re-handshake. See config._RUNTIME_STATE_KEYS.
    cfg.strip_runtime_state()
    # The chain channel was routing through the tunnel we just dropped, so it's
    # now stuck on a dead connection. Rebuild it over restored routing so the
    # next sessions/browse view works immediately instead of timing out.
    _reconnect_client(client)
    ui.success(t("disconnect.done"))
    _pause()


def _reconnect_client(client: Optional[ChainClient]) -> None:
    """Best-effort rebuild of the chain connection after a teardown. If it
    fails (e.g. routing hasn't settled yet) we stay quiet — the next chain
    call self-heals or surfaces a clear error of its own."""
    if client is None:
        return
    try:
        client.reconnect()
    except Exception:
        pass


# --------------------------------------------------------------------------
# Sessions menu
# --------------------------------------------------------------------------


def _live_tunnel_expired(state: dict, active_ids) -> bool:
    """True iff `state` claims a live tunnel but at least one of its session
    ids is no longer active on chain. Sessions are ephemeral (a pay-per-hour or
    -gigabyte session ends when its allocation runs out), and when one expires
    the local tunnel keeps running but the node stops forwarding — so we're
    "connected" with no traffic. Detecting that lets us tear the dead tunnel
    down and stop the UI from claiming we're online."""
    if not state.get("backend"):
        return False
    live = set(cfg.active_session_ids(state))
    return bool(live) and not (live <= set(active_ids))


def sessions_menu(
    unlocked: wallet.Wallet,
    client: ChainClient,
    cache: "Optional[node_cache.NodeCache]" = None,
) -> None:
    ui.info(t("sessions.loading"))
    fetch_ok = True
    try:
        sessions = client.my_active_sessions()
    except Exception as e:
        ui.error(t("common.error", str(e)))
        sessions = []
        fetch_ok = False

    state = cfg.load_state()

    # A live tunnel whose session expired on chain is dead — the node stopped
    # forwarding but our local processes (and the "connected" state) linger.
    # Tear it down and clear the stale state so we restore normal connectivity
    # and stop reporting a connection that no longer routes. Only when the
    # fetch succeeded: a transient RPC error must NOT be read as "expired".
    if fetch_ok and _live_tunnel_expired(state, {s.id for s in sessions}):
        ui.warn(t("sessions.live_expired"))
        _teardown_tunnel(state)
        cfg.clear_state()
        _reconnect_client(client)
        state = {}

    # Fold in any orphan session id saved by a failed handshake. We only
    # surface it if it isn't already in the chain list AND it's still active
    # on chain — otherwise we silently drop it from state.
    orphan_id = state.get("orphan_session_id")
    if orphan_id and not any(s.id == orphan_id for s in sessions):
        verified = client.query_session(int(orphan_id))
        if verified is not None and verified.is_active:
            sessions.append(verified)
        else:
            state.pop("orphan_session_id", None)
            cfg.save_state(state)

    if not sessions:
        ui.info(t("sessions.none"))
        _pause()
        return

    # Build {address -> NodeInfo} from the in-memory cache (instant; no
    # network). Sessions whose node fell out of the active set just show
    # the chain address — at least the user can still end them.
    node_by_addr: dict = {}
    if cache is not None:
        for n in cache.get(wait_timeout=0.0):
            node_by_addr[n.address] = n

    # Forget any remembered chain whose two sessions aren't both still active,
    # so a stale pairing never groups unrelated sessions and the cache stays
    # small. (A chain with both sessions live is kept and will group below.)
    # Only when the fetch actually succeeded — a transient RPC error must not
    # be read as "these sessions are gone" and wipe valid pairings.
    if fetch_ok:
        multihop_cache.prune_to({s.id for s in sessions})

    rows = _group_sessions(sessions, state)

    ui.header(t("main.menu.sessions"))
    ui.info(t("sessions.header"))
    for i, (kind, payload) in enumerate(rows, 1):
        if kind == "chain":
            ui.info("  " + _format_chain_row(i, payload, node_by_addr))
        else:
            ui.info("  " + _format_session_row(i, payload, node_by_addr, orphan_id))
    # Quota warnings stay per on-chain session (each hop has its own quota);
    # both hop ids are printed in the chain row, so a warning is traceable.
    for s in sessions:
        if (s.fraction_used or 0.0) >= _QUOTA_WARN_THRESHOLD:
            ui.warn(t("sessions.quota_warning", s.id, int((s.fraction_used or 0.0) * 100)))
    ui.info("")
    ui.info(t("sessions.prompt.help"))
    raw = ui.prompt(t("sessions.prompt.choice")).strip().lower()

    # Back / cancel — accept anything that means "leave". Without this,
    # typing 'b' (the obvious back keystroke) used to spit "Invalid choice".
    if raw in ("", "b", "back"):
        return

    parsed = _parse_session_action(raw, len(rows))
    if parsed is None:
        ui.error(t("common.invalid_choice"))
        _pause()
        return
    indices, action = parsed

    if action == "e":
        # A chain row expands to both hops, so ending it ends the whole chain.
        _end_sessions(unlocked, client, _expand_rows_for_end(rows, indices))
    else:
        if len(indices) != 1:
            ui.error(t("sessions.reconnect_one_only"))
            _pause()
            return
        kind, payload = rows[indices[0]]
        if kind == "chain":
            # Reconnecting a chain = resume that whole chain from cached creds,
            # not single-hop-reconnect one leg. Look up the selected chain's
            # hops (it may be a remembered chain, not the live one).
            if not _already_connected_guard():
                hops = _find_chain_hops(state, [payload[0].id, payload[1].id])
                if hops is None:
                    ui.error(t("sessions.chain_creds_missing"))
                    _pause()
                else:
                    ui.info(t("sessions.reconnecting_chain"))
                    _resume_multihop({"hops": hops})
        else:
            _reconnect_session(unlocked, client, payload)


_QUOTA_WARN_THRESHOLD = 0.90


def _session_usage_str(s) -> str:
    """Compact 'consumed / limit (pct%)' for a metered (pay-per-use)
    session; empty string for unmetered/subscription-backed ones."""
    kind = s.usage_kind
    if kind is None:
        return ""
    pct = int((s.fraction_used or 0.0) * 100)
    if kind == "bytes":
        used, cap = ui.format_bytes(s.consumed), ui.format_bytes(s.limit)
    else:
        used, cap = ui.format_duration(s.consumed), ui.format_duration(s.limit)
    return f"{used} / {cap} ({pct}%)"


def _format_session_row(i: int, s, node_by_addr: dict, orphan_id) -> str:
    """One enriched session line: id + moniker (country) + type (or just
    the chain address if the node isn't in our cache), plus pay-per-use
    consumption when the session is metered."""
    n = node_by_addr.get(s.node_address)
    if n is not None:
        country = n.country or "—"
        label = f"{n.moniker or '—'}  ({country})  {n.type_name}"
    else:
        # Tail of the address is enough to disambiguate by sight.
        label = s.node_address[-16:]
    marker = "  (orphan)" if s.id == orphan_id else ""
    usage = _session_usage_str(s)
    usage_suffix = f"  —  {usage}" if usage else ""
    return f"{i:>2}. id={s.id:<10}  {label}{marker}{usage_suffix}"


def _chain_hop_label(s, node_by_addr: dict) -> str:
    """Moniker (country) for one chain hop, or the address tail when the node
    isn't in cache — same fallback the single-session row uses."""
    n = node_by_addr.get(s.node_address)
    if n is not None:
        return f"{n.moniker or '—'} ({n.country or '—'})"
    return s.node_address[-12:]


def _format_chain_row(i: int, pair: list, node_by_addr: dict) -> str:
    """One row standing in for a whole multihop chain: entry -> exit. Both hop
    ids are shown so the per-session quota warnings stay traceable, and — when
    the hops are metered (pay-per-use) — each hop's consumption is shown on a
    second line. Both hops carry essentially your full traffic, so the two
    figures should track each other (the entry slightly higher, as it also
    carries the exit layer's wrapping); a wildly asymmetric pair is a sign one
    hop isn't actually routing."""
    entry, exit_ = pair
    line = f"{i:>2}. " + t(
        "sessions.row.multihop",
        _chain_hop_label(entry, node_by_addr),
        _chain_hop_label(exit_, node_by_addr),
        entry.id, exit_.id,
    )
    entry_usage, exit_usage = _session_usage_str(entry), _session_usage_str(exit_)
    if entry_usage or exit_usage:
        line += "\n" + t(
            "sessions.row.multihop_usage", entry_usage or "—", exit_usage or "—"
        )
    return line


def _collapse_chains(sessions: list, chain_pairs: list) -> list:
    """Pure grouping. `chain_pairs` is a list of (entry_id, exit_id) tuples.
    Each pair whose BOTH sessions are present collapses into one
    ('chain', [entry, exit]) row; every other session stays a
    ('single', session) row. A session id is grouped at most once (first
    matching pair wins), so overlapping or stale pairs can't double-count."""
    by_id = {s.id: s for s in sessions}
    used: set = set()
    rows: list = []
    for entry_id, exit_id in chain_pairs:
        if entry_id in by_id and exit_id in by_id and not ({entry_id, exit_id} & used):
            rows.append(("chain", [by_id[entry_id], by_id[exit_id]]))
            used.update((entry_id, exit_id))
    rows += [("single", s) for s in sessions if s.id not in used]
    return rows


def _known_chain_pairs(state: dict) -> list:
    """Ordered (entry_id, exit_id) pairs to group by: the live chain
    (state['hops']) first, then every durably-remembered chain, de-duplicated
    by their unordered id-pair. This is what keeps the two hops of a multihop
    showing as one chain even after you've disconnected or connected somewhere
    else — for as long as both sessions stay active."""
    pairs: list = []
    seen: set = set()

    def add(hops) -> None:
        ids = multihop_cache.hop_session_ids(hops)
        if ids:
            key = frozenset(ids)
            if key not in seen:
                seen.add(key)
                pairs.append((ids[0], ids[1]))

    add(state.get("hops"))
    for hops in multihop_cache.all_chains():
        add(hops)
    return pairs


def _find_chain_hops(state: dict, session_ids) -> "Optional[list]":
    """The hop-pair (with cached creds) for the chain made of `session_ids`,
    looked up among the live chain and the remembered chains — so a chain row
    in the sessions menu can be resumed even when it's no longer the live
    tunnel. None if we no longer hold its credentials."""
    want = set(session_ids)
    for hops in [state.get("hops"), *multihop_cache.all_chains()]:
        if set(multihop_cache.hop_session_ids(hops)) == want and want:
            return list(hops)
    return None


def _group_sessions(sessions: list, state: dict) -> list:
    """Collapse the hops of every known multihop chain (the live one plus any
    remembered, still-active chains) into single 'chain' rows; everything else
    stays a 'single' row. Pairing comes from local memory only — the chain
    isn't recorded on-chain — so a chain whose creds we've lost simply shows as
    individual sessions, still endable one by one."""
    return _collapse_chains(sessions, _known_chain_pairs(state))


def _expand_rows_for_end(rows: list, indices: list) -> list:
    """Flatten the selected rows into the sessions to end. A chain row expands
    to BOTH its hop sessions, so ending a multihop always ends the whole chain
    — never half of it (which would leave a paid hop running on chain)."""
    out: list = []
    for idx in indices:
        kind, payload = rows[idx]
        if kind == "chain":
            out.extend(payload)
        else:
            out.append(payload)
    return out


def _parse_session_action(raw: str, n_sessions: int):
    """Parse the sessions-menu input. Returns (indices, action) or None.

    Accepted formats:
        '3'         → reconnect 3
        '3r'        → same
        '3e'        → end 3
        '1,3,5e'    → end 1, 3, and 5 in one go
        '*e' / 'alle' → end every session in the list
    """
    if not raw:
        return None
    # Trailing letter selects action; default is 'r' (reconnect).
    action = "r"
    body = raw
    if body.endswith(("r", "e")):
        action = body[-1]
        body = body[:-1]
    if body == "all":  # 'alle' → end all
        body = "*"
    if body == "*":
        return list(range(n_sessions)), action

    indices: list[int] = []
    for chunk in body.split(","):
        chunk = chunk.strip()
        if not chunk.isdigit():
            return None
        idx = int(chunk) - 1
        if not 0 <= idx < n_sessions:
            return None
        if idx not in indices:
            indices.append(idx)
    if not indices:
        return None
    return indices, action


def _end_sessions(unlocked: wallet.Wallet, client: ChainClient, sessions: list) -> None:
    """End one or more sessions back-to-back. Each tx is independent —
    a failure on session N doesn't block N+1, but we tell the user which
    ones went through and which didn't."""
    if len(sessions) > 1 and not ui.yes_no(t("sessions.confirm_end_many", len(sessions))):
        ui.info(t("common.cancel"))
        return

    state = cfg.load_state()
    ending_ids = {s.id for s in sessions}
    # Does any session we're ending back the LIVE tunnel? If so we tear the
    # tunnel down — but only AFTER the end txs. The chain endpoint is routed
    # around the tunnel (see _routing.add_chain_bypass), so an end tx reaches
    # the chain over the real network whether the tunnel is up or down. Ending
    # first therefore avoids the wedge entirely: we never broadcast over a
    # connection that the teardown is busy ripping the route out from under.
    live = bool(ending_ids & set(cfg.active_session_ids(state)))

    ok: list[int] = []
    failed: list[tuple[int, str]] = []
    for session in sessions:
        try:
            client.end_session(unlocked.secret, session.id)
            ok.append(session.id)
            # Non-live orphan bookkeeping; the live tunnel (if any) is cleared
            # once after the loop.
            if not live and state.get("orphan_session_id") == session.id:
                state.pop("orphan_session_id", None)
                cfg.save_state(state)
        except WalletNotOnChainError:
            failed.append((session.id, t("connect.wallet_not_funded", unlocked.address)))
            break  # nothing else will work either
        except ChainError as e:
            failed.append((session.id, str(e)))

    # Now that the sessions are ended, drop the tunnel they were backing.
    if live:
        if state.get("backend"):
            ui.info(t("disconnect.starting", connected_label(state)))
            _teardown_tunnel(state)
        cfg.clear_state()

    if ok:
        # Any remembered chain that included an ended session is now defunct.
        multihop_cache.forget(ok)
        ui.success(t("sessions.ok.ended_many", len(ok)) if len(ok) > 1
                   else t("sessions.ok.ended"))
    for sid, err in failed:
        ui.error(f"#{sid}: {err}")
    _pause()


def _reconnect_session(unlocked: wallet.Wallet, client: ChainClient, session) -> None:
    """Reuse a session id that already exists on chain — skip start_session,
    just do the node handshake + tunnel bring-up."""
    if _already_connected_guard():
        return
    ui.info(t("sessions.reconnecting", session.id))
    node = client.get_node(session.node_address)
    if node is None:
        ui.error(t("sessions.node_unreachable", session.node_address))
        _pause()
        return
    try:
        _bring_up_tunnel(unlocked, client, node, session.id)
    except VpnError as e:
        ui.error(t("connect.failed", str(e)))
        _pause()


# --------------------------------------------------------------------------
# Settings menu
# --------------------------------------------------------------------------


def settings_menu() -> bool:
    """Returns True if the gRPC endpoint differs from when the menu was opened,
    so the caller can rebuild the chain client against the new endpoint. Just
    viewing settings (or changing then reverting) returns False — nothing to
    rebuild, and the warm node cache is kept."""
    entry = cfg.load_config()
    entry_grpc = (entry["grpc_host"], entry["grpc_port"])
    while True:
        c = cfg.load_config()
        grpc = f"{c['grpc_host']}:{c['grpc_port']}"
        ui.header(t("settings.menu.title"))
        ui.info(ui.dim(t("settings.label.data_dir", str(cfg.CONFIG_DIR))))
        ui.info("")
        ui.info("1. " + t("settings.menu.grpc", grpc))
        ui.info("2. " + t("settings.menu.reset"))
        ui.info("3. " + t("common.back"))
        choice = ui.prompt("> ")
        if choice == "1":
            raw = ui.prompt(t("settings.prompt.grpc"))
            if not raw:
                continue
            try:
                host, port = raw.rsplit(":", 1)
                c["grpc_host"] = host.strip()
                c["grpc_port"] = int(port)
                cfg.save_config(c)
                ui.success(t("settings.ok.saved"))
                _pause()
            except ValueError:
                ui.error(t("common.invalid_choice"))
        elif choice == "2":
            cfg.save_config(dict(cfg.DEFAULT_CONFIG))
            ui.success(t("settings.ok.saved"))
            _pause()
        elif choice == "3":
            final = cfg.load_config()
            return (final["grpc_host"], final["grpc_port"]) != entry_grpc
        else:
            ui.error(t("common.invalid_choice"))


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _format_price(prices: list[dict], denom: str) -> str:
    """Human-readable price for the wallet's denom (e.g. '0.250 P2P'). Falls
    back to any denom the node lists, or '—' if it lists none. Shared by the
    per-GB and per-hour columns so both format identically."""
    quote = next((p["quote_value"] for p in prices if p.get("denom") == denom), None)
    if quote is not None:
        try:
            return f"{int(quote) / SATOSHI:.3f} {TICKER}"
        except (ValueError, TypeError):
            return str(quote)
    if prices:
        p = prices[0]
        return f"{p.get('quote_value', '?')} {p.get('denom', '?')}"
    return "—"


def _format_node_row(idx: int, n: NodeInfo, denom: str) -> str:
    gb_price = _format_price(n.gigabyte_prices, denom)
    hr_price = _format_price(n.hourly_prices, denom)
    country = (n.country or "—")[:18]
    moniker = (n.moniker or "—")[:28]
    return (
        f"  {idx:>2}  {country:<20}  {moniker:<28}  "
        f"{n.type_name:<10}  {gb_price:<11}  {hr_price}"
    )


def _format_balance(client: ChainClient) -> str:
    udvpn = client.get_balance()
    if udvpn is None:
        return t("balance.not_on_chain")
    return f"{udvpn / SATOSHI:.6f} {TICKER}"