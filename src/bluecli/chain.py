"""Sentinel chain client — a thin façade over the official Python SDK.

Read-only by default. The signing SDK is created lazily on the first tx
broadcast: the `SDKInstance(secret=...)` constructor queries the chain
for the account's sequence number, and that query returns NOT_FOUND for
any wallet that has never received a single coin. Splitting it this way
lets a brand-new zero-balance wallet log in, browse nodes, and see its
empty balance instead of crashing.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Optional

import grpc
import sentinel_protobuf.cosmos.bank.v1beta1.query_pb2 as bank_pb2
import sentinel_protobuf.cosmos.bank.v1beta1.query_pb2_grpc as bank_pb2_grpc
import sentinel_protobuf.sentinel.node.v3.session_pb2 as node_session_pb2
import sentinel_protobuf.sentinel.session.v3.session_pb2 as session_pb2
import sentinel_protobuf.sentinel.subscription.v3.session_pb2 as subscription_session_pb2
from sentinel_sdk.sdk import SDKInstance
from sentinel_sdk.types import PageRequest, Status, TxParams
from sentinel_sdk.utils import search_attribute

from .config import load_config

NODE_TYPE_WIREGUARD = 1
NODE_TYPE_V2RAY = 2


@dataclass
class NodeInfo:
    """The subset of node fields we display and use.

    Prices are stored as plain dicts ({denom, base_value, quote_value}) so
    NodeInfo can be cached on disk via json.dumps + asdict. The Price proto
    is rebuilt only when broadcasting the start-session tx.
    """

    address: str
    moniker: str
    country: str
    remote_url: str
    node_type: int  # 1 = wireguard, 2 = v2ray
    gigabyte_prices: list[dict]
    hourly_prices: list[dict]

    @property
    def type_name(self) -> str:
        return {NODE_TYPE_WIREGUARD: "wireguard", NODE_TYPE_V2RAY: "v2ray"}.get(
            self.node_type, "unknown"
        )

    def price_for(self, denom: str, by_hours: bool) -> Optional[dict]:
        prices = self.hourly_prices if by_hours else self.gigabyte_prices
        for p in prices:
            if p.get("denom") == denom:
                return p
        return None


def _proto_prices_to_dicts(proto_prices: Any) -> list[dict]:
    """Convert a `repeated Price` proto field into plain dicts."""
    return [
        {
            "denom": str(p.denom),
            "base_value": str(p.base_value),
            "quote_value": str(p.quote_value),
        }
        for p in proto_prices
    ]


def _dict_price_to_proto(price_dict: dict) -> Any:
    """Rebuild a Price proto from the plain-dict form. Called only at tx time."""
    import sentinel_protobuf.sentinel.types.v1.price_pb2 as price_pb2

    return price_pb2.Price(
        denom=price_dict["denom"],
        base_value=price_dict["base_value"],
        quote_value=price_dict["quote_value"],
    )


@dataclass
class SessionInfo:
    id: int
    acc_address: str
    node_address: str
    status: int
    # Pay-per-use accounting (0 when the session has no per-session cap,
    # e.g. subscription-backed sessions — see usage_kind).
    download_bytes: int = 0
    upload_bytes: int = 0
    max_bytes: int = 0
    duration_seconds: int = 0
    max_duration_seconds: int = 0

    @property
    def usage_kind(self) -> Optional[str]:
        """'bytes' for gigabyte plans, 'hours' for duration plans, or None
        when the session carries no per-session cap (subscription-backed
        sessions account against the subscription, not the session)."""
        if self.max_bytes > 0:
            return "bytes"
        if self.max_duration_seconds > 0:
            return "hours"
        return None

    @property
    def consumed(self) -> int:
        """Consumed amount in the unit implied by usage_kind (total bytes
        up+down, or seconds). 0 when unmetered."""
        if self.usage_kind == "bytes":
            return self.download_bytes + self.upload_bytes
        if self.usage_kind == "hours":
            return self.duration_seconds
        return 0

    @property
    def is_active(self) -> bool:
        """True iff the session is ACTIVE on chain — not pending-inactive,
        inactive, or expired. The single place that decides 'usable session',
        so the active-status code never has to be hardcoded at a call site."""
        return self.status == Status.ACTIVE.value

    @property
    def limit(self) -> int:
        if self.usage_kind == "bytes":
            return self.max_bytes
        if self.usage_kind == "hours":
            return self.max_duration_seconds
        return 0

    @property
    def fraction_used(self) -> Optional[float]:
        """0.0–1.0, or None if the session is unmetered. Capped at 1.0 so a
        node over-reporting slightly never shows >100%."""
        if self.limit <= 0:
            return None
        return min(self.consumed / self.limit, 1.0)


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------


class ChainError(Exception):
    """Generic chain interaction failure (tx rejected, gRPC down, etc.)."""


class WalletNotOnChainError(ChainError):
    """Raised when we try to sign a tx for a wallet that has never been funded.

    The caller should tell the user to send any amount of DVPN to their
    address first.
    """


class ChainTimeout(ChainError):
    """A chain RPC didn't return within its deadline. The SDK (and the mospy tx
    client underneath it) issue gRPC calls without deadlines, so a slow or
    half-open connection — most notably right after a tunnel teardown changes
    routing under an in-flight connection — could otherwise block forever."""


# Wall-clock ceilings for chain RPCs. These are not the expected latency (a
# healthy query answers in well under a second); they are the point past which
# we stop waiting and hand control back to the user instead of freezing.
_RPC_TIMEOUT = 15.0          # connect, read queries, account reload, broadcast
_TX_CONFIRM_TIMEOUT = 35.0   # waiting for a broadcast tx to land (> the 30s we
                             # pass to wait_for_tx, so its own loop wins normally)


def _run_bounded(fn, timeout: float, label: str):
    """Run a blocking gRPC call under a hard wall-clock deadline.

    The call runs on a daemon thread; if it hasn't finished after `timeout`
    seconds we give up and raise ChainTimeout. The abandoned thread keeps
    running until the OS finally tears the dead socket down, but it can never
    freeze the CLI. Any exception the call raises is re-raised on the caller's
    thread so existing error handling (RpcError -> None, etc.) still applies.
    """
    box: dict = {}
    done = threading.Event()

    def worker() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # re-raised on the caller thread below
            box["error"] = exc
        finally:
            done.set()

    threading.Thread(target=worker, daemon=True, name=f"chain-{label}").start()
    if not done.wait(timeout):
        raise ChainTimeout(
            f"Chain RPC '{label}' timed out after {int(timeout)}s — the network "
            f"or the gRPC endpoint may be unreachable. Please try again."
        )
    if "error" in box:
        raise box["error"]
    return box.get("value")


# --------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------


class ChainClient:
    """Read-only by default. Pass `secret=` to a tx method to enable signing."""

    def __init__(self, address: str):
        cfg = load_config()
        self._host: str = cfg["grpc_host"]
        self._port: int = int(cfg["grpc_port"])
        self._ssl: bool = bool(cfg["grpc_ssl"])
        self._denom: str = cfg["denom"]
        self._address: str = address
        # Read-only SDK. Never queries auth.Account, so always succeeds when
        # gRPC is reachable — even for an unfunded wallet. Bounded: the SDK
        # constructor makes a reflection call with no deadline, which would
        # otherwise hang if the endpoint is unreachable.
        self._sdk = _run_bounded(
            lambda: SDKInstance(self._host, self._port, ssl=self._ssl),
            _RPC_TIMEOUT, "connect",
        )
        self._signing_sdk: Optional[SDKInstance] = None

    @property
    def address(self) -> str:
        return self._address

    @property
    def denom(self) -> str:
        return self._denom

    def reconnect(self) -> None:
        """Rebuild the gRPC connection from scratch.

        The SDK channel can get wedged on a dead connection when the network
        changes under it — most often when a tunnel we were routing through is
        torn down. gRPC keeps retrying that stale subchannel, so every call
        then times out even though normal connectivity is back. A brand-new
        channel re-resolves and connects over the current network. The
        signing SDK is dropped too so it's rebuilt lazily on the next tx.
        """
        self._sdk = _run_bounded(
            lambda: SDKInstance(self._host, self._port, ssl=self._ssl),
            _RPC_TIMEOUT, "reconnect",
        )
        self._signing_sdk = None

    def _query(self, fn, label: str):
        """Run a read query under a deadline; if it times out — almost always a
        stale channel after the network changed under us — rebuild the
        connection once and retry over the current network before giving up.
        This is what stops a single network blip from wedging every later
        query until the app is restarted."""
        try:
            return _run_bounded(fn, _RPC_TIMEOUT, label)
        except ChainTimeout:
            self.reconnect()  # propagates ChainTimeout only if the net is truly down
            return _run_bounded(fn, _RPC_TIMEOUT, label)

    # -- Read-only queries -------------------------------------------------

    def list_active_nodes(self, limit: int = 1000) -> list[NodeInfo]:
        """Return EVERY active node on chain.

        `limit` is the page size, NOT a total cap: the SDK's QueryAll walks
        all pages via the pagination `next_key` cursor and concatenates them,
        so a network with more nodes than `limit` (e.g. ~1,400 vs 1,000) still
        comes back complete — it just takes one extra round trip. We keep the
        page size high to minimise those round trips.
        """
        nodes = self._query(
            lambda: self._sdk.nodes.QueryNodes(
                Status.ACTIVE, pagination=PageRequest(limit=limit)
            ),
            "list_active_nodes",
        )
        # We don't call self._sdk.nodes.QueryNodesStatus: it (a) leaks raw
        # print() calls to stdout, and (b) hits the node's root `/` rather
        # than `/status`, so the response often lacks the `type` field we
        # need to know whether the node speaks WireGuard or V2Ray.
        statuses = _probe_nodes(nodes)
        return [
            info for info in (
                _build_node_info(node, statuses.get(node.address, {})) for node in nodes
            ) if info is not None
        ]

    def get_balance(self) -> Optional[int]:
        """Balance in udvpn, or None if the account doesn't exist on chain.

        None vs 0 is meaningful: None means "wallet has never been funded";
        0 means "account exists but is empty".
        """
        stub = bank_pb2_grpc.QueryStub(self._sdk._channel)
        try:
            resp = stub.Balance(
                bank_pb2.QueryBalanceRequest(address=self._address, denom=self._denom),
                timeout=_RPC_TIMEOUT,
            )
            return int(resp.balance.amount or 0)
        except grpc.RpcError:
            return None

    def my_active_sessions(self) -> list[SessionInfo]:
        """Sessions are returned as google.protobuf.Any; the actual wire-
        format wrapper is sentinel.node.v3.Session (gigabyte/hour pay-per-use)
        or sentinel.subscription.v3.Session (subscription-based), both with
        an embedded BaseSession at field 1. We try each in turn."""
        raw_any = self._query(
            lambda: self._sdk.sessions.QuerySessionsForAccount(
                self._address, pagination=PageRequest(limit=100, reverse=True)
            ),
            "my_active_sessions",
        )
        out: list[SessionInfo] = []
        for any_msg in raw_any:
            base = _parse_session_any(any_msg)
            if base is None:
                continue
            if base.status != Status.ACTIVE.value:
                continue
            out.append(
                SessionInfo(
                    id=int(base.id),
                    acc_address=base.acc_address,
                    node_address=base.node_address,
                    status=int(base.status),
                    **_session_usage(base),
                )
            )
        return out

    def get_node(self, node_address: str) -> Optional[NodeInfo]:
        """Look up a single node by chain address, with the same /status
        probe `list_active_nodes` does. Used to reconnect to a known node
        without re-fetching every node on the network."""
        try:
            node = self._query(
                lambda: self._sdk.nodes.QueryNode(node_address), "get_node"
            )
        except (grpc.RpcError, ChainTimeout):
            return None
        if node is None:
            return None
        statuses = _probe_nodes([node])
        return _build_node_info(node, statuses.get(node.address, {}))

    def query_session(self, session_id: int) -> Optional[SessionInfo]:
        """Look up a single session by id. Returns None if not found or the
        chain query fails."""
        try:
            any_msg = self._query(
                lambda: self._sdk.sessions.QuerySession(session_id), "query_session"
            )
        except (grpc.RpcError, ChainTimeout):
            return None
        if any_msg is None:
            return None
        base = _parse_session_any(any_msg)
        if base is None:
            return None
        return SessionInfo(
            id=int(base.id),
            acc_address=base.acc_address,
            node_address=base.node_address,
            status=int(base.status),
            **_session_usage(base),
        )

    # -- Transactions ------------------------------------------------------

    def start_session(
        self, secret: str, node: NodeInfo, *, gigabytes: int, hours: int
    ) -> int:
        price_dict = node.price_for(self._denom, by_hours=hours > 0)
        if price_dict is None:
            raise ChainError(
                f"Node does not accept {self._denom}. Pick a different node."
            )
        sdk = self._ensure_signing(secret)
        self._reload_account(sdk)
        tx_params = TxParams(denom=self._denom, gas_multiplier=1.5)
        tx = _run_bounded(
            lambda: sdk.nodes.SubscribeToNode(
                node_address=node.address,
                price=_dict_price_to_proto(price_dict),
                gigabytes=gigabytes,
                hours=hours,
                tx_params=tx_params,
            ),
            _RPC_TIMEOUT, "start_session broadcast",
        )
        if tx.get("log"):
            raise ChainError(tx["log"])
        if not tx.get("hash"):
            raise ChainError("Transaction broadcast failed.")

        # The broadcast already returned a hash, so the session is paid. If the
        # confirmation stalls (timeout), don't raise and lose track of it — fall
        # through to the fallback that looks it up among our active sessions.
        try:
            tx_response = _run_bounded(
                lambda: sdk.nodes.wait_for_tx(tx["hash"], timeout=30),
                _TX_CONFIRM_TIMEOUT, "start_session confirm",
            )
            session_id = _extract_session_id(tx_response)
        except ChainTimeout:
            session_id = None

        if session_id is None:
            # Fallback: query our newest active session on this node.
            for s in self.my_active_sessions():
                if s.node_address == node.address:
                    return s.id
            raise ChainError("Session id not found in tx response.")
        return session_id

    def end_session(self, secret: str, session_id: int) -> None:
        sdk = self._ensure_signing(secret)
        self._reload_account(sdk)
        tx_params = TxParams(denom=self._denom, gas_multiplier=1.5)
        tx = _run_bounded(
            lambda: sdk.sessions.EndSession(session_id=session_id, tx_params=tx_params),
            _RPC_TIMEOUT, "end_session broadcast",
        )
        if tx.get("log"):
            raise ChainError(tx["log"])
        if tx.get("hash"):
            # Confirmation is best-effort: the end tx is already broadcast, so a
            # stalled confirm must neither hang nor be reported as a failure —
            # the sessions list reflects the real state on the next refresh.
            try:
                _run_bounded(
                    lambda: sdk.sessions.wait_for_tx(tx["hash"], timeout=30),
                    _TX_CONFIRM_TIMEOUT, "end_session confirm",
                )
            except ChainTimeout:
                pass

    # -- Internals ---------------------------------------------------------

    def _reload_account(self, sdk: SDKInstance) -> None:
        """Re-read account_number and sequence from chain before broadcasting.

        The SDK's Transactor used to do this implicitly, but the call was
        commented out in v12 (`# Required before each tx of we get account
        sequence mismatch...`). Without it, two back-to-back txs from the
        same process always fail with the second one out of sequence.
        """
        try:
            _run_bounded(
                lambda: sdk._client.load_account_data(account=sdk._account),
                _RPC_TIMEOUT, "reload_account",
            )
        except Exception:
            # Best-effort: if the reload fails (or times out), the broadcast
            # will still surface a clearer error to the user.
            pass

    def _ensure_signing(self, secret: str) -> SDKInstance:
        """Create the signing SDK on first use.

        The underlying SDK constructor calls auth.Account on chain, which
        returns NOT_FOUND for never-funded wallets. We translate that into
        a clear, user-actionable error.
        """
        if self._signing_sdk is not None:
            return self._signing_sdk
        try:
            self._signing_sdk = _run_bounded(
                lambda: SDKInstance(
                    self._host, self._port, secret=secret, ssl=self._ssl
                ),
                _RPC_TIMEOUT, "signing_connect",
            )
        except grpc.RpcError as e:
            code = getattr(e, "code", lambda: None)()
            if code == grpc.StatusCode.NOT_FOUND:
                raise WalletNotOnChainError() from e
            raise ChainError(f"gRPC error while preparing the wallet: {e}") from e
        return self._signing_sdk


# --------------------------------------------------------------------------
# Module-level helpers
# --------------------------------------------------------------------------


def _first_remote(node: Any) -> str:
    addrs = list(node.remote_addrs) if hasattr(node, "remote_addrs") else []
    if addrs:
        return "https://" + addrs[0]
    return getattr(node, "remote_url", "")


def _build_node_info(node: Any, info: dict) -> Optional[NodeInfo]:
    """Combine a chain Node proto with its /status probe result into a
    NodeInfo. Returns None when the node didn't respond or didn't
    advertise a usable type — such nodes can't be connected to, so
    surfacing them in the UI would be a dead end."""
    if not info or not info.get("type"):
        return None
    return NodeInfo(
        address=node.address,
        moniker=info.get("moniker", ""),
        country=info.get("country", ""),
        remote_url=_first_remote(node),
        node_type=int(info["type"]),
        gigabyte_prices=_proto_prices_to_dicts(node.gigabyte_prices),
        hourly_prices=_proto_prices_to_dicts(node.hourly_prices),
    )


_SERVICE_TYPE_TO_INT = {"wireguard": NODE_TYPE_WIREGUARD, "v2ray": NODE_TYPE_V2RAY}


def _parse_node_response(data: Any) -> dict:
    """Map a Sentinel node's response to our flat internal dict.

    Reference response (from a live mainnet node):
        {"success": true, "result": {
            "addr": "sentnode1...",
            "service_type": "v2ray",          # or "wireguard"
            "moniker": "...",
            "location": {"country": "...", ...},
            ...
        }}

    Anything that doesn't follow this shape is treated as unusable and
    returns `{}` — we'd rather drop a malformed node from the list than
    show it and crash on connect.
    """
    if not isinstance(data, dict) or not data.get("success"):
        return {}
    result = data.get("result")
    if not isinstance(result, dict):
        return {}
    type_int = _SERVICE_TYPE_TO_INT.get(str(result.get("service_type", "")).lower())
    if not type_int:
        return {}
    location = result.get("location") if isinstance(result.get("location"), dict) else {}
    return {
        "type": type_int,
        "moniker": str(result.get("moniker", "")),
        "country": str(location.get("country", "")),
    }


def _session_int(s: str) -> int:
    """cosmos Int fields come over the wire as strings ("" for zero)."""
    try:
        return int(s) if s else 0
    except (TypeError, ValueError):
        return 0


def _session_usage(base) -> dict:
    """Pull the pay-per-use accounting fields off a BaseSession into the
    kwargs SessionInfo expects. duration/max_duration are protobuf
    Durations; seconds is all the granularity the UX needs."""
    return {
        "download_bytes": _session_int(base.download_bytes),
        "upload_bytes": _session_int(base.upload_bytes),
        "max_bytes": _session_int(base.max_bytes),
        "duration_seconds": int(base.duration.seconds),
        "max_duration_seconds": int(base.max_duration.seconds),
    }


def _parse_session_any(any_msg: Any):
    """Sessions returned from chain are google.protobuf.Any wrapping one of:
        sentinel.node.v3.Session         (pay-per-use)
        sentinel.subscription.v3.Session (subscription-based)
    Both contain an embedded BaseSession at field 1. We pick the right
    wrapper from the Any's type_url, falling back to trying both in case
    the type_url is missing or unexpected.

    Returns the inner BaseSession (so the caller can read id, status, etc.),
    or None if nothing parses to a non-zero session id.
    """
    type_url = getattr(any_msg, "type_url", "") or ""
    if "subscription" in type_url:
        wrappers = [subscription_session_pb2.Session, node_session_pb2.Session]
    else:
        wrappers = [node_session_pb2.Session, subscription_session_pb2.Session]
    for cls in wrappers:
        outer = cls()
        try:
            outer.MergeFromString(any_msg.value)
        except Exception:
            continue
        if outer.base_session.id > 0:
            return outer.base_session
    # Final fallback: maybe the chain returned a bare BaseSession.
    bs = session_pb2.BaseSession()
    try:
        bs.MergeFromString(any_msg.value)
    except Exception:
        return None
    return bs if bs.id > 0 else None


def _probe_nodes(nodes: list[Any], *, timeout: int = 3, workers: int = 64) -> dict:
    """Hit each node's root endpoint in parallel; return a dict of
    `address -> {type, moniker, country}`.

    We bypass the SDK's QueryNodesStatus because it (a) leaks `print()`
    calls to stdout and (b) parses a stale response shape.

    For typical mainnet sizes (~1,400 active nodes), 64 workers × 3s
    timeout completes in 20-40 seconds in the worst case.
    """
    import json
    import ssl
    import urllib.error
    import urllib.request
    from concurrent.futures import ThreadPoolExecutor

    # Sentinel nodes serve self-signed TLS. The chain-side signature is
    # what authenticates the exchange, not the cert.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def probe(node: Any) -> tuple[str, dict]:
        if not getattr(node, "remote_addrs", None):
            return (node.address, {})
        url = "https://" + node.remote_addrs[0]
        try:
            with urllib.request.urlopen(url, context=ctx, timeout=timeout) as f:
                data = json.loads(f.read().decode("utf-8"))
        except Exception:
            # Catch everything: a single bad node response must not kill
            # the whole probe batch. We get this much-too-often: timeout,
            # SSL handshake failure, HTML 5xx body that isn't JSON, etc.
            return (node.address, {})
        return (node.address, _parse_node_response(data))

    if not nodes:
        return {}
    out: dict = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for addr, status in ex.map(probe, nodes):
            out[addr] = status
    return out


def _extract_session_id(tx_response: Any) -> Optional[int]:
    """Find the session id in the tx events, across SDK / chain versions."""
    candidates = (
        ("sentinel.node.v3.EventCreateSession", "session_id"),
        ("sentinel.session.v3.EventStart", "session_id"),
        ("sentinel.session.v2.EventStart", "id"),
        ("sentinel.node.v2.EventCreateSubscription", "id"),
    )
    for event_name, attr_name in candidates:
        value = search_attribute(tx_response, event_name, attr_name)
        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                continue
    return None
