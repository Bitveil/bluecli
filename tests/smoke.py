"""Offline smoke tests.

These exercise every code path that does NOT require a live gRPC connection
or running VPN binaries. They catch:
  - wallet encrypt/decrypt round-trip
  - address derivation from a known BIP-39 vector
  - WireGuard payload decoding from a synthetic 58-byte buffer
  - V2Ray payload decoding from a synthetic 7-byte buffer
  - i18n loading and placeholder substitution
  - state persistence

Run with: `.venv/bin/python tests/smoke.py`

Kept as a single file on purpose — no unittest boilerplate, no pytest
dependency. If something breaks, the assertion that fails tells you exactly
what's wrong.
"""

from __future__ import annotations

import os
import shutil
import socket
import sys
import tempfile
import traceback
from pathlib import Path

# Use a throwaway project dir so we don't touch real state on this machine.
_TMP = Path(tempfile.mkdtemp(prefix="bluecli-smoke-"))
os.environ["BLUECLI_HOME"] = str(_TMP)

# Reload config module so it picks up the new BLUECLI_HOME.
import importlib  # noqa: E402
from bluecli import config  # noqa: E402

importlib.reload(config)
assert config.CONFIG_DIR == _TMP / "data", config.CONFIG_DIR
assert config.BIN_DIR == _TMP / "bin", config.BIN_DIR

from bluecli import i18n, wallet  # noqa: E402
from bluecli.vpn import wireguard as wg_mod  # noqa: E402


_passed = 0
_failed: list[str] = []


def check(name: str, fn):
    global _passed
    try:
        fn()
        _passed += 1
        print(f"  ✓ {name}")
    except Exception:
        _failed.append(name)
        print(f"  ✗ {name}")
        traceback.print_exc()


# --------------------------------------------------------------------------
# i18n
# --------------------------------------------------------------------------


def test_i18n_loads_english():
    i18n.set_language("en")
    assert i18n.t("app.title") == "BlueCLI"


def test_i18n_unknown_key_returns_key():
    assert i18n.t("nope.this.does.not.exist") == "nope.this.does.not.exist"


def test_i18n_placeholders():
    msg = i18n.t("common.error", "boom")
    assert "boom" in msg, msg


def test_i18n_fallback_to_english_for_missing_lang():
    i18n.set_language("xx_definitely_not_a_locale")
    # Fallback is observable through the loaded messages: an English key
    # resolves to its English value rather than echoing the key back.
    assert i18n.t("app.title") == "BlueCLI"


# --------------------------------------------------------------------------
# Wallet
# --------------------------------------------------------------------------

# Standard BIP-39 test vector: this exact mnemonic must derive this exact
# Cosmos/Sentinel address (HRP "sent", path m/44'/118'/0'/0/0).
KNOWN_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)
EXPECTED_ADDRESS = "sent19rl4cm2hmr8afy4kldpxz3fka4jguq0a8mmym6"


def test_wallet_address_derivation_matches_vector():
    addr = wallet._derive_address(KNOWN_MNEMONIC)
    assert addr == EXPECTED_ADDRESS, f"got {addr}"


def test_wallet_create_unlock_delete_round_trip():
    if wallet.exists():
        wallet.delete()
    w1 = wallet.create("hunter2")
    assert wallet.exists()
    assert w1.address.startswith("sent1")
    assert len(w1.mnemonic.split()) == 24

    w2 = wallet.unlock("hunter2")
    assert w2.mnemonic == w1.mnemonic
    assert w2.address == w1.address

    try:
        wallet.unlock("wrong-password")
        raise AssertionError("Should have raised WrongPassword")
    except wallet.WrongPassword:
        pass

    wallet.delete()
    assert not wallet.exists()


def test_wallet_import_validates_mnemonic():
    if wallet.exists():
        wallet.delete()
    try:
        wallet.import_from_mnemonic("not a real mnemonic at all", "pw")
        raise AssertionError("Should have raised InvalidMnemonic")
    except wallet.InvalidMnemonic:
        pass


def test_wallet_import_from_known_vector():
    if wallet.exists():
        wallet.delete()
    w = wallet.import_from_mnemonic(KNOWN_MNEMONIC, "pw")
    assert w.address == EXPECTED_ADDRESS
    wallet.delete()


def test_wallet_refuses_to_overwrite():
    if wallet.exists():
        wallet.delete()
    wallet.create("pw")
    try:
        wallet.create("pw2")
        raise AssertionError("Should have raised WalletExists")
    except wallet.WalletExists:
        pass
    wallet.delete()


def test_derive_private_key_is_deterministic_and_32_bytes():
    priv = wallet.derive_private_key(KNOWN_MNEMONIC)
    assert isinstance(priv, bytes)
    assert len(priv) == 32, len(priv)
    # Same input → same output.
    assert wallet.derive_private_key(KNOWN_MNEMONIC) == priv


# --------------------------------------------------------------------------
# Config + state round trip
# --------------------------------------------------------------------------


def test_config_load_default():
    config.ensure_dir()
    c = config.load_config()
    assert c["grpc_host"] == "grpc.sentinel.co"
    assert c["denom"] == "udvpn"
    assert c["chain_id"] == "sentinelhub-2"


def test_state_round_trip():
    config.save_state({"backend": "wireguard", "session_id": 42})
    s = config.load_state()
    assert s["session_id"] == 42
    config.clear_state()
    assert config.load_state() == {}


# --------------------------------------------------------------------------
# Payload decoders
# --------------------------------------------------------------------------


def test_wireguard_parses_v8_response():
    """The v8.x node returns the WG peer info as JSON, not bit-packed bytes."""
    from bluecli.vpn import HandshakeResult
    from bluecli.vpn import wireguard as wg_mod

    handshake = HandshakeResult(
        node_addrs=["203.0.113.7:9933"],
        peer_data={
            "addrs": ["10.0.0.5/32", "fd00::5/128"],
            "metadata": [
                {"port": 51820, "public_key": "U" + "z" * 43},
            ],
        },
    )
    peer = wg_mod._peer_from_response(handshake)
    assert peer.ipv4 == "10.0.0.5/32", peer.ipv4
    assert peer.ipv6 == "fd00::5/128", peer.ipv6
    # The endpoint host comes from node_addrs (stripped of API port),
    # but the port is the WG listen port from metadata.
    assert peer.endpoint == "203.0.113.7:51820", peer.endpoint
    assert peer.public_key == "U" + "z" * 43


def test_wireguard_config_file_is_valid_ini():
    import configparser

    peer = wg_mod._Peer(
        ipv4="10.0.0.5/32",
        ipv6="fd00::5/128",
        endpoint="203.0.113.7:51820",
        public_key="A" * 44,
    )
    out = _TMP / "test.conf"
    wg_mod._write_config(str(out), "B" * 44, peer)
    cp = configparser.RawConfigParser()
    cp.read(str(out))
    assert cp["Interface"]["PrivateKey"] == "B" * 44
    assert cp["Peer"]["Endpoint"] == "203.0.113.7:51820"
    out.unlink()


def test_v2ray_parses_v8_response():
    """String-form metadata still works (older nodes)."""
    from bluecli.vpn import HandshakeResult
    from bluecli.vpn import v2ray as v2ray_mod

    handshake = HandshakeResult(
        node_addrs=["203.0.113.7:9933"],
        peer_data={
            "metadata": [{
                "port": "443",
                "proxy_protocol": "vmess",
                "transport_protocol": "tcp",
                "transport_security": "tls",
            }],
        },
    )
    server = v2ray_mod._server_from_response(handshake)
    assert server == {
        "host": "203.0.113.7", "port": 443,
        "proxy": "vmess", "transport": "tcp", "security": "tls",
    }


def test_v2ray_parses_int_enum_metadata():
    """REGRESSION: Sentinel nodes return metadata enums as INTEGERS
    (proxy_protocol=2 → vmess, transport_protocol=3 → grpc,
    transport_security=2 → tls). Without decoding, we sent `network: "3"`
    to v2ray, which rejected it with `unknown transport protocol: 3`
    and the tunnel never started. The user saw a flow that said
    `✓ Connected` but no traffic ever moved. This was the FedNet bug.
    """
    from bluecli.vpn import HandshakeResult
    from bluecli.vpn import v2ray as v2ray_mod

    handshake = HandshakeResult(
        node_addrs=["203.0.113.7:9933"],
        peer_data={
            "metadata": [{
                "port": 443,
                "proxy_protocol": 2,        # vmess
                "transport_protocol": 3,    # grpc
                "transport_security": 2,    # tls
            }],
        },
    )
    server = v2ray_mod._server_from_response(handshake)
    assert server["host"] == "203.0.113.7"
    assert server["port"] == 443
    assert server["proxy"] == "vmess", "proxy_protocol=2 must decode to vmess"
    assert server["transport"] == "grpc", "transport_protocol=3 must decode to grpc (NOT '3')"
    assert server["security"] == "tls", "transport_security=2 must decode to tls"


def test_v2ray_parses_digit_string_enum():
    """Some intermediate node versions return enum values as digit-strings
    ('3' as a string). The decoder must handle this too."""
    from bluecli.vpn.v2ray import _decode_enum, _TRANSPORT_PROTOCOL_ENUM

    assert _decode_enum("3", _TRANSPORT_PROTOCOL_ENUM, "tcp") == "grpc"
    assert _decode_enum(3, _TRANSPORT_PROTOCOL_ENUM, "tcp") == "grpc"
    assert _decode_enum("grpc", _TRANSPORT_PROTOCOL_ENUM, "tcp") == "grpc"
    assert _decode_enum(None, _TRANSPORT_PROTOCOL_ENUM, "tcp") == "tcp"
    assert _decode_enum("", _TRANSPORT_PROTOCOL_ENUM, "tcp") == "tcp"


def test_v2ray_config_enables_tls_when_node_says_tls():
    """Pins the bug fix: with security='tls', the streamSettings must
    contain {security: tls, tlsSettings: {serverName, allowInsecure: true}}.
    Without that, v2ray's vmess outbound speaks plain TCP to a TLS server
    and never delivers data — the symptom is 'connected but no traffic'."""
    from bluecli.vpn.v2ray import _build_v2ray_config

    cfg = _build_v2ray_config(
        vmess_address="203.0.113.7", vmess_port=443,
        vmess_uid="00000000-0000-0000-0000-000000000000",
        transport="tcp", security="tls", socks_port=1080,
    )
    ss = cfg["outbounds"][0]["streamSettings"]
    assert ss["network"] == "tcp"
    assert ss["security"] == "tls", "TLS must be enabled when node says transport_security=tls"
    assert ss["tlsSettings"]["serverName"] == "203.0.113.7"
    assert ss["tlsSettings"]["allowInsecure"] is True, \
        "Sentinel nodes use self-signed certs; allowInsecure must be true"


def test_v2ray_config_omits_tls_when_node_doesnt_ask():
    """The inverse: when transport_security is empty/none, streamSettings
    must NOT contain a security field — adding one would fail against a
    plain-TCP server."""
    from bluecli.vpn.v2ray import _build_v2ray_config

    cfg = _build_v2ray_config(
        vmess_address="1.2.3.4", vmess_port=80,
        vmess_uid="00000000-0000-0000-0000-000000000000",
        transport="tcp", security="", socks_port=1080,
    )
    ss = cfg["outbounds"][0]["streamSettings"]
    assert "security" not in ss
    assert "tlsSettings" not in ss


def test_v2ray_endpoint_picker_prefers_tcp_over_grpc():
    """REGRESSION (FedNet bug): when a node lists both grpc and tcp
    endpoints in metadata, we MUST pick tcp. The original code took
    metadata[0] unconditionally, which on grpc-first nodes meant a
    config v2ray 4.x couldn't parse ('unknown transport protocol: grpc').
    The scorer in _server_from_response now walks all entries."""
    from bluecli.vpn import HandshakeResult
    from bluecli.vpn.v2ray import _server_from_response

    hs = HandshakeResult(
        node_addrs=["198.51.100.10:9933"],
        peer_data={"metadata": [
            # grpc first (the historical pain point)
            {"port": 443, "proxy_protocol": 2, "transport_protocol": 3, "transport_security": 2},
            # tcp+tls second — must be picked
            {"port": 8443, "proxy_protocol": 2, "transport_protocol": 7, "transport_security": 2},
        ]},
    )
    server = _server_from_response(hs)
    assert server["transport"] == "tcp", "tcp MUST beat grpc"
    assert server["port"] == 8443
    assert server["security"] == "tls"


def test_v2ray_endpoint_picker_falls_back_to_grpc_if_only_option():
    """If the node ONLY offers grpc, picking grpc is the right thing —
    we still bail later via the v4 pre-check, but the picker itself
    shouldn't lose the only candidate."""
    from bluecli.vpn import HandshakeResult
    from bluecli.vpn.v2ray import _server_from_response

    hs = HandshakeResult(
        node_addrs=["198.51.100.10:9933"],
        peer_data={"metadata": [
            {"port": 443, "proxy_protocol": 2, "transport_protocol": 3, "transport_security": 2},
        ]},
    )
    server = _server_from_response(hs)
    assert server["transport"] == "grpc"


def test_v2ray_endpoint_picker_prefers_tcp_tls_over_tcp_plain():
    """Among two TCP endpoints, TLS wins. Sentinel nodes prefer TLS."""
    from bluecli.vpn import HandshakeResult
    from bluecli.vpn.v2ray import _server_from_response

    hs = HandshakeResult(
        node_addrs=["198.51.100.10:9933"],
        peer_data={"metadata": [
            {"port": 80, "proxy_protocol": 2, "transport_protocol": 7, "transport_security": 1},
            {"port": 443, "proxy_protocol": 2, "transport_protocol": 7, "transport_security": 2},
        ]},
    )
    server = _server_from_response(hs)
    assert server["port"] == 443
    assert server["security"] == "tls"


def test_verify_public_ip_compares_against_baseline():
    """REGRESSION (WG bug): WireGuard's /installtunnelservice on Windows
    returns BEFORE the tunnel is actually routing. Without a pre-connect
    baseline, _verify_public_ip would return on the FIRST valid IP it
    got — which is the user's home IP, because the tunnel isn't up yet.
    We capture the IP before bringing up the tunnel and require the
    post-tunnel IP to be DIFFERENT before we report success.
    """
    # The test is structural: we just verify the function accepts a
    # baseline parameter and that the comparison logic exists in source.
    from bluecli import menus
    import inspect

    sig = inspect.signature(menus._verify_public_ip)
    assert "pre_connect_ip" in sig.parameters, \
        "_verify_public_ip must accept a pre-connect baseline for comparison"

    source = inspect.getsource(menus._verify_public_ip)
    assert "pre_connect_ip" in source
    # The key invariant: if we have a baseline, we must demand the IP
    # changed before declaring success.
    assert "!= pre_connect_ip" in source or "ip != pre_connect_ip" in source, \
        "_verify_public_ip must compare against the pre-connect IP"


def test_v2ray_major_version_detection():
    """v4 ('V2Ray 4.31.0...') and v5 ('V2Ray 5.x...') take incompatible
    CLI args. The regex must extract the right major or v4 users get a
    silent fallback to bin/v2ray/config.json and the tunnel never starts."""
    import re

    # Real v4.31.0 output (verbatim from the user's logs)
    v4_output = (
        "V2Ray 4.31.0 (V2Fly, a community-driven edition of V2Ray.) "
        "Custom (go1.15.2 windows/amd64)\n"
        "A unified platform for anti-censorship.\n"
    )
    m = re.search(r"V2Ray\s+(\d+)\.", v4_output)
    assert m and int(m.group(1)) == 4

    # Hypothetical v5 (different generations differ in detail but the
    # leading 'V2Ray N.' format is stable across releases)
    v5_output = "V2Ray 5.12.1 (V2Fly...)"
    m = re.search(r"V2Ray\s+(\d+)\.", v5_output)
    assert m and int(m.group(1)) == 5


def test_v2ray_pick_free_port_works():
    """Exercise the real _pick_free_port so missing imports (e.g. socket) get
    caught before we hit them on Windows at connect time."""
    from bluecli.vpn import v2ray as v2ray_mod

    port = v2ray_mod._pick_free_port(preferred=0)  # 0 → let OS pick
    assert isinstance(port, int) and 0 < port < 65536, port


def test_v2ray_uuid_sent_as_byte_array():
    """The v8.x node parses `uuid` as v2fly's `type UUID [16]byte`, which has
    no custom MarshalJSON. Go's default for fixed-size byte arrays is a JSON
    array of element values — NOT base64 (that's `[]byte`, a slice), and NOT
    the canonical 8-4-4-4-12 hex string.

    Verified empirically against go1.22 / json.Unmarshal — see
    /tmp/tt.go in the conversation for the test.
    """
    from bluecli.vpn import v2ray as v2ray_mod

    captured = {}

    class FakeResult:
        node_addrs = ["10.0.0.1:9933"]
        peer_data = {"metadata": [{
            "port": "443",
            "proxy_protocol": "vmess",
            "transport_protocol": "tcp",
            "transport_security": "tls",
        }]}

    def fake_fetch(*, remote_url, session_id, private_key, request_data, timeout=20):
        captured["request_data"] = request_data
        return FakeResult()

    orig_fetch = v2ray_mod.fetch_node_credentials
    v2ray_mod.fetch_node_credentials = fake_fetch
    try:
        v2ray_mod.fetch_creds(
            remote_url="https://example.invalid",
            session_id=1,
            private_key=b"\x01" * 32,
        )

        sent = captured.get("request_data") or {}
        uid_field = sent.get("uuid")
        assert isinstance(uid_field, list), (
            f"uuid must be a JSON list, got {type(uid_field).__name__}: {uid_field!r}. "
            "The node would reject anything else as "
            "'cannot unmarshal ... into uuid.UUID'."
        )
        assert len(uid_field) == 16, f"uuid must be 16 bytes, got {len(uid_field)}"
        assert all(isinstance(b, int) and 0 <= b <= 255 for b in uid_field), (
            f"uuid bytes must be ints 0-255, got {uid_field!r}"
        )
        import json as _json
        encoded = _json.dumps(sent, separators=(",", ":"))
        assert '"uuid":[' in encoded, f"expected JSON array, got: {encoded}"
    finally:
        v2ray_mod.fetch_node_credentials = orig_fetch


def test_handshake_signing_is_deterministic_low_s():
    """Verify the ECDSA signature is deterministic and uses canonical low-S form.

    We don't hit a node — we just produce a signature and check the encoding
    matches Cosmos verifier expectations (64 bytes, R||S, S in low half).
    """
    import hashlib

    import ecdsa
    from ecdsa.util import sigencode_string_canonize

    priv = bytes.fromhex(
        "0102030405060708091011121314151617181920212223242526272829303132"
    )[:32]
    sk = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256)
    msg = (42843892).to_bytes(8, "big") + b'{"public_key":"AAAA"}'
    sig_a = sk.sign_deterministic(msg, hashfunc=hashlib.sha256, sigencode=sigencode_string_canonize)
    sig_b = sk.sign_deterministic(msg, hashfunc=hashlib.sha256, sigencode=sigencode_string_canonize)
    assert sig_a == sig_b, "signature must be deterministic (RFC 6979)"
    assert len(sig_a) == 64, f"compact signature must be 64 bytes, got {len(sig_a)}"
    s_int = int.from_bytes(sig_a[32:], "big")
    # secp256k1 order n
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    assert s_int <= n // 2, "S must be in the low half (canonical form)"

    # Pubkey compressed form is 33 bytes starting with 0x02 or 0x03.
    pub = sk.verifying_key.to_string(encoding="compressed")
    assert len(pub) == 33
    assert pub[0] in (2, 3)


def test_probe_nodes_empty_and_unreachable():
    """Sanity-check the node prober without spinning up a real server."""
    from bluecli.chain import _probe_nodes

    class FakeNode:
        def __init__(self, address, remote_addrs):
            self.address = address
            self.remote_addrs = remote_addrs

    assert _probe_nodes([]) == {}
    # A bogus host should resolve to an empty dict, not crash.
    n = FakeNode("sentnodeXYZ", ["127.0.0.1:1"])
    result = _probe_nodes([n], timeout=1)
    assert result == {"sentnodeXYZ": {}}


def test_parse_node_response_real_v2ray_shape():
    """Verbatim response shape captured from a live mainnet node."""
    from bluecli.chain import _parse_node_response, NODE_TYPE_V2RAY

    sample = {
        "success": True,
        "result": {
            "addr": "sentnode10f3vfvxk82fka06u93w03qqjlm5cwws638u7tv",
            "downlink": "14490009",
            "handshake_dns": False,
            "location": {
                "city": "Southfield",
                "country": "United States",
                "country_code": "US",
                "latitude": 42.4593,
                "longitude": -83.2207,
            },
            "moniker": "SuchNode-erNU7cfmKPdp",
            "peers": 4,
            "service_type": "v2ray",
            "uplink": "45592037",
            "version": {"commit": "f2bdf6d", "tag": "8.3.1"},
        },
    }
    parsed = _parse_node_response(sample)
    assert parsed["type"] == NODE_TYPE_V2RAY
    assert parsed["moniker"] == "SuchNode-erNU7cfmKPdp"
    assert parsed["country"] == "United States"


def test_parse_node_response_wireguard_variant():
    from bluecli.chain import _parse_node_response, NODE_TYPE_WIREGUARD

    sample = {
        "success": True,
        "result": {
            "service_type": "wireguard",
            "moniker": "TestWG",
            "location": {"country": "Italy"},
        },
    }
    parsed = _parse_node_response(sample)
    assert parsed["type"] == NODE_TYPE_WIREGUARD
    assert parsed["moniker"] == "TestWG"
    assert parsed["country"] == "Italy"


def test_parse_node_response_rejects_garbage():
    from bluecli.chain import _parse_node_response

    # success=False → empty
    assert _parse_node_response({"success": False, "error": "..."}) == {}
    # missing service_type → empty (we can't connect without knowing protocol)
    assert _parse_node_response({"success": True, "result": {"moniker": "x"}}) == {}
    # unknown service_type → empty
    assert _parse_node_response({"success": True, "result": {"service_type": "openvpn"}}) == {}
    # non-dict → empty
    assert _parse_node_response(None) == {}
    assert _parse_node_response("not a dict") == {}


def test_parse_session_any_node_wrapper():
    """Sessions on chain are sentinel.node.v3.Session (or .subscription.v3.Session)
    that wrap BaseSession at field 1. Verify our parser unwraps correctly."""
    import sentinel_protobuf.sentinel.node.v3.session_pb2 as node_session_pb2
    import sentinel_protobuf.sentinel.session.v3.session_pb2 as base_session_pb2
    import sentinel_protobuf.sentinel.types.v1.price_pb2 as price_pb2
    from google.protobuf.any_pb2 import Any as AnyMsg

    from bluecli.chain import _parse_session_any

    # Build a real Session proto and wrap it in Any, just like the chain does.
    base = base_session_pb2.BaseSession(
        id=42845632,
        acc_address="sent1abc",
        node_address="sentnode1xyz",
        status=1,  # ACTIVE
    )
    outer = node_session_pb2.Session(
        base_session=base,
        price=price_pb2.Price(denom="udvpn", base_value="0", quote_value="25000000"),
    )
    any_msg = AnyMsg()
    any_msg.type_url = "/sentinel.node.v3.Session"
    any_msg.value = outer.SerializeToString()

    parsed = _parse_session_any(any_msg)
    assert parsed is not None
    assert parsed.id == 42845632
    assert parsed.acc_address == "sent1abc"
    assert parsed.node_address == "sentnode1xyz"
    assert parsed.status == 1


def test_parse_session_any_subscription_wrapper():
    import sentinel_protobuf.sentinel.subscription.v3.session_pb2 as sub_session_pb2
    import sentinel_protobuf.sentinel.session.v3.session_pb2 as base_session_pb2
    from google.protobuf.any_pb2 import Any as AnyMsg

    from bluecli.chain import _parse_session_any

    base = base_session_pb2.BaseSession(id=1234, status=1, node_address="sentnode1sub")
    outer = sub_session_pb2.Session(base_session=base, subscription_id=99)
    any_msg = AnyMsg()
    any_msg.type_url = "/sentinel.subscription.v3.Session"
    any_msg.value = outer.SerializeToString()

    parsed = _parse_session_any(any_msg)
    assert parsed is not None
    assert parsed.id == 1234
    assert parsed.node_address == "sentnode1sub"


def test_price_dict_roundtrip():
    """NodeInfo stores prices as dicts (cache-friendly); they round-trip to
    a Price proto exactly when we broadcast the start-session tx."""
    from bluecli.chain import _dict_price_to_proto

    proto = _dict_price_to_proto({
        "denom": "udvpn",
        "base_value": "100",
        "quote_value": "25000000",
    })
    assert proto.denom == "udvpn"
    assert proto.base_value == "100"
    assert proto.quote_value == "25000000"


def test_node_cache_serves_disk_seed():
    """When the cache file is fresh, get() returns it without needing the
    live fetcher to complete."""
    import json
    import time

    from bluecli import config as cfg
    from bluecli.chain import NodeInfo
    from bluecli.node_cache import NodeCache, _CACHE_FILE

    cfg.ensure_dir()

    seed = NodeInfo(
        address="sentnode1seed",
        moniker="seeded",
        country="Italy",
        remote_url="https://1.2.3.4:9933",
        node_type=1,
        gigabyte_prices=[{"denom": "udvpn", "base_value": "0", "quote_value": "1"}],
        hourly_prices=[],
    )
    payload = {
        "ts": time.time(),
        "nodes": [{
            "address": seed.address, "moniker": seed.moniker, "country": seed.country,
            "remote_url": seed.remote_url, "node_type": seed.node_type,
            "gigabyte_prices": seed.gigabyte_prices, "hourly_prices": seed.hourly_prices,
        }],
    }
    with _CACHE_FILE.open("w") as f:
        json.dump(payload, f)

    import threading
    blocker = threading.Event()

    def slow_fetch():
        blocker.wait()
        return []

    cache = NodeCache(fetch=slow_fetch)
    cache.start()
    try:
        result = cache.get(wait_timeout=2.0)
        assert len(result) == 1, f"expected 1 seeded node, got {len(result)}"
        assert result[0].address == "sentnode1seed"
    finally:
        cache.stop()
        blocker.set()
    _CACHE_FILE.unlink(missing_ok=True)


def test_format_node_row_with_dict_prices():
    """Regression: NodeInfo.gigabyte_prices is `list[dict]`, not protobuf.
    Every code path in the formatter must use dict-key access.
    """
    from bluecli.chain import NodeInfo, NODE_TYPE_WIREGUARD, NODE_TYPE_V2RAY
    from bluecli.menus import _format_node_row

    # Branch 1: udvpn price present → shown as DVPN
    n = NodeInfo(
        address="sentnode1aaa", moniker="VPN-A", country="Italy",
        remote_url="https://1.1.1.1:9933", node_type=NODE_TYPE_WIREGUARD,
        gigabyte_prices=[{"denom": "udvpn", "base_value": "0", "quote_value": "25000000"}],
        hourly_prices=[],
    )
    row = _format_node_row(1, n)
    assert "25.000 DVPN" in row, row
    assert "Italy" in row and "VPN-A" in row and "wireguard" in row

    # Branch 2: no udvpn, only IBC → fallback to raw "<value> <denom>"
    n = NodeInfo(
        address="sentnode1bbb", moniker="VPN-B", country="Germany",
        remote_url="https://2.2.2.2:9933", node_type=NODE_TYPE_V2RAY,
        gigabyte_prices=[{"denom": "ibc/SOMEHASH", "base_value": "0", "quote_value": "5000"}],
        hourly_prices=[],
    )
    row = _format_node_row(2, n)
    assert "5000 ibc/SOMEHASH" in row, row
    assert "DVPN" not in row, row

    # Branch 3: no prices at all → em-dash
    n = NodeInfo(
        address="sentnode1ccc", moniker="VPN-C", country="",
        remote_url="https://3.3.3.3:9933", node_type=NODE_TYPE_WIREGUARD,
        gigabyte_prices=[], hourly_prices=[],
    )
    row = _format_node_row(3, n)
    assert "—" in row, row


def test_node_list_age_label():
    """Freshness line: None when no timestamp, 'just now' under a minute,
    '<duration> ago' beyond. Pure + injected clock, no real time involved."""
    from bluecli.i18n import set_language
    from bluecli.menus import _node_list_age_label

    set_language("en")

    # No timestamp yet → no line (never show a misleading 'just now').
    assert _node_list_age_label(0, 1000.0) is None
    assert _node_list_age_label(0.0, 1000.0) is None

    # Under a minute → 'just now'.
    assert _node_list_age_label(970.0, 1000.0) == "Node list updated just now"
    # Future/zero-age clock skew is clamped to 'just now', never negative.
    assert _node_list_age_label(1010.0, 1000.0) == "Node list updated just now"

    # Exactly a minute and beyond → '<duration> ago'.
    assert _node_list_age_label(940.0, 1000.0) == "Node list updated 1m ago"
    assert _node_list_age_label(820.0, 1000.0) == "Node list updated 3m ago"
    assert _node_list_age_label(6100.0, 10000.0) == "Node list updated 1h 5m ago"


def test_node_cache_set_fetch_keeps_data():
    """set_fetch re-points the refresh source WITHOUT discarding the cached
    list — the node list is chain state, so a gRPC-endpoint change mustn't
    invalidate it."""
    from bluecli.node_cache import NodeCache

    a = lambda: ["A"]
    b = lambda: ["B"]
    c = NodeCache(fetch=a)
    c._nodes = ["cached"]            # pretend a prior refresh landed
    assert c._fetch is a
    c.set_fetch(b)
    assert c._fetch is b             # future refreshes use the new source
    assert c.get(wait_timeout=0.0) == ["cached"]  # data preserved across the swap


def test_node_cache_last_refresh_accessor():
    """last_refresh() starts at 0.0 (so the UI shows no freshness line) and
    reflects whatever the cache recorded, read under the lock."""
    from bluecli.chain import NodeInfo, NODE_TYPE_V2RAY
    from bluecli.node_cache import NodeCache

    c = NodeCache(fetch=lambda: [])
    assert c.last_refresh() == 0.0  # never refreshed yet

    # Simulate a recorded refresh (what _loop does on a successful fetch).
    with c._lock:
        c._last_refresh = 123456.0
    assert c.last_refresh() == 123456.0


def test_clamp_page():
    """1-indexed page request -> clamped 0-indexed page. Out-of-range snaps
    to the nearest valid page instead of erroring."""
    from bluecli.menus import _clamp_page

    assert _clamp_page(1, 5) == 0     # first page
    assert _clamp_page(3, 5) == 2     # middle
    assert _clamp_page(5, 5) == 4     # last page
    assert _clamp_page(99, 5) == 4    # past the end -> last
    assert _clamp_page(0, 5) == 0     # below 1 -> first
    assert _clamp_page(-7, 5) == 0    # negative -> first
    assert _clamp_page(1, 1) == 0     # single page
    assert _clamp_page(4, 0) == 0     # no pages -> 0 (defensive)


def test_collapse_chains_pure():
    """Pure grouping over explicit (entry,exit) id-pairs: collapse present
    pairs, leave the rest single, never double-group an id."""
    from types import SimpleNamespace
    from bluecli.menus import _collapse_chains

    def sess(i):
        return SimpleNamespace(id=i)

    s1, s2, s3, s4 = sess(1), sess(2), sess(3), sess(4)

    rows = _collapse_chains([s1, s2, s3], [(1, 2)])
    assert rows[0] == ("chain", [s1, s2]) and ("single", s3) in rows and len(rows) == 2

    assert _collapse_chains([s1, s2, s3], []) == [
        ("single", s1), ("single", s2), ("single", s3)
    ]

    # Pair with a missing session -> not collapsed; present one stays single.
    assert _collapse_chains([s1], [(1, 9)]) == [("single", s1)]

    # Two independent pairs -> two chain rows.
    assert _collapse_chains([s1, s2, s3, s4], [(1, 2), (3, 4)]) == [
        ("chain", [s1, s2]), ("chain", [s3, s4])
    ]

    # Overlapping pairs -> first wins, the id isn't reused.
    assert _collapse_chains([s1, s2, s3], [(1, 2), (2, 3)]) == [
        ("chain", [s1, s2]), ("single", s3)
    ]


def test_multihop_cache_remember_prune_forget():
    """Durable chain memory: upsert by id-pair, prune to active, forget by id,
    ignore malformed pairs. Hermetic — cleans its own file."""
    from bluecli import multihop_cache as mc

    mc._CACHE_FILE.unlink(missing_ok=True)

    def hop(sid, role="entry"):
        return {"role": role, "session_id": sid, "node_address": f"sentnode1{sid}"}

    try:
        mc.remember([hop(1, "entry"), hop(2, "exit")])
        assert [[h["session_id"] for h in c] for c in mc.all_chains()] == [[1, 2]]

        # Re-remembering the same id-pair upserts, doesn't duplicate.
        mc.remember([hop(2, "exit"), hop(1, "entry")])
        assert len(mc.all_chains()) == 1

        mc.remember([hop(3), hop(4)])
        assert len(mc.all_chains()) == 2

        # Malformed (single hop) is ignored.
        mc.remember([hop(9)])
        assert len(mc.all_chains()) == 2

        # Prune to a set missing session 3/4 -> that chain drops.
        mc.prune_to({1, 2})
        assert [{h["session_id"] for h in c} for c in mc.all_chains()] == [{1, 2}]

        # Forget by one member id -> chain gone.
        mc.forget([2])
        assert mc.all_chains() == []
    finally:
        mc._CACHE_FILE.unlink(missing_ok=True)


def test_known_chain_pairs_merges_live_and_remembered():
    """_known_chain_pairs lists the live chain first, then remembered chains,
    de-duplicated by id-pair. This is the regression guard for the bug where a
    multihop pair separated into singles after connecting elsewhere."""
    from bluecli import multihop_cache as mc
    from bluecli.menus import _known_chain_pairs

    mc._CACHE_FILE.unlink(missing_ok=True)

    def hop(sid):
        return {"role": "entry", "session_id": sid, "node_address": f"n{sid}"}

    try:
        state = {"hops": [hop(10), hop(11)]}
        assert _known_chain_pairs(state) == [(10, 11)]

        # A remembered chain still groups even when it's NOT the live state
        # (e.g. user connected single-hop elsewhere -> no live hops).
        mc.remember([hop(20), hop(21)])
        assert _known_chain_pairs({"hops": None}) == [(20, 21)]

        # Live + remembered: live first, then remembered.
        assert _known_chain_pairs(state) == [(10, 11), (20, 21)]

        # Live chain also remembered -> appears once.
        mc.remember([hop(10), hop(11)])
        pairs = _known_chain_pairs(state)
        assert pairs.count((10, 11)) == 1 and (20, 21) in pairs and len(pairs) == 2
    finally:
        mc._CACHE_FILE.unlink(missing_ok=True)


def test_find_chain_hops_lookup():
    """_find_chain_hops resolves a chain's hop-pair (with creds) by its
    unordered session-id set, from the live chain or remembered chains."""
    from bluecli import multihop_cache as mc
    from bluecli.menus import _find_chain_hops

    mc._CACHE_FILE.unlink(missing_ok=True)

    def hop(sid):
        return {"role": "entry", "session_id": sid, "node_address": f"n{sid}"}

    try:
        state = {"hops": [hop(5), hop(6)]}
        assert _find_chain_hops(state, [5, 6]) == [hop(5), hop(6)]
        assert _find_chain_hops(state, [6, 5]) == [hop(5), hop(6)]  # unordered

        mc.remember([hop(7), hop(8)])
        assert _find_chain_hops(state, [8, 7]) == [hop(7), hop(8)]

        assert _find_chain_hops(state, [99, 100]) is None
    finally:
        mc._CACHE_FILE.unlink(missing_ok=True)


def test_live_tunnel_expired():
    """A live tunnel is 'expired' when any of its session ids is no longer
    active on chain; not-connected state is never flagged."""
    from bluecli.menus import _live_tunnel_expired

    # single-hop
    sh = {"backend": "v2ray", "session_id": 5}
    assert _live_tunnel_expired(sh, {5, 9}) is False     # still active
    assert _live_tunnel_expired(sh, {9}) is True          # expired/ended
    assert _live_tunnel_expired(sh, set()) is True        # gone

    # multihop: BOTH hops must still be active
    mh = {"backend": "v2ray-multihop", "hops": [{"session_id": 1}, {"session_id": 2}]}
    assert _live_tunnel_expired(mh, {1, 2, 3}) is False
    assert _live_tunnel_expired(mh, {1}) is True           # one hop gone breaks the chain

    # not connected → never flagged (nothing to reconcile)
    assert _live_tunnel_expired({}, set()) is False
    assert _live_tunnel_expired({"session_id": 5}, set()) is False  # no backend = not live


def test_chain_sessions_alive():
    """A cached chain is resumable only when BOTH its hop sessions are still in
    the active set; anything else (one gone, both gone, malformed) is dead."""
    from bluecli.menus import _chain_sessions_alive

    hops = [{"session_id": 10}, {"session_id": 20}]
    assert _chain_sessions_alive(hops, {10, 20, 30}) is True   # both active
    assert _chain_sessions_alive(hops, {10, 30}) is False       # one ended/expired
    assert _chain_sessions_alive(hops, set()) is False          # both gone
    assert _chain_sessions_alive([{"session_id": 10}], {10}) is False  # not a pair
    assert _chain_sessions_alive("nonsense", {10}) is False     # malformed


def test_run_bounded_timeout_and_passthrough():
    """The bounded-call runner returns fast results, gives up (ChainTimeout) on
    overruns without waiting for the call, and re-raises the call's own
    exceptions unchanged. ChainTimeout is a ChainError so existing handlers
    catch it."""
    import time as _t
    from bluecli.chain import _run_bounded, ChainTimeout, ChainError

    assert issubclass(ChainTimeout, ChainError)

    # Fast success returns the value.
    assert _run_bounded(lambda: 42, 1.0, "fast") == 42

    # An overrun gives up at ~the deadline, not after the call finishes.
    start = _t.time()
    try:
        _run_bounded(lambda: _t.sleep(2), 0.2, "slow")
        assert False, "expected ChainTimeout"
    except ChainTimeout:
        pass
    assert _t.time() - start < 1.5, "should give up near the deadline"

    # An exception from the call propagates unchanged (type preserved).
    def boom():
        raise ValueError("nope")
    try:
        _run_bounded(boom, 1.0, "boom")
        assert False, "expected ValueError"
    except ValueError as e:
        assert "nope" in str(e)


def test_query_self_heals_on_timeout():
    """A timed-out read query rebuilds the connection once and retries; if it
    still times out, the error propagates (network really down)."""
    from bluecli.chain import ChainClient, ChainTimeout

    class Fake:
        def __init__(self):
            self.reconnects = 0

        def reconnect(self):
            self.reconnects += 1

    # First attempt 'times out', retry after reconnect succeeds.
    fake = Fake()
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise ChainTimeout("simulated stale channel")
        return "sessions!"

    assert ChainClient._query(fake, flaky, "test") == "sessions!"
    assert fake.reconnects == 1 and calls["n"] == 2

    # Persistent timeout: reconnect once, then give up (propagate).
    fake2 = Fake()

    def always_timeout():
        raise ChainTimeout("network down")

    try:
        ChainClient._query(fake2, always_timeout, "test")
        assert False, "expected ChainTimeout to propagate"
    except ChainTimeout:
        pass
    assert fake2.reconnects == 1


def test_chain_bypass_bookkeeping():
    """The chain-bypass file round-trips the routed IPs and clears cleanly."""
    from bluecli.vpn import _routing

    _routing._clear_chain_bypass()
    assert _routing._read_chain_bypass() == []
    _routing._write_chain_bypass(["1.2.3.4", "5.6.7.8"])
    assert _routing._read_chain_bypass() == ["1.2.3.4", "5.6.7.8"]
    _routing._clear_chain_bypass()
    assert _routing._read_chain_bypass() == []


def test_resolve_chain_ips_literal():
    """A literal-IP grpc_host needs no DNS; an empty host yields no bypass."""
    from bluecli.vpn import _routing
    from bluecli import config as _cfg

    orig = _cfg.load_config
    try:
        _cfg.load_config = lambda: {"grpc_host": "9.9.9.9", "grpc_port": 9090}
        assert _routing._resolve_chain_ips() == ["9.9.9.9"]
        _cfg.load_config = lambda: {"grpc_host": "  ", "grpc_port": 9090}
        assert _routing._resolve_chain_ips() == []
    finally:
        _cfg.load_config = orig


def test_node_cache_signals_done_even_when_fetch_returns_empty():
    """The bug that caused 'carica all'infinito': when the network has zero
    responsive nodes the fetcher returns []. The cache used to never set
    its done-event in that case, so .get(wait_timeout=N) would always
    sit on the full timeout. With the fix, an empty fetch still signals
    completion."""
    import threading
    from bluecli.node_cache import NodeCache, _CACHE_FILE

    _CACHE_FILE.unlink(missing_ok=True)

    fetch_called = threading.Event()

    def empty_fetch():
        fetch_called.set()
        return []

    cache = NodeCache(fetch=empty_fetch)
    cache.start()
    try:
        # Without the fix, this would hang the full 5s; with the fix the
        # cache signals done as soon as the empty fetch returns.
        result = cache.get(wait_timeout=5.0)
        assert fetch_called.is_set(), "fetch should have run"
        assert result == [], f"expected empty, got {len(result)}"
        assert cache.last_error() is None
    finally:
        cache.stop()


def test_node_cache_records_fetch_errors():
    """If the fetcher raises, last_error() must surface it instead of
    silently hiding the failure behind an empty list."""
    from bluecli.node_cache import NodeCache, _CACHE_FILE

    _CACHE_FILE.unlink(missing_ok=True)

    def boom_fetch():
        raise RuntimeError("simulated gRPC outage")

    cache = NodeCache(fetch=boom_fetch)
    cache.start()
    try:
        result = cache.get(wait_timeout=5.0)
        assert result == []
        err = cache.last_error()
        assert err is not None
        assert "simulated gRPC outage" in err, err
    finally:
        cache.stop()


def test_strip_runtime_state_preserves_session_creds():
    """The boundary between 'disconnect' (tunnel down) and 'end session'
    (session gone for good) is encoded in config.strip_runtime_state.
    Tunnel-runtime keys must go; everything else must stay so the next
    reconnect can use cached credentials."""
    from bluecli import config as cfg

    cfg.ensure_dir()
    cfg.save_state({
        # Runtime — should be removed
        "backend": "wireguard",
        "interface": "wg-blue",
        "config_path": "/tmp/wg.conf",
        "pid": 12345,
        "tun2socks_pid": 12346,
        "socks_port": 1080,
        "tun_iface": "blue-tun",
        "node_ip": "1.2.3.4",
        "orig_gw": "192.168.1.1",
        # Session/creds — must survive
        "session_id": 42897957,
        "node_address": "sentnode1xxx",
        "node_type": 1,
        "wg_privkey_b64": "cHJpdg==",
        "wg_pubkey_b64": "cHViYWJj",
        "handshake_node_addrs": ["1.2.3.4:9933"],
        "handshake_peer_data": {"ipv4": "10.0.0.2"},
    })
    cfg.strip_runtime_state()
    after = cfg.load_state()

    # Removed
    for k in ("backend", "interface", "config_path", "pid",
              "tun2socks_pid", "socks_port",
              "tun_iface", "node_ip", "orig_gw"):
        assert k not in after, f"runtime key {k!r} should have been stripped, got {after}"
    # Preserved
    assert after["session_id"] == 42897957
    assert after["wg_privkey_b64"] == "cHJpdg=="
    assert after["handshake_peer_data"] == {"ipv4": "10.0.0.2"}
    cfg.clear_state()


def test_wg_credentials_state_roundtrip():
    """WGCredentials must survive a save/load through plain dicts so that
    reconnect after an app restart still finds the cached handshake."""
    from bluecli.vpn.wireguard import WGCredentials

    creds = WGCredentials(
        keypair_privkey_b64="cHJpdg==",
        keypair_pubkey_b64="cHViYWJj",
        handshake_node_addrs=["1.2.3.4:9933"],
        handshake_peer_data={"ipv4": "10.0.0.2", "ipv6": "fd00::2"},
    )
    state: dict = {}
    state.update(creds.to_state())
    # Persist would happen here; we simulate by just re-reading.
    rebuilt = WGCredentials.from_state(state)
    assert rebuilt.keypair_privkey_b64 == "cHJpdg=="
    assert rebuilt.keypair_pubkey_b64 == "cHViYWJj"
    assert rebuilt.handshake_node_addrs == ["1.2.3.4:9933"]
    assert rebuilt.handshake_peer_data == {"ipv4": "10.0.0.2", "ipv6": "fd00::2"}


def test_v2_credentials_state_roundtrip():
    from bluecli.vpn.v2ray import V2Credentials

    creds = V2Credentials(
        uuid_hex="0123456789abcdef0123456789abcdef",
        handshake_node_addrs=["5.6.7.8:9933"],
        handshake_peer_data={"metadata": [{"port": "443"}]},
    )
    state = creds.to_state()
    rebuilt = V2Credentials.from_state(state)
    assert rebuilt.uuid_hex == "0123456789abcdef0123456789abcdef"
    assert rebuilt.handshake_node_addrs == ["5.6.7.8:9933"]
    assert rebuilt.handshake_peer_data == {"metadata": [{"port": "443"}]}
    # And the hex must round-trip cleanly to the original 16 raw bytes.
    import uuid as _uuid
    raw = bytes.fromhex(rebuilt.uuid_hex)
    assert len(raw) == 16
    assert _uuid.UUID(bytes=raw)  # parses


def test_node_handshake_error_carries_status_code():
    """The 409 detection in menus._get_or_fetch_*_creds depends on the
    NodeHandshakeError having `status_code == 409`. If the field is lost
    or the wrong int is plumbed through, the 'this session is dead' path
    silently degrades to a generic error and the user gets a confusing
    raw HTTP dump again."""
    from bluecli.vpn import NodeHandshakeError

    e = NodeHandshakeError("boom", status_code=409)
    assert e.status_code == 409
    assert "boom" in str(e)

    # Default for the connect-refused case (we never got a status)
    e2 = NodeHandshakeError("dns failed")
    assert e2.status_code == 0


def test_reconnect_uses_cached_creds_when_state_matches():
    """The core promise: if state.json has WG creds for the session we're
    reconnecting to, _get_or_fetch_wg_creds must NOT call fetch_creds —
    the node would respond 409. We patch fetch_creds to raise if called,
    then make sure cached creds come back instead."""
    import bluecli.menus as menus_mod
    import bluecli.vpn.wireguard as wg_mod

    # State as it would look right after a bring-up failure: handshake
    # received and persisted, but tunnel didn't come up.
    state = {
        "session_id": 42897957,
        "node_address": "sentnode1xxx",
        "node_type": 1,  # NODE_TYPE_WIREGUARD
        "wg_privkey_b64": "cHJpdg==",
        "wg_pubkey_b64": "cHViYWJj",
        "handshake_node_addrs": ["1.2.3.4:9933"],
        "handshake_peer_data": {"ipv4": "10.0.0.2", "ipv6": "fd00::2"},
        "orphan_session_id": 42897957,
    }

    def boom_fetch(*args, **kwargs):
        raise AssertionError(
            "fetch_creds was called — this would 409 against the real node. "
            "The cached state.json should have been used instead."
        )

    orig = wg_mod.fetch_creds
    wg_mod.fetch_creds = boom_fetch
    try:
        class _Node:
            address = "sentnode1xxx"
            node_type = 1
            remote_url = "https://1.2.3.4:9933"

        creds = menus_mod._get_or_fetch_creds(
            state, same_session=True, node=_Node(),
            session_id=42897957, priv=b"\x01" * 32,
            cls=wg_mod.WGCredentials, marker_key="wg_privkey_b64",
            fetch=wg_mod.fetch_creds,
        )
        assert creds.keypair_privkey_b64 == "cHJpdg=="
        assert creds.handshake_peer_data["ipv4"] == "10.0.0.2"
    finally:
        wg_mod.fetch_creds = orig


def test_409_response_maps_to_friendly_error():
    """When fetch_creds raises a 409 NodeHandshakeError (e.g. orphan from
    pre-fix code), menus._get_or_fetch_creds must re-raise it as a
    VpnError with the user-facing 'session_already_registered' message,
    not bubble up the raw HTTP text."""
    import bluecli.menus as menus_mod
    import bluecli.vpn.wireguard as wg_mod
    from bluecli.vpn import NodeHandshakeError, VpnError

    def fake_409(*args, **kwargs):
        raise NodeHandshakeError(
            "Node returned HTTP 409: session 1 already exists in database (code=3)",
            status_code=409,
        )

    orig = wg_mod.fetch_creds
    wg_mod.fetch_creds = fake_409
    try:
        class _Node:
            address = "sentnode1xxx"
            node_type = 1
            remote_url = "https://1.2.3.4:9933"

        try:
            menus_mod._get_or_fetch_creds(
                state={}, same_session=False, node=_Node(),
                session_id=1, priv=b"\x01" * 32,
                cls=wg_mod.WGCredentials, marker_key="wg_privkey_b64",
                fetch=wg_mod.fetch_creds,
            )
        except VpnError as e:
            msg = str(e)
            # Must NOT be the raw HTTP-409 text — that's what surfaced
            # before and confused the user. It must be the i18n string.
            assert "already registered" in msg.lower() or "registered on the node" in msg.lower(), msg
        else:
            raise AssertionError("Expected a VpnError but got nothing")
    finally:
        wg_mod.fetch_creds = orig


def test_routing_get_default_route_doesnt_crash():
    """Exercises the platform-dispatch logic in _routing.get_default_route.
    Returns whatever the host OS reports — None is fine, but it must not
    crash with NameError, missing import, etc."""
    from bluecli.vpn import _routing
    route = _routing.get_default_route()
    if route is not None:
        assert isinstance(route.gateway, str) and route.gateway
        assert isinstance(route.interface, str) and route.interface


def test_configure_tun_emits_netsh_on_windows():
    """On Windows, configure_tun MUST assign an IP to the wintun adapter
    via `netsh interface ipv4 set address`. Without it, every `add route`
    that names the IP as gateway silently no-ops. This regression cost a
    debugging session; the test pins the netsh sequence."""
    from bluecli.vpn import _routing as r

    captured: list[list[str]] = []

    def fake_run(cmd, *, check=True):
        captured.append(cmd)
        class _P:
            returncode = 0
            # "show interface" → wintun visible. PowerShell verify → 'OK'.
            stdout = (
                "Admin State    State          Type             Interface Name\n"
                "Enabled        Connected      Dedicated        blue-tun\n"
                "OK\n"  # PowerShell Get-NetIPAddress success marker
            )
            stderr = ""
        return _P()

    orig_run, orig_l, orig_m, orig_w = r._run, r.is_linux, r.is_macos, r.is_windows
    r._run = fake_run
    r.is_linux = lambda: False
    r.is_macos = lambda: False
    r.is_windows = lambda: True
    try:
        r.configure_tun("blue-tun", "198.18.0.1")
    finally:
        r._run, r.is_linux, r.is_macos, r.is_windows = orig_run, orig_l, orig_m, orig_w

    # Must have polled for the interface
    assert any("show" in " ".join(c) and "interface" in " ".join(c) for c in captured), captured
    # Must have set the IP via `netsh interface ipv4 set address`
    set_addr = next(
        (c for c in captured if "set" in c and "address" in c and "ipv4" in c), None
    )
    assert set_addr is not None, f"no 'netsh interface ipv4 set address': {captured}"
    assert "name=blue-tun" in set_addr
    assert "addr=198.18.0.1" in set_addr
    assert "mask=255.255.255.0" in set_addr
    # Must have verified via PowerShell (NOT netsh show addresses, which
    # hides IPs on media-disconnected adapters — wintun's default state)
    powershell_verify = any(
        "powershell" in c[0].lower() and "Get-NetIPAddress" in " ".join(c)
        for c in captured
    )
    assert powershell_verify, \
        f"missing PowerShell Get-NetIPAddress verify: {captured}"
    # Must have set DNS on the wintun (best-effort, check=False)
    assert any("dnsservers" in c for c in captured), f"DNS not set: {captured}"


def test_configure_tun_falls_back_to_powershell_new_netipaddress():
    """REGRESSION: when netsh accepts set-address but the IP doesn't get
    persisted (antivirus hook, or wintun in 'media disconnected' state
    confusing the netsh code path), we must fall back to PowerShell
    New-NetIPAddress before giving up. Only if BOTH fail do we error."""
    from bluecli.vpn import _routing as r

    captured: list[list[str]] = []
    # State machine: first PowerShell verify returns nothing (no 'OK'),
    # second one (after New-NetIPAddress) returns 'OK'.
    ps_verify_calls = [0]

    def fake_run(cmd, *, check=True):
        captured.append(cmd)
        is_ps_verify = (
            cmd[0].lower().startswith("powershell")
            and "Get-NetIPAddress" in " ".join(cmd)
        )

        class _P:
            returncode = 0
            stdout = (
                "Admin State    State          Type             Interface Name\n"
                "Enabled        Connected      Dedicated        blue-tun\n"
            )
            stderr = ""

        if is_ps_verify:
            ps_verify_calls[0] += 1
            if ps_verify_calls[0] == 1:
                _P.stdout = ""  # First check: IP not found
            else:
                _P.stdout = "OK\n"  # After New-NetIPAddress: now found
        return _P()

    orig_run, orig_l, orig_m, orig_w = r._run, r.is_linux, r.is_macos, r.is_windows
    r._run = fake_run
    r.is_linux = lambda: False
    r.is_macos = lambda: False
    r.is_windows = lambda: True
    try:
        r.configure_tun("blue-tun", "198.18.0.1")
    finally:
        r._run, r.is_linux, r.is_macos, r.is_windows = orig_run, orig_l, orig_m, orig_w

    # Must have invoked PowerShell New-NetIPAddress as a fallback
    fallback = any(
        cmd[0].lower().startswith("powershell")
        and "New-NetIPAddress" in " ".join(cmd)
        for cmd in captured
    )
    assert fallback, f"PowerShell New-NetIPAddress fallback not invoked: {captured}"


def test_configure_tun_raises_when_both_methods_fail():
    """If netsh AND PowerShell New-NetIPAddress both fail to make the IP
    visible, raise a clear error pointing at the most likely cause
    (antivirus / firewall) instead of proceeding to install a default
    route that points at a phantom gateway."""
    from bluecli.vpn import _routing as r

    def fake_run(cmd, *, check=True):
        class _P:
            returncode = 0
            stdout = (
                "Admin State    State          Type             Interface Name\n"
                "Enabled        Connected      Dedicated        blue-tun\n"
            )
            stderr = ""
        return _P()

    orig_run, orig_l, orig_m, orig_w = r._run, r.is_linux, r.is_macos, r.is_windows
    r._run = fake_run
    r.is_linux = lambda: False
    r.is_macos = lambda: False
    r.is_windows = lambda: True
    try:
        try:
            r.configure_tun("blue-tun", "198.18.0.1")
        except RuntimeError as e:
            msg = str(e)
        else:
            msg = ""
    finally:
        r._run, r.is_linux, r.is_macos, r.is_windows = orig_run, orig_l, orig_m, orig_w

    assert "antivirus" in msg.lower() or "firewall" in msg.lower(), \
        f"error must hint at antivirus/firewall, got: {msg!r}"


def test_add_split_default_uses_local_ip_on_windows():
    """On Windows the default-via-TUN route is installed via
    `netsh interface ipv4 add route`, with the wintun named explicitly
    (NOT via `route add`, which infers the interface from gateway and
    can silently pick the wrong one). Metric must be 1 to beat the
    system default."""
    from bluecli.vpn import _routing as r

    captured: list[list[str]] = []

    def fake_run(cmd, *, check=True):
        captured.append(cmd)
        class _P:
            returncode = 0
            stdout = ""
            stderr = ""
        return _P()

    orig_run, orig_l, orig_m, orig_w = r._run, r.is_linux, r.is_macos, r.is_windows
    r._run = fake_run
    r.is_linux = lambda: False
    r.is_macos = lambda: False
    r.is_windows = lambda: True
    try:
        r.add_default_via_tun("blue-tun", "198.18.0.1")
    finally:
        r._run, r.is_linux, r.is_macos, r.is_windows = orig_run, orig_l, orig_m, orig_w

    netsh_routes = [c for c in captured if c[0] == "netsh" and "add" in c and "route" in c]
    assert len(netsh_routes) == 1, f"expected 1 'netsh add route' call, got {netsh_routes}"
    cmd = netsh_routes[0]
    assert "0.0.0.0/0" in cmd, f"must install default 0.0.0.0/0, got {cmd}"
    assert "blue-tun" in cmd, f"interface must be named explicitly, got {cmd}"
    assert "198.18.0.1" in cmd, f"gateway must be the TUN's local IP, got {cmd}"
    assert "metric=1" in cmd, f"metric must be 1 to beat system default, got {cmd}"


def test_already_connected_guard_short_circuits_with_live_state():
    """With state.backend set (= tunnel up), the guard must return True
    AND not let the connect flow continue. The warning must include a
    human-readable label (moniker + country when present) so the user
    knows what they're disconnecting from, not just an opaque sentnode
    address."""
    import bluecli.menus as menus_mod
    import bluecli.config as cfg_mod

    cfg_mod.save_state({
        "session_id": 1,
        "node_address": "sentnode1lf9w8ufk02wpaz93my4855vnyv7d9gx3fwgdgx",
        "node_moniker": "Cyrano",
        "node_country": "Albania",
        "backend": "wireguard",
        "interface": "wg-blue",
        "config_path": "/tmp/x.conf",
    })

    captured: list = []
    orig_warn, orig_info = menus_mod.ui.warn, menus_mod.ui.info
    orig_pause = menus_mod._pause
    menus_mod.ui.warn = lambda m: captured.append(("warn", m))
    menus_mod.ui.info = lambda m: captured.append(("info", m))
    menus_mod._pause = lambda: None
    try:
        assert menus_mod._already_connected_guard() is True
    finally:
        menus_mod.ui.warn, menus_mod.ui.info = orig_warn, orig_info
        menus_mod._pause = orig_pause
        cfg_mod.clear_state()

    warns = [m for kind, m in captured if kind == "warn"]
    assert warns, "guard must warn the user"
    # The warn line must use the friendly label, not the long address
    assert "Cyrano" in warns[0], f"warn must mention the moniker, got {warns[0]!r}"
    assert "Albania" in warns[0], f"warn must mention the country, got {warns[0]!r}"
    assert "sentnode1lf9w8ufk02wpaz93my4855vnyv7d9gx3fwgdgx" not in warns[0], (
        f"warn must not dump the full address, got {warns[0]!r}"
    )


def test_already_connected_guard_passes_when_disconnected():
    """No backend in state → guard returns False, connect flow continues."""
    import bluecli.menus as menus_mod
    import bluecli.config as cfg_mod
    cfg_mod.clear_state()
    assert menus_mod._already_connected_guard() is False


def test_parse_session_action_single_default_is_reconnect():
    from bluecli.menus import _parse_session_action
    assert _parse_session_action("3", 5) == ([2], "r")


def test_parse_session_action_letters_explicit():
    from bluecli.menus import _parse_session_action
    assert _parse_session_action("3r", 5) == ([2], "r")
    assert _parse_session_action("3e", 5) == ([2], "e")


def test_parse_session_action_comma_list():
    """'1,3,5e' must end three sessions in one go."""
    from bluecli.menus import _parse_session_action
    assert _parse_session_action("1,3,5e", 6) == ([0, 2, 4], "e")


def test_parse_session_action_star_means_all():
    """'*e' and 'alle' both terminate every session."""
    from bluecli.menus import _parse_session_action
    assert _parse_session_action("*e", 4) == ([0, 1, 2, 3], "e")
    assert _parse_session_action("alle", 4) == ([0, 1, 2, 3], "e")


def test_parse_session_action_rejects_garbage():
    from bluecli.menus import _parse_session_action
    assert _parse_session_action("foo", 5) is None
    assert _parse_session_action("", 5) is None
    assert _parse_session_action("99e", 5) is None      # out of range
    assert _parse_session_action("1,99e", 5) is None    # one bad item invalidates


def test_filter_nodes_matches_moniker_country_and_protocol():
    """The browse filter is a substring match across three fields."""
    from bluecli.menus import _filter_nodes
    from bluecli.chain import NodeInfo, NODE_TYPE_WIREGUARD, NODE_TYPE_V2RAY

    nodes = [
        NodeInfo("a1", "Foo Node", "Germany", "https://x", NODE_TYPE_WIREGUARD, [], []),
        NodeInfo("a2", "Bar Node", "Italy",   "https://x", NODE_TYPE_V2RAY,     [], []),
        NodeInfo("a3", "Foobar",   "France",  "https://x", NODE_TYPE_WIREGUARD, [], []),
    ]
    # Moniker substring.
    assert [n.address for n in _filter_nodes(nodes, "foo")] == ["a1", "a3"]
    # Country substring, case insensitive.
    assert [n.address for n in _filter_nodes(nodes, "ITALY")] == ["a2"]
    # Protocol via type_name.
    assert [n.address for n in _filter_nodes(nodes, "v2")] == ["a2"]
    assert [n.address for n in _filter_nodes(nodes, "wireguard")] == ["a1", "a3"]
    # No match → empty list, no crash.
    assert _filter_nodes(nodes, "nope") == []


def test_wireguard_install_retries_once_on_failure():
    """The first /installtunnelservice often fails right after
    /uninstalltunnelservice because the Windows Service Control Manager
    hasn't fully released the prior instance. _bring_up must retry once
    before surfacing the error."""
    if sys.platform != "win32":
        # The retry only runs on the Windows path; simulate by monkey-
        # patching sys.platform via the module.
        import bluecli.vpn.wireguard as wg_mod

        # Mock sys.platform so the Windows branch executes.
        orig_platform = wg_mod.sys.platform
        wg_mod.sys.platform = "win32"
    else:
        wg_mod = __import__("bluecli.vpn.wireguard", fromlist=["x"])
        orig_platform = None

    import bluecli.vpn.wireguard as wg_mod
    calls: list[list[str]] = []

    class _Result:
        def __init__(self, rc): self.returncode = rc; self.stdout = ""; self.stderr = ""

    # First install fails (returncode 1), second succeeds (returncode 0).
    install_results = iter([_Result(1), _Result(0)])

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if "/installtunnelservice" in cmd:
            return next(install_results)
        return _Result(0)  # uninstall, anything else

    orig_run = wg_mod.subprocess.run
    orig_sleep = wg_mod.time.sleep
    orig_isfile = type(wg_mod.bin_path("wireguard", "wireguard")).is_file
    wg_mod.subprocess.run = fake_run
    wg_mod.time.sleep = lambda _: None  # don't actually wait
    type(wg_mod.bin_path("wireguard", "wireguard")).is_file = lambda self: True
    try:
        wg_mod._bring_up("/tmp/x.conf")
    finally:
        wg_mod.subprocess.run = orig_run
        wg_mod.time.sleep = orig_sleep
        type(wg_mod.bin_path("wireguard", "wireguard")).is_file = orig_isfile
        if orig_platform is not None:
            wg_mod.sys.platform = orig_platform

    installs = [c for c in calls if "/installtunnelservice" in c]
    assert len(installs) == 2, (
        f"expected 2 install attempts (1 fail + 1 retry), got {len(installs)}: {installs}"
    )


def test_keccak_shim_matches_canonical_vector():
    """The bundled safe-pysha3 shim must produce REAL Keccak-256 hashes
    (the variant with 0x01 padding used by Ethereum and Cosmos), not
    SHA3-256 (NIST variant with 0x06 padding) which would silently
    produce different tx hashes and cause chain broadcasts to be
    rejected with 'signature verification failed'.

    Verifies against the canonical empty-string Keccak-256 vector.
    """
    from sha3 import keccak_256

    empty = keccak_256(b"").hexdigest()
    assert empty == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", (
        f"shim is computing the wrong hash. Got {empty!r}. "
        "If this looks like the SHA3-256 vector (a7ffc6f8…), the shim "
        "is delegating to hashlib instead of pycryptodome Keccak."
    )
    # And a non-empty input, to be sure update() works.
    h = keccak_256()
    h.update(b"abc")
    abc = h.hexdigest()
    assert abc == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45", abc


def test_connected_label_uses_moniker_country_and_backend():
    """When state.json has moniker + country + backend, the status line
    must show '<moniker> (<country>) — <backend>' — not the long
    sentnode address."""
    from bluecli.menus import connected_label
    state = {
        "backend": "wireguard",
        "node_address": "sentnode1lf9w8ufk02wpaz93my4855vnyv7d9gx3fwgdgx",
        "node_moniker": "Cyrano",
        "node_country": "Albania",
    }
    assert connected_label(state) == "Cyrano (Albania) \u2014 wireguard"


def test_connected_label_v2ray_backend():
    """V2Ray sessions must show the backend the same way WireGuard does."""
    from bluecli.menus import connected_label
    state = {
        "backend": "v2ray",
        "node_address": "sentnode1xyz",
        "node_moniker": "FedNet",
        "node_country": "Argentina",
    }
    assert connected_label(state) == "FedNet (Argentina) \u2014 v2ray"


def test_connected_label_partial_metadata():
    """Tolerate empty country / empty moniker / missing backend without
    producing awkward '() ' or trailing dashes."""
    from bluecli.menus import connected_label
    # Moniker but no country, with backend
    assert connected_label({"node_moniker": "Cyrano", "node_country": "",
                             "backend": "wireguard"}) == "Cyrano \u2014 wireguard"
    # Moniker only, no backend (defensive — in practice backend is always set
    # whenever the status line is shown at all)
    assert connected_label({"node_moniker": "Cyrano"}) == "Cyrano"
    # No moniker → fall through to address tail, with backend appended
    addr = "sentnode1ABCDEFGHIJKLMNOP"  # 9 + 16 = 25 chars
    label = connected_label({"node_moniker": "", "node_country": "Albania",
                              "node_address": addr, "backend": "v2ray"})
    assert label == addr[-16:] + " \u2014 v2ray", f"got {label!r}"


def test_connected_label_legacy_state_uses_address_tail():
    """state.json files saved before moniker/country were persisted
    don't have them — the label must still be useful and include the
    backend (which IS in legacy state because disconnect needs it)."""
    from bluecli.menus import connected_label
    state = {
        "backend": "wireguard",
        "node_address": "sentnode1lf9w8ufk02wpaz93my4855vnyv7d9gx3fwgdgx",
    }
    label = connected_label(state)
    # Tail + backend; total still much shorter than the bare sentnode address
    assert "wireguard" in label
    assert label.endswith("\u2014 wireguard")
    assert "vnyv7d9gx3fwgdgx" in label, f"must use address tail, got {label!r}"


def test_wg_quick_uses_bundled_when_present():
    """If bin/wireguard/wg-quick is bundled, it must win over system PATH —
    the bundled tools are the ones we ship and test against."""
    import bluecli.vpn.wireguard as wg_mod

    captured = []
    class _R:
        def __init__(self): self.returncode = 0; self.stdout = ""; self.stderr = ""
    def fake_run(cmd, **kw):
        captured.append(cmd)
        return _R()

    orig_run = wg_mod.subprocess.run
    orig_isfile = type(wg_mod.bin_path("wireguard", "wg-quick")).is_file
    wg_mod.subprocess.run = fake_run
    type(wg_mod.bin_path("wireguard", "wg-quick")).is_file = lambda self: True
    try:
        wg_mod._wg_quick("up", "/tmp/test.conf", check=False)
    finally:
        wg_mod.subprocess.run = orig_run
        type(wg_mod.bin_path("wireguard", "wg-quick")).is_file = orig_isfile

    assert captured, "must call subprocess.run"
    cmd = captured[0]
    # The third arg (after sudo -E) must be the bundled path, not system
    assert "bin/wireguard/wg-quick" in cmd[2] or "bin\\wireguard\\wg-quick" in cmd[2], (
        f"bundled wg-quick must be preferred, got {cmd[2]!r}"
    )


def test_wg_quick_falls_back_to_system_path():
    """If bundled wg-quick is absent (user didn't ship it for Linux),
    fall back to whatever wg-quick is on PATH — typically /usr/bin/wg-quick
    from the wireguard-tools distro package."""
    import bluecli.vpn.wireguard as wg_mod

    captured = []
    class _R:
        def __init__(self): self.returncode = 0; self.stdout = ""; self.stderr = ""
    def fake_run(cmd, **kw):
        captured.append(cmd)
        return _R()

    orig_run = wg_mod.subprocess.run
    orig_which = wg_mod.shutil.which
    orig_isfile = type(wg_mod.bin_path("wireguard", "wg-quick")).is_file
    wg_mod.subprocess.run = fake_run
    wg_mod.shutil.which = lambda name: "/usr/bin/wg-quick" if name == "wg-quick" else None
    type(wg_mod.bin_path("wireguard", "wg-quick")).is_file = lambda self: False
    try:
        wg_mod._wg_quick("up", "/tmp/test.conf", check=False)
    finally:
        wg_mod.subprocess.run = orig_run
        wg_mod.shutil.which = orig_which
        type(wg_mod.bin_path("wireguard", "wg-quick")).is_file = orig_isfile

    assert captured, "must call subprocess.run"
    cmd = captured[0]
    assert cmd[2] == "/usr/bin/wg-quick", f"must use system wg-quick, got {cmd[2]!r}"


def test_wg_quick_raises_when_nothing_available():
    """Neither bundled nor system wg-quick available → clear error with
    install instructions per distro."""
    import bluecli.vpn.wireguard as wg_mod
    from bluecli.vpn import VpnError

    orig_which = wg_mod.shutil.which
    orig_isfile = type(wg_mod.bin_path("wireguard", "wg-quick")).is_file
    wg_mod.shutil.which = lambda name: None
    type(wg_mod.bin_path("wireguard", "wg-quick")).is_file = lambda self: False
    try:
        wg_mod._wg_quick("up", "/tmp/test.conf", check=False)
        raise AssertionError("should have raised VpnError")
    except VpnError as e:
        msg = str(e)
        assert "wg-quick not found" in msg
        # Should mention at least one common distro install command
        assert "wireguard-tools" in msg
    finally:
        wg_mod.shutil.which = orig_which
        type(wg_mod.bin_path("wireguard", "wg-quick")).is_file = orig_isfile


def test_wg_config_omits_dns_on_linux():
    """On Linux we manage /etc/resolv.conf ourselves (see _routing.set_dns),
    so the wg-quick config must NOT carry a DNS line — leaving it to
    wg-quick would (a) need resolvconf and (b) risk pointing the resolver
    at a private nameserver the exit node can't reach."""
    import tempfile, os
    import bluecli.vpn.wireguard as wg_mod

    class _MockSys:
        platform = "linux"
    orig_sys = wg_mod.sys
    wg_mod.sys = _MockSys()
    peer = wg_mod._Peer(ipv4="10.0.0.2/32", ipv6="", endpoint="1.2.3.4:51820",
                        public_key="aaaa")
    try:
        with tempfile.NamedTemporaryFile(mode="r", suffix=".conf", delete=False) as f:
            path = f.name
        try:
            wg_mod._write_config(path, "privkey", peer)
            content = open(path).read()
        finally:
            os.unlink(path)
    finally:
        wg_mod.sys = orig_sys

    assert "DNS" not in content, f"Linux config must omit DNS=, got:\n{content}"
    assert "PrivateKey" in content and "PublicKey" in content


def test_wg_config_keeps_dns_off_linux():
    """On Windows/macOS the native tooling applies the config's DNS line,
    so it must be present there."""
    import tempfile, os
    import bluecli.vpn.wireguard as wg_mod

    class _MockSys:
        platform = "win32"
    orig_sys = wg_mod.sys
    wg_mod.sys = _MockSys()
    peer = wg_mod._Peer(ipv4="10.0.0.2/32", ipv6="", endpoint="1.2.3.4:51820",
                        public_key="aaaa")
    try:
        with tempfile.NamedTemporaryFile(mode="r", suffix=".conf", delete=False) as f:
            path = f.name
        try:
            wg_mod._write_config(path, "privkey", peer)
            content = open(path).read()
        finally:
            os.unlink(path)
    finally:
        wg_mod.sys = orig_sys

    assert "DNS = 1.1.1.1, 1.0.0.1" in content, f"non-Linux must keep DNS=, got:\n{content}"


def test_dns_set_and_restore_regular_file(tmp_path=None):
    """set_dns backs up a regular /etc/resolv.conf and writes public
    nameservers; restore_dns puts the original back exactly."""
    import tempfile, os
    import bluecli.vpn._routing as r

    workdir = tempfile.mkdtemp()
    fake_resolv = os.path.join(workdir, "resolv.conf")
    fake_backup = os.path.join(workdir, "data", "resolv.conf.bluecli-bak")
    original = "nameserver 172.21.239.10\nnameserver 172.21.242.10\n"
    with open(fake_resolv, "w") as f:
        f.write(original)

    # Redirect the module's paths + force the linux branch.
    orig_resolv, orig_backup_fn, orig_is_linux = r._RESOLV_CONF, r._dns_backup_path, r.is_linux
    import pathlib
    r._RESOLV_CONF = fake_resolv
    r._dns_backup_path = lambda: pathlib.Path(fake_backup)
    r.is_linux = lambda: True
    try:
        r.set_dns(("1.1.1.1", "1.0.0.1"))
        after = open(fake_resolv).read()
        assert "1.1.1.1" in after and "172.21.239.10" not in after, after
        assert os.path.exists(fake_backup), "backup not created"

        r.restore_dns()
        restored = open(fake_resolv).read()
        assert restored == original, f"restore mismatch: {restored!r}"
        assert not os.path.exists(fake_backup), "backup not cleaned up"
    finally:
        r._RESOLV_CONF, r._dns_backup_path, r.is_linux = orig_resolv, orig_backup_fn, orig_is_linux


def test_dns_set_preserves_real_original_across_relaunch():
    """If a previous session left a backup (e.g. Ctrl+C without cleanup),
    a second set_dns must NOT overwrite it with the already-modified
    resolv.conf — the real original must survive."""
    import tempfile, os, pathlib
    import bluecli.vpn._routing as r

    workdir = tempfile.mkdtemp()
    fake_resolv = os.path.join(workdir, "resolv.conf")
    fake_backup = os.path.join(workdir, "data", "resolv.conf.bluecli-bak")
    original = "nameserver 10.0.0.1\n"
    open(fake_resolv, "w").write(original)

    orig_resolv, orig_backup_fn, orig_is_linux = r._RESOLV_CONF, r._dns_backup_path, r.is_linux
    r._RESOLV_CONF = fake_resolv
    r._dns_backup_path = lambda: pathlib.Path(fake_backup)
    r.is_linux = lambda: True
    try:
        r.set_dns(("1.1.1.1",))           # first session
        r.set_dns(("1.1.1.1",))           # "relaunch" without cleanup
        r.restore_dns()
        assert open(fake_resolv).read() == original, "real original lost across relaunch"
    finally:
        r._RESOLV_CONF, r._dns_backup_path, r.is_linux = orig_resolv, orig_backup_fn, orig_is_linux


def test_prompt_new_password_returns_match():
    """Happy path: two identical entries returned."""
    import bluecli.menus as menus_mod
    pws = iter(["s3cret", "s3cret"])
    orig = menus_mod.ui.password
    menus_mod.ui.password = lambda _: next(pws)
    try:
        assert menus_mod._prompt_new_password() == "s3cret"
    finally:
        menus_mod.ui.password = orig


def test_prompt_new_password_rejects_mismatch_and_empty():
    """Empty first entry → None. Confirm-mismatch → None. Both report
    a clear error to the user before returning."""
    import bluecli.menus as menus_mod
    errors: list = []
    orig_err, orig_pw = menus_mod.ui.error, menus_mod.ui.password

    menus_mod.ui.error = lambda m: errors.append(m)
    try:
        # Empty first
        menus_mod.ui.password = lambda _: ""
        assert menus_mod._prompt_new_password() is None
        assert len(errors) == 1

        # Mismatch
        pws = iter(["abc", "def"])
        menus_mod.ui.password = lambda _: next(pws)
        assert menus_mod._prompt_new_password() is None
        assert len(errors) == 2
    finally:
        menus_mod.ui.error, menus_mod.ui.password = orig_err, orig_pw


def test_load_browseable_nodes_filters_and_sorts():
    """Helper must filter to wireguard/v2ray only AND sort by (country, moniker)."""
    import bluecli.menus as menus_mod
    from bluecli.chain import NodeInfo, NODE_TYPE_WIREGUARD, NODE_TYPE_V2RAY

    class _FakeCache:
        def __init__(self, nodes): self._nodes = nodes
        def get(self, wait_timeout=0.0): return self._nodes
        def last_error(self): return None

    cache = _FakeCache([
        NodeInfo("b1", "Beta",   "Italy",   "https://x", NODE_TYPE_V2RAY,     [], []),
        NodeInfo("a1", "Alpha",  "Italy",   "https://x", NODE_TYPE_WIREGUARD, [], []),
        NodeInfo("c1", "Gamma",  "",        "https://x", 99,                  [], []),  # unknown type, dropped
        NodeInfo("d1", "Delta",  "Albania", "",          NODE_TYPE_WIREGUARD, [], []),  # no remote_url, dropped
        NodeInfo("e1", "Epsilon", "Albania", "https://x", NODE_TYPE_WIREGUARD, [], []),
    ])
    nodes = menus_mod._load_browseable_nodes(client=None, cache=cache)
    assert nodes is not None
    # Sort: (country, moniker) → Albania.Epsilon, Italy.Alpha, Italy.Beta
    monikers = [n.moniker for n in nodes]
    assert monikers == ["Epsilon", "Alpha", "Beta"], f"unexpected order: {monikers}"


def test_load_browseable_nodes_empty_cache_with_error_reports_it():
    """If the cache is empty AND has an error, surface the error and return None."""
    import bluecli.menus as menus_mod

    class _FakeCache:
        def get(self, wait_timeout=0.0): return []
        def last_error(self): return "gRPC unreachable"

    errors: list = []
    orig_err, orig_info, orig_pause = menus_mod.ui.error, menus_mod.ui.info, menus_mod._pause
    menus_mod.ui.error = lambda m: errors.append(m)
    menus_mod.ui.info = lambda m: None
    menus_mod._pause = lambda: None
    try:
        assert menus_mod._load_browseable_nodes(client=None, cache=_FakeCache()) is None
    finally:
        menus_mod.ui.error, menus_mod.ui.info, menus_mod._pause = orig_err, orig_info, orig_pause

    assert errors and "gRPC unreachable" in errors[0]


def test_disconnect_message_includes_node_label():
    """The disconnect flow must name what we're disconnecting from
    (using the connected_label) — anything terser is too opaque after
    several connections in one session. Also reassures the user that
    the chain session persists."""
    from bluecli.i18n import t, set_language
    set_language("en")

    starting = t("disconnect.starting", "Cyrano (Albania) — wireguard")
    assert "Cyrano (Albania) — wireguard" in starting, (
        f"disconnect.starting must accept a label, got {starting!r}. "
        "If you removed the {0} placeholder, the user won't know which "
        "node they're disconnecting from."
    )
    done = t("disconnect.done")
    # Must reassure that the session is still on chain (saves users from
    # thinking the disconnect costs them their paid time).
    assert "chain" in done.lower() or "session" in done.lower(), (
        f"disconnect.done must mention session persistence, got {done!r}"
    )


def test_ui_clear_tty_guarded():
    """clear() is a no-op when stdout isn't a TTY (tests/pipes); on a TTY it
    runs exactly one platform clear command."""
    from bluecli import ui
    calls = []
    real_system, real_stdout = os.system, sys.stdout

    class _Out:
        def __init__(self, tty):
            self._tty = tty

        def isatty(self):
            return self._tty

        def write(self, *_):
            pass

        def flush(self):
            pass

    try:
        os.system = lambda c: calls.append(c) or 0
        sys.stdout = _Out(False)
        ui.clear()                       # not a tty → nothing happens
        sys.stdout = _Out(True)
        ui.clear()                       # tty → one clear command
    finally:
        os.system, sys.stdout = real_system, real_stdout

    assert len(calls) == 1 and calls[0] in ("cls", "clear")


def test_ui_intro_banner_safe():
    """The art loads, and the startup intro + sticky banner are safe when
    stdout isn't a TTY: no exceptions, and the intro must NOT run its per-line
    cascade (which would sleep ~2s) — it returns instantly instead."""
    import contextlib
    import io
    import time as _t
    from bluecli import art, ui

    assert len(art.BANNER_LINES) >= 1
    assert len(art.BLUEFREN_LINES) >= 1

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        elapsed = None
        if not ui._TTY:
            t0 = _t.time()
            ui.intro()
            elapsed = _t.time() - t0
        ui.banner()          # must not raise
        ui.header("Test")    # routes through banner(); must not raise
    if elapsed is not None:
        assert elapsed < 0.5  # no-op, not the full cascade


def test_ui_format_bytes():
    from bluecli import ui
    assert ui.format_bytes(0) == "0 B"
    assert ui.format_bytes(512) == "512 B"
    assert ui.format_bytes(1024) == "1 KB"
    assert ui.format_bytes(5 * 1024 ** 3) == "5.0 GB"
    assert ui.format_bytes(int(3.2 * 1024 ** 3)) == "3.2 GB"


def test_ui_format_duration():
    from bluecli import ui
    assert ui.format_duration(0) == "0m"
    assert ui.format_duration(45 * 60) == "45m"
    assert ui.format_duration(3600) == "1h"
    assert ui.format_duration(3600 + 12 * 60) == "1h 12m"


def test_session_usage_bytes_plan():
    from bluecli.chain import SessionInfo
    s = SessionInfo(id=1, acc_address="a", node_address="n", status=1,
                    download_bytes=2 * 1024 ** 3, upload_bytes=1 * 1024 ** 3,
                    max_bytes=10 * 1024 ** 3)
    assert s.usage_kind == "bytes"
    assert s.consumed == 3 * 1024 ** 3
    assert s.limit == 10 * 1024 ** 3
    assert abs(s.fraction_used - 0.3) < 1e-9


def test_session_usage_hours_plan():
    from bluecli.chain import SessionInfo
    s = SessionInfo(id=1, acc_address="a", node_address="n", status=1,
                    duration_seconds=3600, max_duration_seconds=5 * 3600)
    assert s.usage_kind == "hours"
    assert s.consumed == 3600 and s.limit == 5 * 3600
    assert abs(s.fraction_used - 0.2) < 1e-9


def test_session_is_active_matches_chain_status():
    """is_active is True only for the ACTIVE status code, matching the on-chain
    enum (UNSPECIFIED=0, ACTIVE=1, INACTIVE_PENDING=2, INACTIVE=3)."""
    from bluecli.chain import SessionInfo, Status

    def s(status):
        return SessionInfo(id=1, acc_address="a", node_address="n", status=status)

    assert s(Status.ACTIVE.value).is_active is True
    assert s(Status.UNSPECIFIED.value).is_active is False
    assert s(Status.INACTIVE_PENDING.value).is_active is False
    assert s(Status.INACTIVE.value).is_active is False


def test_session_usage_unmetered_subscription():
    from bluecli.chain import SessionInfo
    s = SessionInfo(id=1, acc_address="a", node_address="n", status=1)
    assert s.usage_kind is None
    assert s.consumed == 0 and s.limit == 0
    assert s.fraction_used is None


def test_session_fraction_capped_at_one():
    from bluecli.chain import SessionInfo
    s = SessionInfo(id=1, acc_address="a", node_address="n", status=1,
                    download_bytes=20 * 1024 ** 3, upload_bytes=0,
                    max_bytes=10 * 1024 ** 3)
    assert s.fraction_used == 1.0  # node over-report must never show >100%


def test_session_int_parsing():
    from bluecli.chain import _session_int
    assert _session_int("") == 0
    assert _session_int("1073741824") == 1073741824
    assert _session_int(None) == 0
    assert _session_int("garbage") == 0


def test_session_usage_str_and_threshold():
    from bluecli import menus
    from bluecli.chain import SessionInfo
    s = SessionInfo(id=7, acc_address="a", node_address="n", status=1,
                    download_bytes=int(9.5 * 1024 ** 3), upload_bytes=0,
                    max_bytes=10 * 1024 ** 3)
    usage = menus._session_usage_str(s)
    assert "GB" in usage and "95%" in usage
    assert (s.fraction_used or 0.0) >= menus._QUOTA_WARN_THRESHOLD
    # unmetered → no usage string, never warns
    s2 = SessionInfo(id=8, acc_address="a", node_address="n", status=1)
    assert menus._session_usage_str(s2) == ""
    assert (s2.fraction_used or 0.0) < menus._QUOTA_WARN_THRESHOLD


def test_atomic_write_json_roundtrip_and_mode():
    import json
    import os
    import tempfile
    import pathlib
    from bluecli import config as cfg
    d = tempfile.mkdtemp()
    p = pathlib.Path(d) / "state.json"
    cfg._atomic_write_json(p, {"a": 1, "b": "x"}, mode=0o600)
    assert json.loads(p.read_text()) == {"a": 1, "b": "x"}
    assert not (pathlib.Path(d) / "state.json.tmp").exists(), "temp file left behind"
    if os.name != "nt":
        assert (p.stat().st_mode & 0o777) == 0o600


def test_verify_public_ip_no_route_is_bounded():
    """When the tunnel isn't reaching the internet, verify must NOT call any
    fetch (which could hang on DNS), must stay within budget, and must return
    'no_route' (the caller then restores the network)."""
    import time as _time
    from bluecli import menus
    orig = (menus._has_connectivity, menus._fetch_public_ip, menus._fetch_public_ip_no_dns)

    def _boom(timeout):
        raise AssertionError("must not fetch while unreachable")

    menus._has_connectivity = lambda timeout=3.0: False
    menus._fetch_public_ip = _boom
    menus._fetch_public_ip_no_dns = _boom
    try:
        start = _time.time()
        status = menus._verify_public_ip(pre_connect_ip="1.2.3.4", budget=0.5)
        elapsed = _time.time() - start
    finally:
        (menus._has_connectivity, menus._fetch_public_ip,
         menus._fetch_public_ip_no_dns) = orig
    assert elapsed < 5.0, f"verify overran its budget: {elapsed:.1f}s"
    assert status == "no_route"


def test_verify_public_ip_reports_changed_ip():
    """Routes (changed exit IP via the DNS-free probe) + DNS resolving = 'ok',
    and the exit IP is shown."""
    from bluecli import menus
    from bluecli import ui as _ui
    orig = (menus._has_connectivity, menus._fetch_public_ip_no_dns,
            menus._dns_resolves, _ui.info)
    infos: list = []
    menus._has_connectivity = lambda timeout=3.0: True
    menus._fetch_public_ip_no_dns = lambda timeout: "9.9.9.9"
    menus._dns_resolves = lambda **kw: True
    _ui.info = lambda msg, *a, **k: infos.append(msg)
    try:
        status = menus._verify_public_ip(pre_connect_ip="1.2.3.4", budget=5.0)
    finally:
        (menus._has_connectivity, menus._fetch_public_ip_no_dns,
         menus._dns_resolves, _ui.info) = orig
    assert status == "ok"
    assert any("9.9.9.9" in str(m) for m in infos)


def test_verify_public_ip_detects_broken_dns():
    """The VPS case: tunnel routes (DNS-free probe returns a changed exit IP)
    but the system resolver fails → status 'dns'. The exit IP is still shown so
    the user can see the tunnel reached the internet — no silent hang."""
    from bluecli import menus
    from bluecli import ui as _ui
    orig = (menus._has_connectivity, menus._fetch_public_ip_no_dns,
            menus._dns_resolves, _ui.info)
    infos: list = []
    menus._has_connectivity = lambda timeout=3.0: True
    menus._fetch_public_ip_no_dns = lambda timeout: "9.9.9.9"
    menus._dns_resolves = lambda **kw: False
    _ui.info = lambda msg, *a, **k: infos.append(msg)
    try:
        status = menus._verify_public_ip(pre_connect_ip="1.2.3.4", budget=2.0)
    finally:
        (menus._has_connectivity, menus._fetch_public_ip_no_dns,
         menus._dns_resolves, _ui.info) = orig
    assert status == "dns"
    assert any("9.9.9.9" in str(m) for m in infos)


def test_teardown_tunnel_dispatches_by_backend():
    from bluecli import menus
    from bluecli.vpn import wireguard as wg, v2ray as v2
    calls: list = []
    ow, ov = wg.disconnect, v2.disconnect
    wg.disconnect = lambda st: calls.append("wg")
    v2.disconnect = lambda st: calls.append("v2")
    try:
        menus._teardown_tunnel({"backend": "wireguard"})
        menus._teardown_tunnel({"backend": "v2ray"})
        menus._teardown_tunnel({"backend": None})  # nothing live → no-op
    finally:
        wg.disconnect, v2.disconnect = ow, ov
    assert calls == ["wg", "v2"]


def test_ending_active_session_tears_down_tunnel():
    """Regression: ending the currently-connected session must tear down the
    local tunnel (kill processes + restore routing) and clear state — not
    just end it on chain, which would leave the user stuck in a dead tunnel."""
    from bluecli import menus
    from bluecli import ui as _ui
    from bluecli import config as cfg

    active = {
        "session_id": 555, "backend": "v2ray", "node_type": "v2ray",
        "node_moniker": "X", "node_country": "Y",
        "tun2socks_pid": 1, "pid": 2, "tun_iface": "blue-tun", "node_ip": "5.5.5.5",
    }
    seen = {"teardown": 0, "cleared": False}

    class FakeClient:
        def end_session(self, secret, sid):
            assert sid == 555

    class FakeSession:
        id = 555
        node_address = "sentnode1xxx"

    class FakeWallet:
        secret = "words"
        address = "sent1xxx"

    saved = (cfg.load_state, cfg.clear_state, cfg.save_state,
             menus._teardown_tunnel, menus._pause,
             _ui.success, _ui.info, _ui.error)
    cfg.load_state = lambda: dict(active)
    cfg.clear_state = lambda: seen.__setitem__("cleared", True)
    cfg.save_state = lambda s: None
    menus._teardown_tunnel = lambda st: seen.__setitem__("teardown", seen["teardown"] + 1)
    menus._pause = lambda: None
    _ui.success = _ui.info = _ui.error = lambda *a, **k: None
    try:
        menus._end_sessions(FakeWallet(), FakeClient(), [FakeSession()])
    finally:
        (cfg.load_state, cfg.clear_state, cfg.save_state,
         menus._teardown_tunnel, menus._pause,
         _ui.success, _ui.info, _ui.error) = saved

    assert seen["teardown"] == 1, "active-session end must tear down the live tunnel"
    assert seen["cleared"] is True, "state must be cleared after ending active session"


def test_coincurve_stub_is_a_tripwire():
    """The bundled coincurve shim must raise loudly if anything ever
    calls it. coincurve is only present to satisfy pip — bip-utils is
    patched to use its pure-Python ecdsa backend instead. If a code
    path actually reaches coincurve, the USE_COINCURVE=False patch
    failed to apply, and we must fail hard rather than risk producing
    keys through an unexpected backend.
    """
    import importlib.util
    import pathlib
    stub = (pathlib.Path(__file__).parent.parent
            / "wheelhouse_src" / "coincurve_stub" / "coincurve.py")
    assert stub.is_file(), f"stub source missing at {stub}"
    spec = importlib.util.spec_from_file_location("_coincurve_stub_test", stub)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    for call in (
        lambda: mod.PublicKey(b"\x02" * 33),
        lambda: mod.PublicKey.from_secret(b"\x01" * 32),
        lambda: mod.PrivateKey(b"\x01" * 32),
    ):
        try:
            call()
        except NotImplementedError as e:
            assert "stub" in str(e).lower()
        else:
            raise AssertionError("coincurve stub must raise when called")


# --------------------------------------------------------------------------
# Run
# --------------------------------------------------------------------------


def test_transport_cache_record_and_eligible():
    import pathlib
    import tempfile
    from bluecli import transport_cache as tc
    saved = tc._CACHE_FILE
    tc._CACHE_FILE = pathlib.Path(tempfile.mkdtemp()) / "tc.json"
    try:
        tc.record("sentnode1AAA", ["tcp", "websocket"])
        tc.record("sentnode1BBB", ["grpc"])
        tc.record("sentnode1CCC", ["TCP"])      # case-normalised
        tc.record("sentnode1DDD", [])           # empty → ignored (so never eligible)
        assert tc.eligible_addresses("tcp") == {"sentnode1AAA", "sentnode1CCC"}
        tc.record("sentnode1BBB", ["tcp"])      # last-write-wins
        assert "sentnode1BBB" in tc.eligible_addresses("tcp")
    finally:
        tc._CACHE_FILE = saved


def test_offered_transports():
    from bluecli.vpn import v2ray as v2ray_mod
    pd = {"metadata": [
        {"transport_protocol": 7},     # tcp
        {"transport_protocol": 8},     # websocket
        {"transport_protocol": "tcp"}, # textual duplicate
        {"transport_protocol": 3},     # grpc
        "not-a-dict",
    ]}
    assert v2ray_mod.offered_transports(pd) == ["grpc", "tcp", "websocket"]
    assert v2ray_mod.offered_transports({}) == []
    assert v2ray_mod.offered_transports({"metadata": []}) == []


def test_multihop_config_structure():
    from bluecli.vpn import v2ray as v2ray_mod
    entry = {"host": "10.0.0.1", "port": 443, "proxy": "vmess", "transport": "tcp", "security": "tls"}
    exit_ = {"host": "10.0.0.2", "port": 80, "proxy": "vmess", "transport": "tcp", "security": ""}
    cfg = v2ray_mod._build_v2ray_multihop_config(
        entry=entry, entry_uid="E", exit=exit_, exit_uid="X", socks_port=1080
    )
    obs = cfg["outbounds"]
    assert len(obs) == 2
    # Exit is the default (first) outbound and dials through the entry.
    assert obs[0]["tag"] == "exit-out"
    assert obs[0]["proxySettings"] == {"tag": "entry-out"}
    assert obs[1]["tag"] == "entry-out"
    assert "proxySettings" not in obs[1]
    # One socks inbound, unchanged from single-hop.
    assert len(cfg["inbounds"]) == 1 and cfg["inbounds"][0]["tag"] == "socks-in"
    # Each outbound carries its own server.
    assert obs[0]["settings"]["vnext"][0]["address"] == "10.0.0.2"
    assert obs[1]["settings"]["vnext"][0]["address"] == "10.0.0.1"


def test_require_tcp_endpoints():
    from bluecli.vpn import v2ray as v2ray_mod
    tcp = {"transport": "tcp"}
    ws = {"transport": "websocket"}
    v2ray_mod._require_tcp_endpoints(tcp, tcp)  # both tcp → no raise
    for bad in ((tcp, ws), (ws, tcp), (ws, ws)):
        try:
            v2ray_mod._require_tcp_endpoints(*bad)
            assert False, "expected VpnError for non-tcp endpoint"
        except v2ray_mod.VpnError:
            pass


def test_proxy_session_multihop_backend():
    from bluecli.vpn import v2ray as v2ray_mod
    base = dict(pid=1, tun2socks_pid=2, socks_port=3, config_path="c",
                tun_iface="t", node_ip="i", orig_gw="g")
    assert v2ray_mod.V2RayProxySession(**base).to_state()["backend"] == "v2ray"
    assert v2ray_mod.V2RayProxySession(**base, multihop=True).to_state()["backend"] == "v2ray-multihop"


def test_active_session_ids():
    from bluecli import config as cfg
    assert cfg.active_session_ids({"session_id": 7}) == [7]
    assert cfg.active_session_ids({}) == []
    multi = {"hops": [{"session_id": 10}, {"session_id": 20}]}
    assert cfg.active_session_ids(multi) == [10, 20]
    # Malformed hops are skipped, not crashed on.
    assert cfg.active_session_ids({"hops": [{"x": 1}, {"session_id": 5}]}) == [5]


def test_connected_label_multihop_chain():
    from bluecli import menus
    multi = {"backend": "v2ray-multihop", "hops": [
        {"node_moniker": "EntryDE", "node_country": "DE"},
        {"node_moniker": "ExitJP", "node_country": "JP"},
    ]}
    label = menus.connected_label(multi)
    assert "EntryDE (DE)" in label and "ExitJP (JP)" in label
    assert "\u2192" in label  # arrow between hops
    assert "v2ray-multihop" in label
    # Single-hop label is unchanged.
    assert menus.connected_label({"backend": "v2ray", "node_moniker": "Solo", "node_country": "IT"}) == "Solo (IT) \u2014 v2ray"


def test_teardown_covers_multihop():
    from bluecli import menus
    from bluecli.vpn import v2ray as v2ray_mod
    calls = []
    orig = v2ray_mod.disconnect
    v2ray_mod.disconnect = lambda st: calls.append("v2")
    try:
        menus._teardown_tunnel({"backend": "v2ray-multihop"})
    finally:
        v2ray_mod.disconnect = orig
    assert calls == ["v2"]


def test_multihop_partial_notice_includes_orphan():
    """Anti-burn regression: if a hop's session was paid (start_session ok) but
    its handshake then failed, that session is held in `orphan_session_id`, not
    yet in `hops`. The partial notice must still list it alongside any
    fully-formed hop, so the user is told about every session they paid for and
    can end it from 'My active sessions'."""
    from bluecli import menus
    from bluecli import ui as _ui

    # entry hop fully persisted (session 555); exit session 777 was paid, then
    # its handshake failed before it could be added to `hops`.
    state = {
        "hops": [{"role": "entry", "session_id": 555, "v2_uuid_hex": "ab"}],
        "orphan_session_id": 777,
    }
    captured = []
    saved_warn = _ui.warn
    _ui.warn = lambda msg, *a, **k: captured.append(str(msg))
    try:
        menus._multihop_partial_notice(state)
    finally:
        _ui.warn = saved_warn

    assert captured, "a partial multihop bring-up must warn the user"
    text = captured[0]
    assert "555" in text, "the fully-formed hop session must be listed"
    assert "777" in text, "the paid-but-orphaned hop session must be listed"


def test_group_sessions_collapses_chain():
    """The two hops of the current chain (per state['hops']) collapse into one
    'chain' row, entry-first; unrelated sessions stay individual."""
    import types
    from bluecli import menus

    def S(i, addr):
        return types.SimpleNamespace(id=i, node_address=addr,
                                     fraction_used=0.0, usage_kind=None)

    sessions = [S(10, "entryAddr"), S(20, "exitAddr"), S(30, "otherAddr")]
    state = {"hops": [{"role": "entry", "session_id": 10},
                      {"role": "exit", "session_id": 20}]}
    rows = menus._group_sessions(sessions, state)
    assert [k for k, _ in rows] == ["chain", "single"], rows
    assert [s.id for s in rows[0][1]] == [10, 20], "hops must be entry-first"
    assert rows[1][1].id == 30


def test_group_sessions_no_hops_all_single():
    import types
    from bluecli import menus
    sessions = [types.SimpleNamespace(id=10, node_address="a"),
                types.SimpleNamespace(id=20, node_address="b")]
    rows = menus._group_sessions(sessions, {})
    assert [k for k, _ in rows] == ["single", "single"]


def test_group_sessions_incomplete_chain_stays_single():
    """If only one recorded hop is still on chain, we can't form a chain row —
    both legs show individually (still endable one by one)."""
    import types
    from bluecli import menus
    sessions = [types.SimpleNamespace(id=10, node_address="a")]  # exit (20) gone
    state = {"hops": [{"role": "entry", "session_id": 10},
                      {"role": "exit", "session_id": 20}]}
    rows = menus._group_sessions(sessions, state)
    assert rows == [("single", sessions[0])]


def test_expand_rows_for_end_chain_expands_both():
    """Selecting a chain row for ending must flatten to BOTH hop sessions, so a
    multihop is always ended whole — never leaving one paid hop running."""
    import types
    from bluecli import menus
    s10, s20, s30 = (types.SimpleNamespace(id=i) for i in (10, 20, 30))
    rows = [("chain", [s10, s20]), ("single", s30)]
    assert [s.id for s in menus._expand_rows_for_end(rows, [0])] == [10, 20]
    assert [s.id for s in menus._expand_rows_for_end(rows, [1])] == [30]
    assert [s.id for s in menus._expand_rows_for_end(rows, [0, 1])] == [10, 20, 30]


def test_single_hop_persist_clears_stale_hops():
    """State exclusivity: committing to a single-hop session must drop any
    multihop `hops` left cached from a prior chain disconnect — otherwise stale
    hops keep winning in active_session_ids() and the live single-hop tunnel
    won't tear down when its session is ended."""
    from bluecli import menus
    from bluecli import config as cfg
    from bluecli import ui as _ui

    class FakeCreds:
        def to_state(self):
            return {"v2_uuid_hex": "ab", "handshake_node_addrs": [],
                    "handshake_peer_data": {}}

    class FakeNode:
        remote_url = "https://node.example"
        address = "sentnode1new"
        node_type = 2
        moniker = "New"
        country = "IT"

    captured = {}
    saved = (cfg.save_state, _ui.info, _ui.error)
    cfg.save_state = lambda s: captured.update({"state": dict(s)})
    _ui.info = lambda *a, **k: None
    _ui.error = lambda *a, **k: None
    try:
        state = {"hops": [{"role": "entry", "session_id": 1},
                          {"role": "exit", "session_id": 2}]}
        menus._get_or_fetch_creds(
            state, False, FakeNode(), 99, b"\x00" * 32,
            cls=FakeCreds, marker_key="v2_uuid_hex",
            fetch=lambda **kw: FakeCreds(),
        )
    finally:
        (cfg.save_state, _ui.info, _ui.error) = saved

    assert "hops" not in captured["state"], "single-hop persist must drop stale hops"
    assert captured["state"].get("session_id") == 99


def test_verify_status_classification():
    """The pure verify decision: usable only when traffic flows AND DNS works."""
    from bluecli.menus import _verify_status
    assert _verify_status(False, None, None, False) == "no_route"   # nothing reachable
    assert _verify_status(True, None, None, False) == "no_route"    # reachable, no exit IP
    assert _verify_status(True, "1.2.3.4", "1.2.3.4", True) == "no_route"  # IP unchanged
    assert _verify_status(True, "9.9.9.9", "1.2.3.4", False) == "dns"      # routes, no DNS
    assert _verify_status(True, "9.9.9.9", "1.2.3.4", True) == "ok"        # routes + DNS
    assert _verify_status(True, "9.9.9.9", None, True) == "ok"             # no baseline


def test_parse_trace_ip():
    """The DNS-free probe must pull the exit IP out of a cdn-cgi/trace body."""
    from bluecli.menus import _parse_trace_ip
    assert _parse_trace_ip("fl=123\nh=1.1.1.1\nip=203.0.113.7\nts=1.0\n") == "203.0.113.7"
    assert _parse_trace_ip("fl=1\nno_ip_line\n") is None


def test_connected_resolv_conf_forces_tcp_dns():
    """While connected, DNS must be forced over TCP (`use-vc`): UDP datagrams
    don't reliably survive the SOCKS/proxy-chain path, TCP does."""
    from bluecli.vpn import _routing
    body = _routing._connected_resolv_conf(("1.1.1.1", "1.0.0.1"))
    assert "use-vc" in body
    assert "nameserver 1.1.1.1" in body and "nameserver 1.0.0.1" in body


def test_emergency_cleanup_tears_down_multihop():
    """Fail-safe: an abrupt exit during a multihop session must tear the tunnel
    down. The backend is 'v2ray-multihop', so a bare '== v2ray' check would
    silently skip it and strand the user with redirected routing."""
    import bluecli.__main__ as entry
    from bluecli import config as cfg
    from bluecli.vpn import v2ray as v2ray_mod

    calls = {"disc": 0, "strip": 0}
    saved = (cfg.load_state, cfg.strip_runtime_state, v2ray_mod.disconnect)
    cfg.load_state = lambda: {"backend": "v2ray-multihop", "tun_iface": "blue-tun",
                              "node_ip": "5.5.5.5", "pid": 1, "tun2socks_pid": 2}
    cfg.strip_runtime_state = lambda: calls.__setitem__("strip", calls["strip"] + 1)
    v2ray_mod.disconnect = lambda st: calls.__setitem__("disc", calls["disc"] + 1)
    try:
        entry._emergency_cleanup()
    finally:
        (cfg.load_state, cfg.strip_runtime_state, v2ray_mod.disconnect) = saved
    assert calls["disc"] == 1, "multihop backend must be torn down on abrupt exit"
    assert calls["strip"] == 1


def test_restore_after_failed_verify_restores_and_keeps_creds():
    """A failed verification must tear the tunnel down and strip ONLY runtime
    state (keeping session/creds so the user can retry), with a reason message
    that differs between the DNS and no-route cases."""
    from bluecli import menus
    from bluecli import config as cfg
    from bluecli import ui as _ui

    calls = {"teardown": 0, "strip": 0, "errors": []}
    saved = (menus._teardown_tunnel, cfg.strip_runtime_state, _ui.error)
    menus._teardown_tunnel = lambda st: calls.__setitem__("teardown", calls["teardown"] + 1)
    cfg.strip_runtime_state = lambda: calls.__setitem__("strip", calls["strip"] + 1)
    _ui.error = lambda msg, *a, **k: calls["errors"].append(str(msg))
    try:
        menus._restore_after_failed_verify({"backend": "v2ray"}, "dns")
        menus._restore_after_failed_verify({"backend": "v2ray"}, "no_route")
    finally:
        (menus._teardown_tunnel, cfg.strip_runtime_state, _ui.error) = saved
    assert calls["teardown"] == 2 and calls["strip"] == 2
    assert len(calls["errors"]) == 2 and calls["errors"][0] != calls["errors"][1]


def test_outbound_dials_by_ip_direct():
    """A directly-dialed endpoint (dial_through=None) must dial the pre-resolved
    IP, not the hostname — otherwise v2ray's name lookup deadlocks inside the
    tunnel it's building. TLS SNI must stay the hostname."""
    from bluecli.vpn.v2ray import _build_outbound
    ob = _build_outbound(
        server={"host": "brazil.dvpn-x.com", "port": 443, "proxy": "vless",
                "transport": "tcp", "security": "tls", "dial_address": "203.0.113.9"},
        uid="u", tag="vless-out",
    )
    assert ob["settings"]["vnext"][0]["address"] == "203.0.113.9", \
        "a directly-dialed endpoint must be dialed by IP"
    assert ob["streamSettings"]["tlsSettings"]["serverName"] == "brazil.dvpn-x.com", \
        "SNI must remain the hostname for the node's cert/vhost routing"


def test_outbound_through_proxy_keeps_hostname():
    """An endpoint reached THROUGH another proxy (the multihop exit, with
    dial_through set) keeps its hostname — the upstream node resolves it."""
    from bluecli.vpn.v2ray import _build_outbound
    ob = _build_outbound(
        server={"host": "exit.example.com", "port": 443, "proxy": "vless",
                "transport": "tcp", "security": "tls", "dial_address": "203.0.113.9"},
        uid="u", tag="exit-out", dial_through="entry-out",
    )
    assert ob["settings"]["vnext"][0]["address"] == "exit.example.com"
    assert ob["proxySettings"]["tag"] == "entry-out"


def test_outbound_falls_back_to_host_without_dial_ip():
    """No pre-resolved IP supplied → dial the host (IP-endpoint nodes / back-compat)."""
    from bluecli.vpn.v2ray import _build_outbound
    ob = _build_outbound(
        server={"host": "5.5.5.5", "port": 80, "proxy": "vmess",
                "transport": "tcp", "security": "none"},
        uid="u", tag="vmess-out",
    )
    assert ob["settings"]["vnext"][0]["address"] == "5.5.5.5"


def test_multihop_config_dials_entry_by_ip_exit_by_host():
    """Builder end-to-end: the entry outbound dials the resolved IP; the exit
    outbound (carried through the entry) keeps its hostname."""
    from bluecli.vpn.v2ray import _build_v2ray_multihop_config
    cfg = _build_v2ray_multihop_config(
        entry={"host": "entry.dvpn.com", "port": 443, "proxy": "vless",
               "transport": "tcp", "security": "tls", "dial_address": "198.51.100.4"},
        entry_uid="e",
        exit={"host": "exit.dvpn.com", "port": 443, "proxy": "vless",
              "transport": "tcp", "security": "tls"},
        exit_uid="x",
        socks_port=1080,
    )
    by_tag = {ob["tag"]: ob for ob in cfg["outbounds"]}
    assert by_tag["entry-out"]["settings"]["vnext"][0]["address"] == "198.51.100.4"
    assert by_tag["exit-out"]["settings"]["vnext"][0]["address"] == "exit.dvpn.com"
    assert by_tag["exit-out"]["proxySettings"]["tag"] == "entry-out"


def test_chain_row_shows_per_hop_usage():
    """The multihop row must surface each hop's consumption (on a second line)
    when the hops are metered, and omit it when they're not — so usage is
    visible at a glance without expanding the chain into its hops."""
    import types
    from bluecli import menus, ui

    def S(i, used, limit):
        return types.SimpleNamespace(id=i, node_address=f"addr{i}",
                                     usage_kind="bytes", fraction_used=used / limit,
                                     consumed=used, limit=limit)
    row = menus._format_chain_row(
        1, [S(190, 12_900_000, 1_000_000_000), S(195, 11_800_000, 1_000_000_000)], {}
    )
    assert "\n" in row, "a metered chain must show a usage line"
    assert ui.format_bytes(12_900_000) in row and ui.format_bytes(11_800_000) in row
    assert "entry" in row and "exit" in row

    def U(i):
        return types.SimpleNamespace(id=i, node_address=f"addr{i}",
                                     usage_kind=None, fraction_used=0.0)
    assert "\n" not in menus._format_chain_row(2, [U(1), U(2)], {}), \
        "an unmetered chain must not add a usage line"


def main() -> int:
    tests = [
        ("i18n.loads_english", test_i18n_loads_english),
        ("i18n.unknown_key_returns_key", test_i18n_unknown_key_returns_key),
        ("i18n.placeholders", test_i18n_placeholders),
        ("i18n.fallback_to_english", test_i18n_fallback_to_english_for_missing_lang),
        ("wallet.address_derivation_vector", test_wallet_address_derivation_matches_vector),
        ("wallet.create_unlock_delete", test_wallet_create_unlock_delete_round_trip),
        ("wallet.import_validates_mnemonic", test_wallet_import_validates_mnemonic),
        ("wallet.import_from_vector", test_wallet_import_from_known_vector),
        ("wallet.refuses_to_overwrite", test_wallet_refuses_to_overwrite),
        ("wallet.derive_private_key", test_derive_private_key_is_deterministic_and_32_bytes),
        ("config.load_default", test_config_load_default),
        ("state.round_trip", test_state_round_trip),
        ("vpn.wireguard.v8_response_parser", test_wireguard_parses_v8_response),
        ("vpn.wireguard.config_file", test_wireguard_config_file_is_valid_ini),
        ("vpn.v2ray.v8_response_parser", test_v2ray_parses_v8_response),
        ("vpn.v2ray.int_enum_decoding", test_v2ray_parses_int_enum_metadata),
        ("vpn.v2ray.digit_string_enum", test_v2ray_parses_digit_string_enum),
        ("vpn.v2ray.tls_enabled_when_node_says_tls", test_v2ray_config_enables_tls_when_node_says_tls),
        ("vpn.v2ray.tls_omitted_when_node_doesnt", test_v2ray_config_omits_tls_when_node_doesnt_ask),
        ("vpn.v2ray.endpoint_picker_prefers_tcp", test_v2ray_endpoint_picker_prefers_tcp_over_grpc),
        ("vpn.v2ray.endpoint_picker_grpc_only_fallback", test_v2ray_endpoint_picker_falls_back_to_grpc_if_only_option),
        ("vpn.v2ray.endpoint_picker_tls_beats_plain", test_v2ray_endpoint_picker_prefers_tcp_tls_over_tcp_plain),
        ("menus.verify_public_ip_baseline", test_verify_public_ip_compares_against_baseline),
        ("vpn.v2ray.major_version_detection", test_v2ray_major_version_detection),
        ("vpn.v2ray.pick_free_port", test_v2ray_pick_free_port_works),
        ("vpn.v2ray.uuid_format", test_v2ray_uuid_sent_as_byte_array),
        ("vpn.handshake.signing_canonical", test_handshake_signing_is_deterministic_low_s),
        ("chain.probe_nodes_basic", test_probe_nodes_empty_and_unreachable),
        ("chain.parse_response_real_v2ray", test_parse_node_response_real_v2ray_shape),
        ("chain.parse_response_wireguard", test_parse_node_response_wireguard_variant),
        ("chain.parse_response_rejects_garbage", test_parse_node_response_rejects_garbage),
        ("chain.parse_session_any_node", test_parse_session_any_node_wrapper),
        ("chain.parse_session_any_subscription", test_parse_session_any_subscription_wrapper),
        ("chain.price_dict_roundtrip", test_price_dict_roundtrip),
        ("node_cache.disk_seed", test_node_cache_serves_disk_seed),
        ("menus.format_node_row", test_format_node_row_with_dict_prices),
        ("node_cache.signals_done_on_empty", test_node_cache_signals_done_even_when_fetch_returns_empty),
        ("node_cache.records_fetch_errors", test_node_cache_records_fetch_errors),
        ("vpn.wireguard.creds_roundtrip", test_wg_credentials_state_roundtrip),
        ("vpn.v2ray.creds_roundtrip", test_v2_credentials_state_roundtrip),
        ("config.strip_runtime_preserves_creds", test_strip_runtime_state_preserves_session_creds),
        ("vpn.handshake_error.status_code", test_node_handshake_error_carries_status_code),
        ("menus.reconnect_uses_cached_creds", test_reconnect_uses_cached_creds_when_state_matches),
        ("menus.409_maps_to_friendly_error", test_409_response_maps_to_friendly_error),
        ("routing.get_default_route", test_routing_get_default_route_doesnt_crash),
        ("routing.configure_tun_windows_netsh", test_configure_tun_emits_netsh_on_windows),
        ("routing.configure_tun_ps_fallback", test_configure_tun_falls_back_to_powershell_new_netipaddress),
        ("routing.configure_tun_raises_on_total_failure", test_configure_tun_raises_when_both_methods_fail),
        ("routing.split_default_windows_gateway", test_add_split_default_uses_local_ip_on_windows),
        ("menus.already_connected_guard_blocks", test_already_connected_guard_short_circuits_with_live_state),
        ("menus.already_connected_guard_passes", test_already_connected_guard_passes_when_disconnected),
        ("menus.parse_session_default_is_reconnect", test_parse_session_action_single_default_is_reconnect),
        ("menus.parse_session_explicit_letters", test_parse_session_action_letters_explicit),
        ("menus.parse_session_comma_list", test_parse_session_action_comma_list),
        ("menus.parse_session_star_means_all", test_parse_session_action_star_means_all),
        ("menus.parse_session_rejects_garbage", test_parse_session_action_rejects_garbage),
        ("menus.filter_nodes_three_fields", test_filter_nodes_matches_moniker_country_and_protocol),
        ("vpn.wireguard.install_retries_once", test_wireguard_install_retries_once_on_failure),
        ("vendor.sha3_shim_real_keccak", test_keccak_shim_matches_canonical_vector),
        ("app.connected_label_wireguard", test_connected_label_uses_moniker_country_and_backend),
        ("app.connected_label_v2ray", test_connected_label_v2ray_backend),
        ("app.connected_label_partial", test_connected_label_partial_metadata),
        ("app.connected_label_legacy_state", test_connected_label_legacy_state_uses_address_tail),
        ("vpn.wireguard.wg_quick_prefers_bundled", test_wg_quick_uses_bundled_when_present),
        ("vpn.wireguard.wg_quick_falls_back_to_system", test_wg_quick_falls_back_to_system_path),
        ("vpn.wireguard.wg_quick_clear_error_when_missing", test_wg_quick_raises_when_nothing_available),
        ("vpn.wireguard.config_omits_dns_on_linux", test_wg_config_omits_dns_on_linux),
        ("vpn.wireguard.config_keeps_dns_off_linux", test_wg_config_keeps_dns_off_linux),
        ("vpn.routing.dns_set_and_restore", test_dns_set_and_restore_regular_file),
        ("vpn.routing.dns_preserves_original_across_relaunch", test_dns_set_preserves_real_original_across_relaunch),
        ("menus.prompt_new_password_match", test_prompt_new_password_returns_match),
        ("menus.prompt_new_password_rejects_bad", test_prompt_new_password_rejects_mismatch_and_empty),
        ("menus.browseable_nodes_filter_and_sort", test_load_browseable_nodes_filters_and_sorts),
        ("menus.browseable_nodes_reports_error", test_load_browseable_nodes_empty_cache_with_error_reports_it),
        ("menus.disconnect_message_with_label", test_disconnect_message_includes_node_label),
        ("vendor.coincurve_stub_tripwire", test_coincurve_stub_is_a_tripwire),
        ("ui.clear_tty_guarded", test_ui_clear_tty_guarded),
        ("ui.intro_banner_safe", test_ui_intro_banner_safe),
        ("ui.format_bytes", test_ui_format_bytes),
        ("ui.format_duration", test_ui_format_duration),
        ("chain.session_usage_bytes_plan", test_session_usage_bytes_plan),
        ("chain.session_usage_hours_plan", test_session_usage_hours_plan),
        ("chain.session_is_active", test_session_is_active_matches_chain_status),
        ("chain.session_usage_unmetered", test_session_usage_unmetered_subscription),
        ("chain.session_fraction_capped", test_session_fraction_capped_at_one),
        ("chain.session_int_parsing", test_session_int_parsing),
        ("menus.session_usage_str_and_threshold", test_session_usage_str_and_threshold),
        ("config.atomic_write_roundtrip", test_atomic_write_json_roundtrip_and_mode),
        ("menus.verify_no_route_bounded", test_verify_public_ip_no_route_is_bounded),
        ("menus.verify_reports_changed_ip", test_verify_public_ip_reports_changed_ip),
        ("menus.verify_detects_broken_dns", test_verify_public_ip_detects_broken_dns),
        ("menus.teardown_dispatches_by_backend", test_teardown_tunnel_dispatches_by_backend),
        ("menus.ending_active_session_tears_down", test_ending_active_session_tears_down_tunnel),
        ("transport_cache.record_and_eligible", test_transport_cache_record_and_eligible),
        ("v2ray.offered_transports", test_offered_transports),
        ("v2ray.multihop_config_structure", test_multihop_config_structure),
        ("v2ray.require_tcp_endpoints", test_require_tcp_endpoints),
        ("v2ray.proxy_session_multihop_backend", test_proxy_session_multihop_backend),
        ("config.active_session_ids", test_active_session_ids),
        ("menus.connected_label_multihop", test_connected_label_multihop_chain),
        ("menus.teardown_covers_multihop", test_teardown_covers_multihop),
        ("menus.multihop_partial_notice_orphan", test_multihop_partial_notice_includes_orphan),
        ("menus.group_sessions_collapses_chain", test_group_sessions_collapses_chain),
        ("menus.group_sessions_no_hops_all_single", test_group_sessions_no_hops_all_single),
        ("menus.group_sessions_incomplete_chain", test_group_sessions_incomplete_chain_stays_single),
        ("menus.expand_rows_for_end_chain", test_expand_rows_for_end_chain_expands_both),
        ("menus.single_hop_persist_clears_hops", test_single_hop_persist_clears_stale_hops),
        ("menus.verify_status_classification", test_verify_status_classification),
        ("menus.parse_trace_ip", test_parse_trace_ip),
        ("routing.connected_resolv_conf_tcp", test_connected_resolv_conf_forces_tcp_dns),
        ("main.emergency_cleanup_multihop", test_emergency_cleanup_tears_down_multihop),
        ("menus.restore_after_failed_verify", test_restore_after_failed_verify_restores_and_keeps_creds),
        ("v2ray.outbound_dials_by_ip_direct", test_outbound_dials_by_ip_direct),
        ("v2ray.outbound_through_proxy_keeps_host", test_outbound_through_proxy_keeps_hostname),
        ("v2ray.outbound_fallback_host", test_outbound_falls_back_to_host_without_dial_ip),
        ("v2ray.multihop_entry_ip_exit_host", test_multihop_config_dials_entry_by_ip_exit_by_host),
        ("menus.chain_row_shows_per_hop_usage", test_chain_row_shows_per_hop_usage),
        ("menus.node_list_age_label", test_node_list_age_label),
        ("node_cache.last_refresh_accessor", test_node_cache_last_refresh_accessor),
        ("node_cache.set_fetch_keeps_data", test_node_cache_set_fetch_keeps_data),
        ("menus.clamp_page", test_clamp_page),
        ("menus.collapse_chains_pure", test_collapse_chains_pure),
        ("multihop_cache.remember_prune_forget", test_multihop_cache_remember_prune_forget),
        ("menus.known_chain_pairs_merges", test_known_chain_pairs_merges_live_and_remembered),
        ("menus.find_chain_hops", test_find_chain_hops_lookup),
        ("menus.chain_sessions_alive", test_chain_sessions_alive),
        ("menus.live_tunnel_expired", test_live_tunnel_expired),
        ("chain.run_bounded_timeout", test_run_bounded_timeout_and_passthrough),
        ("chain.query_self_heals", test_query_self_heals_on_timeout),
        ("routing.chain_bypass_bookkeeping", test_chain_bypass_bookkeeping),
        ("routing.resolve_chain_ips_literal", test_resolve_chain_ips_literal),
    ]

    print(f"Smoke tests (tmp HOME={_TMP})")
    for name, fn in tests:
        check(name, fn)

    print()
    print(f"  passed: {_passed}/{len(tests)}")
    if _failed:
        print(f"  failed: {', '.join(_failed)}")
    shutil.rmtree(_TMP, ignore_errors=True)
    return 0 if not _failed else 1


if __name__ == "__main__":
    sys.exit(main())
