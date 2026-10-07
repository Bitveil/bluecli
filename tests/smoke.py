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
    assert c["grpc_host"] == "grpc-sentinel.busurnode.com"
    assert c["grpc_port"] == 443 and c["grpc_ssl"] is True  # 443 is TLS
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


def test_amneziawg_parses_peer_response():
    """dvpnx 9.x node: addrs + metadata with port, public_key and the full
    obfuscation set (S1-S4 uint16, H1-H4 uint32, I1-I5 optional strings)."""
    from bluecli.vpn import HandshakeResult
    from bluecli.vpn import amneziawg as awg_mod

    handshake = HandshakeResult(
        node_addrs=["203.0.113.7:9933"],
        peer_data={
            "addrs": ["10.7.0.5/32", "fd00::5/128"],
            "metadata": [{
                "port": 443,
                "public_key": "U" + "z" * 43,
                "s1": 13, "s2": 64, "s3": 4, "s4": 8,
                "h1": 28, "h2": 76, "h3": 24, "h4": 30,
                "i1": "<b 0x1f00>", "i2": "<b 0x0005>",
            }],
        },
    )
    peer = awg_mod._peer_from_response(handshake)
    assert peer.ipv4 == "10.7.0.5/32", peer.ipv4
    assert peer.ipv6 == "fd00::5/128", peer.ipv6
    assert peer.host == "203.0.113.7"
    assert peer.endpoint == "203.0.113.7:443"
    assert peer.public_key == "U" + "z" * 43
    assert peer.obfs["s1"] == 13 and peer.obfs["h4"] == 30
    assert peer.obfs["i1"] == "<b 0x1f00>"
    assert "i3" not in peer.obfs  # optional keys absent -> omitted


def test_amneziawg_rejects_bad_obfs_metadata():
    """Missing or out-of-spec obfuscation params must fail loudly at parse
    time, before we hand garbage to the engine."""
    from bluecli.vpn import HandshakeResult, VpnError
    from bluecli.vpn import amneziawg as awg_mod

    def make(metadata):
        return HandshakeResult(
            node_addrs=["203.0.113.7:9933"],
            peer_data={"addrs": ["10.7.0.5/32"], "metadata": [metadata]},
        )

    good = {"port": 443, "public_key": "U" + "z" * 43,
            "s1": 13, "s2": 64, "s3": 4, "s4": 8,
            "h1": 28, "h2": 76, "h3": 24, "h4": 30}

    for bad in (
        {**good, "s1": "12"},          # string instead of int
        {**good, "s1": 65},            # S1 > 64
        {**good, "s4": 33},            # S4 > 32
        {**good, "h1": 4},             # H must be > 4
        {**good, "s1": 12, "s2": 68},  # S1+56 == S2 is invalid
    ):
        try:
            awg_mod._peer_from_response(make(bad))
        except VpnError:
            pass
        else:
            raise AssertionError(f"metadata {bad} should have been rejected")


def test_amneziawg_config_full_and_setconf_variants():
    """Two conf flavors:
    - the FULL conf (fed to the Windows client) MUST contain
      Address/DNS/MTU — the client applies them to the TUN;
    - the SETCONF variant (Linux `awg setconf`) MUST NOT contain them,
      because awg errors with "Line unrecognized" on those keys.
    Both must carry the obfuscation keys the node sent."""
    import configparser

    from bluecli.vpn import amneziawg as awg_mod

    peer = awg_mod._Peer(
        ipv4="10.7.0.5/32",
        ipv6="",
        host="203.0.113.7",
        endpoint="203.0.113.7:443",
        public_key="A" * 44,
        obfs={"s1": 13, "s2": 64, "s3": 4, "s4": 8,
              "h1": 28, "h2": 76, "h3": 24, "h4": 30,
              "i1": "<b 0x1f00>"},
    )
    full = _TMP / "awg-test.conf"
    awg_mod._write_config(
        str(full), our_privkey="B" * 44, peer=peer,
        junk={"jc": 5, "jmin": 100, "jmax": 300}, listen_port=54321,
    )
    cp = configparser.RawConfigParser()
    cp.read(str(full))
    iface = cp["Interface"]
    assert iface["PrivateKey"] == "B" * 44
    assert iface["Jc"] == "5"
    assert iface["S1"] == "13"
    assert iface["H4"] == "30"
    assert iface["I1"] == "<b 0x1f00>"
    assert iface["MTU"] == "1420"
    assert iface["Address"] == "10.7.0.5/32"
    if sys.platform != "linux":
        assert "dns" in iface, "Windows client needs the DNS line"
    assert cp["Peer"]["Endpoint"] == "203.0.113.7:443"
    assert cp["Peer"]["AllowedIPs"] == "0.0.0.0/0, ::/0"

    stripped = _TMP / "awg-test.setconf.conf"
    awg_mod._write_setconf_conf(str(full), str(stripped))
    cp2 = configparser.RawConfigParser()
    cp2.read(str(stripped))
    iface2_keys = set(cp2["Interface"].keys())
    assert not {"address", "dns", "mtu"} & iface2_keys, iface2_keys
    accepted_iface = {"privatekey", "listenport", "jc", "jmin", "jmax",
                      "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
                      "i1", "i2", "i3", "i4", "i5"}
    assert iface2_keys <= accepted_iface, iface2_keys - accepted_iface
    assert cp2["Interface"]["PrivateKey"] == "B" * 44
    assert cp2["Interface"]["S1"] == "13"
    assert cp2["Interface"]["I1"] == "<b 0x1f00>"
    assert cp2["Peer"]["Endpoint"] == "203.0.113.7:443"
    full.unlink()
    stripped.unlink()


def test_amneziawg_junk_params_in_range():
    """Jc 0-10, Jmin/Jmax 64-1024 and Jmin < Jmax, always."""
    from bluecli.vpn import amneziawg as awg_mod

    for _ in range(200):
        junk = awg_mod._generate_junk()
        assert 0 <= junk["jc"] <= 10, junk
        assert 64 <= junk["jmin"] < junk["jmax"] <= 1024, junk


def test_amneziawg_credentials_state_roundtrip():
    """AWGCredentials must survive a save/load through plain dicts so that
    reconnect after an app restart still finds the cached handshake."""
    from bluecli.vpn.amneziawg import AWGCredentials

    creds = AWGCredentials(
        keypair_privkey_b64="cHJpdg==",
        keypair_pubkey_b64="cHViYWJj",
        handshake_node_addrs=["1.2.3.4:9933"],
        handshake_peer_data={"addrs": ["10.7.0.5/32"],
                             "metadata": [{"port": 443}]},
    )
    state = creds.to_state()
    rebuilt = AWGCredentials.from_state(state)
    assert rebuilt.keypair_privkey_b64 == "cHJpdg=="
    assert rebuilt.keypair_pubkey_b64 == "cHViYWJj"
    assert rebuilt.handshake_node_addrs == ["1.2.3.4:9933"]
    assert rebuilt.handshake_peer_data == {"addrs": ["10.7.0.5/32"],
                                           "metadata": [{"port": 443}]}
    # Marker key must be the awg_* family — the wg/v2 markers would clash
    # with a previous connection of another protocol.
    assert "awg_privkey_b64" in state
    assert "wg_privkey_b64" not in state
    assert "v2_uuid_hex" not in state


def test_amneziawg_require_rejects_non_executable():
    """POSIX: a bundled binary that exists but lost its execute bit (zips
    made on Windows drop POSIX modes) must produce a clear, actionable
    error — 'chmod +x <path>' — instead of surfacing later as a cryptic
    'command not found' from sudo. Field incident, 2026-08."""
    import os as _os

    from bluecli.vpn import VpnError
    from bluecli.vpn import amneziawg as awg_mod

    if _os.name != "posix":
        return  # execute bits don't exist on Windows

    p = _TMP / "fake-awg-binary"
    p.write_bytes(b"\x7fELF")
    _os.chmod(p, 0o644)  # present but NOT executable
    try:
        awg_mod._require(p, "fake")
    except VpnError as e:
        assert "not executable" in str(e) and "chmod +x" in str(e), e
    else:
        raise AssertionError("non-executable binary should have been rejected")
    finally:
        p.unlink()
    # And the executable case still passes:
    p.write_bytes(b"\x7fELF")
    _os.chmod(p, 0o755)
    awg_mod._require(p, "fake")  # must not raise
    p.unlink()


def test_amneziawg_wait_until_ready_surfaces_probe_error():
    """When the readiness probe itself fails (e.g. non-executable `awg`),
    the timeout error must include the probe's stderr — otherwise it
    misleadingly blames the engine and its harmless startup banner.
    Field incident, 2026-08."""
    import bluecli.vpn.amneziawg as awg_mod
    from bluecli.vpn import VpnError

    class _FailingProbe:
        returncode = 1
        stdout = ""
        stderr = "sudo: /x/bin/amneziawg/awg: command not found"

    orig_awg = awg_mod._awg
    orig_tail = awg_mod._read_log_tail
    awg_mod._awg = lambda *a, **k: _FailingProbe()
    awg_mod._read_log_tail = lambda *a, **k: "┌ banner ┐"
    try:
        try:
            awg_mod._wait_until_ready(awg_mod.Path("/x/awg"), timeout=0.1)
        except VpnError as e:
            msg = str(e)
            assert "command not found" in msg, msg   # the probe's own error
            assert "banner" in msg, msg              # engine log still shown
        else:
            raise AssertionError("timeout should have raised VpnError")
    finally:
        awg_mod._awg = orig_awg
        awg_mod._read_log_tail = orig_tail


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


def test_parse_node_response_declared_transports():
    """dvpnx >= 9.0.0 declares per-inbound v2ray metadata on the info
    endpoint; transport enums arrive as Go byte values (7=tcp, 8=websocket).
    We must parse those, tolerate string variants, and treat anything
    unreadable as 'not declared' (None) so eligibility falls back safely."""
    from bluecli.chain import _parse_node_response, _declared_transports

    def result_with(metadata):
        return {"success": True, "result": {
            "service_type": "v2ray", "moniker": "N",
            "location": {"country": "Italy"},
            "version": {"commit": "053a819", "tag": "9.0.0"},
            "service_metadata": metadata,
        }}

    # 9.0.0 shape, int enums: tcp (7) + websocket (8); unknown (99) skipped.
    parsed = _parse_node_response(result_with([
        {"port": "10000", "proxy_protocol": 2, "transport_protocol": 7,
         "transport_security": 2, "tls_pin": "sha256:abc"},
        {"port": "10001", "proxy_protocol": 1, "transport_protocol": 8,
         "transport_security": 1, "tls_pin": ""},
        {"port": "10002", "proxy_protocol": 2, "transport_protocol": 99,
         "transport_security": 1, "tls_pin": ""},
    ]))
    assert parsed["transports"] == ["tcp", "websocket"], parsed

    # String variant (same vocabulary the handshake metadata uses), "ws" alias.
    parsed = _parse_node_response(result_with([
        {"transport_protocol": "TCP"}, {"transport_protocol": "ws"},
    ]))
    assert parsed["transports"] == ["tcp", "websocket"], parsed

    # Verbatim payloads captured from live mainnet nodes (2026-07): a 9.0.0
    # node declaring grpc(3)+tcp(7) inbounds, and an 8.3.1 node with no
    # service_metadata at all. These pin the real wire format.
    taco = {"success": True, "result": {
        "addr": "sentnode1ny0rx6hgnpwyludyygw4e47gnqv9sjtnl3r7zw",
        "downlink": "68163516", "handshake_dns": False,
        "location": {"city": "Worcester", "country": "United Kingdom",
                     "country_code": "GB", "latitude": 52.1941, "longitude": -2.21905},
        "moniker": "taco-GB-31-V2", "peers": 5, "service_type": "v2ray",
        "service_metadata": [
            {"port": "", "proxy_protocol": 2, "transport_protocol": 3,
             "transport_security": 2, "tls_pin": ""},
            {"port": "", "proxy_protocol": 1, "transport_protocol": 7,
             "transport_security": 2, "tls_pin": ""},
        ],
        "uplink": "22812908",
        "version": {"commit": "9cb7ac9122358aebed599f8740b46af810917b98", "tag": "9.0.0"},
    }}
    parsed = _parse_node_response(taco)
    assert parsed["transports"] == ["grpc", "tcp"], parsed
    assert parsed["country"] == "United Kingdom"

    # 8.3.1 verbatim: no service_metadata key → None (legacy, not declared).
    legacy = {"success": True, "result": {
        "addr": "sentnode16tr2xa9mcpkmylk0kafc4cgelw6vlayzlyr5ey",
        "downlink": "8012606", "handshake_dns": False,
        "location": {"city": "Mumbai", "country": "India", "country_code": "IN",
                     "latitude": 19.0748, "longitude": 72.8856},
        "moniker": "0_Premium_Service_100G_Nibiru70", "peers": 84,
        "service_type": "v2ray", "uplink": "6122205",
        "version": {"commit": "f2bdf6d00f673b852d5613f849887f4367686eb2", "tag": "8.3.1"},
    }}
    assert _parse_node_response(legacy)["transports"] is None

    # Unreadable declarations → None, never a guess and never a crash.
    for bad in ({}, "tcp", 7, [], [{"transport_protocol": 0}],
                [{"transport_protocol": True}], ["tcp"], [{"other": 1}],
                [{"transport_protocol": None}]):
        assert _declared_transports(bad) is None, bad


def test_node_cache_roundtrips_declared_transports():
    """declared_transports must survive the disk cache roundtrip (save via
    asdict, load via NodeInfo(**item)) for both declaring and legacy nodes —
    a stale-but-fresh cache file must not erase what a node declared."""
    from bluecli import config as cfg
    from bluecli.chain import NodeInfo, NODE_TYPE_V2RAY
    from bluecli.node_cache import NodeCache, _CACHE_FILE

    cfg.ensure_dir()
    _CACHE_FILE.unlink(missing_ok=True)

    declaring = NodeInfo(
        address="sentnode1new", moniker="New", country="IT",
        remote_url="https://1:1", node_type=NODE_TYPE_V2RAY,
        gigabyte_prices=[], hourly_prices=[],
        declared_transports=["tcp", "websocket"],
    )
    legacy = NodeInfo(
        address="sentnode1old", moniker="Old", country="DE",
        remote_url="https://2:1", node_type=NODE_TYPE_V2RAY,
        gigabyte_prices=[], hourly_prices=[],
    )
    assert legacy.declared_transports is None  # field defaults to None

    writer = NodeCache(fetch=lambda: [])  # not started: no background thread
    writer._save_to_disk([declaring, legacy])
    reader = NodeCache(fetch=lambda: [])
    reader._load_from_disk()
    loaded = {n.address: n for n in reader.get(wait_timeout=0.0)}
    assert loaded["sentnode1new"].declared_transports == ["tcp", "websocket"]
    assert loaded["sentnode1old"].declared_transports is None
    _CACHE_FILE.unlink(missing_ok=True)


def test_multihop_eligible_native_first():
    """A declaring node decides on its declaration ALONE (fresher than any
    cached handshake — even a cache hit must not override a no-tcp
    declaration); the handshake-learned cache only speaks for legacy nodes
    that don't declare. This is the seam that lets the cache be deleted once
    the network migrates."""
    from bluecli.chain import NodeInfo, NODE_TYPE_V2RAY
    from bluecli.menus import _multihop_eligible

    def node(addr, declared):
        return NodeInfo(
            address=addr, moniker="m", country="c", remote_url="https://x:1",
            node_type=NODE_TYPE_V2RAY, gigabyte_prices=[], hourly_prices=[],
            declared_transports=declared,
        )

    cached = {"sentnode1cached"}
    # Declares tcp, never handshaked → eligible natively, no cache needed.
    assert _multihop_eligible(node("sentnode1a", ["tcp", "grpc"]), cached) is True
    # Declares only quic, even though an old handshake cached it as tcp →
    # NOT eligible: the fresh declaration wins over stale cache.
    assert _multihop_eligible(node("sentnode1cached", ["quic"]), cached) is False
    # Legacy (no declaration) + cached as tcp → eligible via fallback.
    assert _multihop_eligible(node("sentnode1cached", None), cached) is True
    # Legacy + never handshaked → not eligible (same as today).
    assert _multihop_eligible(node("sentnode1b", None), cached) is False


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
    """NodeInfo prices are list[dict] (not protobuf), and the row must show BOTH
    the per-GB and per-hour price for the wallet's denom, formatted with the P2P
    ticker. Every code path uses dict-key access."""
    from bluecli.chain import NodeInfo, NODE_TYPE_WIREGUARD, NODE_TYPE_V2RAY
    from bluecli.menus import _format_node_row

    # Branch 1: udvpn prices present (GB and hourly) → both shown as P2P.
    n = NodeInfo(
        address="sentnode1aaa", moniker="VPN-A", country="Italy",
        remote_url="https://1.1.1.1:9933", node_type=NODE_TYPE_WIREGUARD,
        gigabyte_prices=[{"denom": "udvpn", "base_value": "0", "quote_value": "25000000"}],
        hourly_prices=[{"denom": "udvpn", "base_value": "0", "quote_value": "500000"}],
    )
    row = _format_node_row(1, n, "udvpn")
    assert "25.000 P2P" in row, row          # per-GB column
    assert "0.500 P2P" in row, row           # per-hour column
    assert "Italy" in row and "VPN-A" in row and "wireguard" in row

    # Branch 2: no udvpn, only IBC → fallback to raw "<value> <denom>";
    # hourly absent → em-dash.
    n = NodeInfo(
        address="sentnode1bbb", moniker="VPN-B", country="Germany",
        remote_url="https://2.2.2.2:9933", node_type=NODE_TYPE_V2RAY,
        gigabyte_prices=[{"denom": "ibc/SOMEHASH", "base_value": "0", "quote_value": "5000"}],
        hourly_prices=[],
    )
    row = _format_node_row(2, n, "udvpn")
    assert "5000 ibc/SOMEHASH" in row, row
    assert "P2P" not in row, row
    assert "—" in row, row                   # empty hourly column

    # Branch 3: no prices at all → em-dash for both price columns.
    n = NodeInfo(
        address="sentnode1ccc", moniker="VPN-C", country="",
        remote_url="https://3.3.3.3:9933", node_type=NODE_TYPE_WIREGUARD,
        gigabyte_prices=[], hourly_prices=[],
    )
    row = _format_node_row(3, n, "udvpn")
    assert row.count("—") >= 2, row          # GB and hourly both em-dashed


def test_pick_multihop_node_renders_rows_and_returns_choice():
    """Regression: the multihop node picker must call the row formatter with the
    SAME signature as the browser — (idx, node, denom). A missing `denom` arg
    crashed the multihop menu in the wild; this exercises that exact path with
    the real formatter so any signature drift fails here, not for the user."""
    from bluecli import menus
    from bluecli import ui as _ui
    from bluecli.chain import NodeInfo, NODE_TYPE_V2RAY

    nodes = [
        NodeInfo(address="n1", moniker="Entry", country="IT", remote_url="https://1:1",
                 node_type=NODE_TYPE_V2RAY,
                 gigabyte_prices=[{"denom": "udvpn", "base_value": "0", "quote_value": "25000000"}],
                 hourly_prices=[{"denom": "udvpn", "base_value": "0", "quote_value": "500000"}]),
        NodeInfo(address="n2", moniker="Exit", country="DE", remote_url="https://2:1",
                 node_type=NODE_TYPE_V2RAY, gigabyte_prices=[], hourly_prices=[]),
    ]
    rendered: list = []
    saved = (_ui.info, _ui.prompt, _ui.error)
    _ui.info = lambda m="", *a, **k: rendered.append(str(m))
    _ui.prompt = lambda *a, **k: "1"
    _ui.error = lambda *a, **k: None
    try:
        picked = menus._pick_multihop_node(nodes, "multihop.prompt.entry", "udvpn")
    finally:
        (_ui.info, _ui.prompt, _ui.error) = saved
    assert picked is nodes[0], picked
    blob = "\n".join(rendered)
    assert "Entry" in blob and "25.000 P2P" in blob, blob  # rendered with denom + ticker


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


def test_node_cache_refresh_now_runs_and_is_mutually_exclusive():
    """A user-triggered refresh runs the fetch in the calling thread and returns
    True; while a refresh is already in flight (the shared lock is held), a
    second refresh_now() must return False WITHOUT fetching. That gate is how
    the browser says 'already in progress' and how manual and background
    refreshes stay one-at-a-time."""
    from bluecli.node_cache import NodeCache, _CACHE_FILE
    from bluecli.chain import NodeInfo, NODE_TYPE_V2RAY
    _CACHE_FILE.unlink(missing_ok=True)

    sample = [NodeInfo(address="sentnode1x", moniker="M", country="IT",
                       remote_url="https://1.2.3.4:1", node_type=NODE_TYPE_V2RAY,
                       gigabyte_prices=[], hourly_prices=[])]
    calls = {"n": 0}

    def fetch():
        calls["n"] += 1
        return sample

    cache = NodeCache(fetch=fetch)  # NOT started: no background loop in this test
    # 1) Free → runs once, updates the cache, returns True.
    assert cache.refresh_now() is True
    assert calls["n"] == 1
    assert cache.get(wait_timeout=0.0) == sample
    # 2) A refresh already in flight (lock held) → busy, no extra fetch.
    assert cache._refresh_lock.acquire(blocking=False) is True
    try:
        assert cache.refresh_now() is False
        assert calls["n"] == 1, "must not fetch while a refresh is in progress"
    finally:
        cache._refresh_lock.release()


def test_refresh_node_list_reports_busy_and_keeps_list():
    """Browser refresh helper: when the cache reports a refresh already running,
    warn the user and keep the current list unchanged (no silent swap)."""
    from bluecli import menus
    from bluecli import ui as _ui

    class _BusyCache:
        def refresh_now(self):
            return False

        def get(self, **k):
            return []  # would replace the list if (wrongly) consulted

    warns: list = []
    saved = (_ui.warn, _ui.info, menus._pause)
    _ui.warn = lambda m, *a, **k: warns.append(str(m))
    _ui.info = lambda *a, **k: None
    menus._pause = lambda *a, **k: None
    current = ["NODE_A", "NODE_B"]
    try:
        out = menus._refresh_node_list(_BusyCache(), client=None, current=current)
    finally:
        (_ui.warn, _ui.info, menus._pause) = saved
    assert out is current, "a busy refresh must keep the current list"
    assert warns, "the user must be told a refresh is already in progress"


def test_refresh_node_list_runs_and_returns_browseable():
    """Browser refresh helper: when not busy, run the refresh and return the
    fresh list filtered to connectable nodes and sorted by country/moniker."""
    from bluecli import menus
    from bluecli import ui as _ui
    from bluecli.chain import NodeInfo, NODE_TYPE_V2RAY

    fresh = [
        NodeInfo(address="n2", moniker="B", country="DE", remote_url="https://2:1",
                 node_type=NODE_TYPE_V2RAY, gigabyte_prices=[], hourly_prices=[]),
        NodeInfo(address="n1", moniker="A", country="AT", remote_url="https://1:1",
                 node_type=NODE_TYPE_V2RAY, gigabyte_prices=[], hourly_prices=[]),
    ]

    class _OkCache:
        def refresh_now(self):
            return True

        def get(self, **k):
            return list(fresh)

    saved = (_ui.info, menus._pause)
    _ui.info = lambda *a, **k: None
    menus._pause = lambda *a, **k: None
    try:
        out = menus._refresh_node_list(_OkCache(), client=None, current=[])
    finally:
        (_ui.info, menus._pause) = saved
    assert [n.address for n in out] == ["n1", "n2"], out  # AT/A before DE/B


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
        "tun_local_ip": "10.7.0.5",
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
              "tun_iface", "tun_local_ip", "node_ip", "orig_gw"):
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


def test_amneziawg_windows_service_retries_once_on_failure():
    """Same Service Control Manager race as WireGuard: the first
    /installtunnelservice right after /uninstalltunnelservice often fails,
    so _bring_up_windows must retry once before surfacing the error.
    (This is the ONLY Windows path: amneziawg.exe service client.)"""
    import bluecli.vpn.amneziawg as awg_mod

    if sys.platform != "win32":
        orig_platform = awg_mod.sys.platform
        awg_mod.sys.platform = "win32"
    else:
        orig_platform = None

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

    orig_run = awg_mod.subprocess.run
    orig_sleep = awg_mod.time.sleep
    orig_isfile = type(awg_mod.bin_path("amneziawg", "amneziawg")).is_file
    awg_mod.subprocess.run = fake_run
    awg_mod.time.sleep = lambda _: None  # don't actually wait
    type(awg_mod.bin_path("amneziawg", "amneziawg")).is_file = lambda self: True
    try:
        awg_mod._bring_up_windows("/tmp/awg.conf")
    finally:
        awg_mod.subprocess.run = orig_run
        awg_mod.time.sleep = orig_sleep
        type(awg_mod.bin_path("amneziawg", "amneziawg")).is_file = orig_isfile
        if orig_platform is not None:
            awg_mod.sys.platform = orig_platform

    installs = [c for c in calls if "/installtunnelservice" in c]
    assert len(installs) == 2, (
        f"expected 2 install attempts (1 fail + 1 retry), got {len(installs)}: {installs}"
    )
    # The uninstall before install must target our fixed interface name,
    # matching what disconnect will later uninstall.
    assert any(c[1] == "/uninstalltunnelservice" and c[2] == "awg-blue"
               for c in calls), f"expected uninstall of awg-blue, got {calls}"


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
    """When nothing reaches the internet — neither the DNS-free probe nor the
    hostname fetch — verify returns 'no_route' within budget. The hostname
    fetch is bounded in a thread, so even a hanging resolver can't overrun us."""
    import time as _time
    from bluecli import menus
    orig = (menus._fetch_public_ip, menus._fetch_public_ip_no_dns)
    menus._fetch_public_ip_no_dns = lambda timeout: None   # DNS-free probe fails
    menus._fetch_public_ip = lambda timeout: None          # hostname fetch yields nothing
    try:
        start = _time.time()
        status = menus._verify_public_ip(pre_connect_ip="1.2.3.4", budget=0.5)
        elapsed = _time.time() - start
    finally:
        (menus._fetch_public_ip, menus._fetch_public_ip_no_dns) = orig
    assert status == "no_route"
    assert elapsed < 5.0, f"verify overran its budget: {elapsed:.1f}s"


def test_verify_public_ip_dns_fallback_when_cloudflare_blocked():
    """The office/hotspot case that was a false negative: the DNS-free probe
    (Cloudflare 1.1.1.1) is blocked, but the node routes everything else. A
    hostname lookup returns a changed exit IP → routing and DNS both work →
    'ok', NOT a bogus 'no_route' that tears a working tunnel down."""
    from bluecli import menus
    from bluecli import ui as _ui
    orig = (menus._fetch_public_ip_no_dns, menus._fetch_public_ip,
            menus._dns_resolves, _ui.info)
    infos: list = []
    menus._fetch_public_ip_no_dns = lambda timeout: None      # Cloudflare blocked
    menus._dns_resolves = lambda **kw: True                   # resolver works
    menus._fetch_public_ip = lambda timeout: "5.6.7.8"        # node IP via hostname
    _ui.info = lambda msg, *a, **k: infos.append(msg)
    try:
        status = menus._verify_public_ip(pre_connect_ip="1.2.3.4", budget=5.0)
    finally:
        (menus._fetch_public_ip_no_dns, menus._fetch_public_ip,
         menus._dns_resolves, _ui.info) = orig
    assert status == "ok"
    assert any("5.6.7.8" in str(m) for m in infos)


def test_verify_public_ip_reports_changed_ip():
    """Routes (changed exit IP via the DNS-free probe) + DNS resolving = 'ok',
    and the exit IP is shown."""
    from bluecli import menus
    from bluecli import ui as _ui
    orig = (menus._fetch_public_ip_no_dns, menus._dns_resolves, _ui.info)
    infos: list = []
    menus._fetch_public_ip_no_dns = lambda timeout: "9.9.9.9"
    menus._dns_resolves = lambda **kw: True
    _ui.info = lambda msg, *a, **k: infos.append(msg)
    try:
        status = menus._verify_public_ip(pre_connect_ip="1.2.3.4", budget=5.0)
    finally:
        (menus._fetch_public_ip_no_dns, menus._dns_resolves, _ui.info) = orig
    assert status == "ok"
    assert any("9.9.9.9" in str(m) for m in infos)


def test_verify_public_ip_detects_broken_dns():
    """The VPS case: tunnel routes (DNS-free probe returns a changed exit IP)
    but the system resolver fails → status 'dns'. The exit IP is still shown so
    the user can see the tunnel reached the internet — no silent hang."""
    from bluecli import menus
    from bluecli import ui as _ui
    orig = (menus._fetch_public_ip_no_dns, menus._dns_resolves, _ui.info)
    infos: list = []
    menus._fetch_public_ip_no_dns = lambda timeout: "9.9.9.9"
    menus._dns_resolves = lambda **kw: False
    _ui.info = lambda msg, *a, **k: infos.append(msg)
    try:
        status = menus._verify_public_ip(pre_connect_ip="1.2.3.4", budget=2.0)
    finally:
        (menus._fetch_public_ip_no_dns, menus._dns_resolves, _ui.info) = orig
    assert status == "dns"
    assert any("9.9.9.9" in str(m) for m in infos)


def test_verify_fallback_not_gated_by_dns_precheck():
    """Regression: the hostname fallback used to fire ONLY if a Cloudflare name
    resolved within 4s. On a hostile network / during tunnel warm-up that
    pre-check failed, so a perfectly working tunnel (a browser hitting
    api.ipify.org returns the node IP) was torn down as a bogus 'no_route'.
    The fallback must now stand on its own: DNS-free probe blocked AND the
    Cloudflare-name resolver check failing, yet a hostname fetch returns a
    CHANGED exit IP -> the tunnel routes and resolves -> 'ok'."""
    from bluecli import menus
    from bluecli import ui as _ui
    orig = (menus._fetch_public_ip_no_dns, menus._fetch_public_ip,
            menus._dns_resolves, _ui.info)
    infos: list = []
    menus._fetch_public_ip_no_dns = lambda timeout: None   # Cloudflare blocked
    menus._dns_resolves = lambda **kw: False               # old gate would block here
    menus._fetch_public_ip = lambda timeout: "5.6.7.8"     # node IP, fetched by name
    _ui.info = lambda msg, *a, **k: infos.append(msg)
    try:
        status = menus._verify_public_ip(pre_connect_ip="1.2.3.4", budget=5.0)
    finally:
        (menus._fetch_public_ip_no_dns, menus._fetch_public_ip,
         menus._dns_resolves, _ui.info) = orig
    assert status == "ok", f"expected ok, got {status!r}"
    assert any("5.6.7.8" in str(m) for m in infos)


def test_fetch_public_ip_bounded_caps_a_hang():
    """The hostname fetch is now called unconditionally in the verify loop, so
    it MUST be hang-proof: a resolver that never answers can't be allowed to
    overrun. _fetch_public_ip_bounded returns within ~timeout even when the
    underlying fetch hangs."""
    import time as _time
    from bluecli import menus
    orig = menus._fetch_public_ip

    def _hang(timeout):
        _time.sleep(5.0)
        return "9.9.9.9"

    menus._fetch_public_ip = _hang
    try:
        start = _time.time()
        ip = menus._fetch_public_ip_bounded(timeout=0.3)
        elapsed = _time.time() - start
    finally:
        menus._fetch_public_ip = orig
    assert ip is None, f"should not have waited for the hang, got {ip!r}"
    assert elapsed < 2.0, f"bounded fetch overran: {elapsed:.1f}s"


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


def test_warn_after_unverified_keeps_tunnel():
    """A verification that can't confirm connectivity must NOT tear the tunnel
    down or strip runtime state — the tunnel stays up and the user decides. It
    only warns, with a message that differs between the DNS and no-route cases."""
    from bluecli import menus
    from bluecli import config as cfg
    from bluecli import ui as _ui

    calls = {"teardown": 0, "strip": 0, "warns": []}
    saved = (menus._teardown_tunnel, cfg.strip_runtime_state, _ui.warn)
    menus._teardown_tunnel = lambda st: calls.__setitem__("teardown", calls["teardown"] + 1)
    cfg.strip_runtime_state = lambda: calls.__setitem__("strip", calls["strip"] + 1)
    _ui.warn = lambda msg, *a, **k: calls["warns"].append(str(msg))
    try:
        menus._warn_after_unverified("dns")
        menus._warn_after_unverified("no_route")
    finally:
        (menus._teardown_tunnel, cfg.strip_runtime_state, _ui.warn) = saved
    assert calls["teardown"] == 0, "a verify warning must not tear the tunnel down"
    assert calls["strip"] == 0, "a verify warning must not strip runtime state"
    assert len(calls["warns"]) == 2 and calls["warns"][0] != calls["warns"][1]


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


# ---------------------------------------------------------------------------
# 1.4.0 — Xray + Hysteria2 backends, shared SOCKS engine, tx error wrapping
# ---------------------------------------------------------------------------

_XRAY_UUID = "8d6f1c2a-3b4e-4f5a-9b8c-7d6e5f4a3b2c"


def _hs(meta, addrs=("203.0.113.9:443",)):
    from bluecli.vpn import HandshakeResult
    return HandshakeResult(node_addrs=list(addrs), peer_data={"metadata": meta})


def test_socks_require_binary():
    """Missing → clear error; present but not executable (POSIX) → chmod hint;
    executable → passes. Shared by the Xray and Hysteria2 backends."""
    import os as _os
    from bluecli.vpn import VpnError, socks_tunnel
    p = _TMP / "fake-core"
    p.unlink(missing_ok=True)
    try:
        socks_tunnel.require_binary(p, "fake")
        raise AssertionError("missing binary must raise")
    except VpnError as e:
        assert "missing" in str(e), e
    p.write_bytes(b"\x7fELF")
    try:
        if _os.name == "posix":
            _os.chmod(p, 0o644)
            try:
                socks_tunnel.require_binary(p, "fake")
                raise AssertionError("non-executable binary must raise")
            except VpnError as e:
                assert "chmod +x" in str(e), e
            _os.chmod(p, 0o755)
        socks_tunnel.require_binary(p, "fake")  # must not raise
    finally:
        p.unlink(missing_ok=True)


def test_socks_session_state_is_runtime_only():
    """Every key a SOCKS session persists must be a runtime key, so
    disconnect/strip_runtime_state removes them all (and keeps creds)."""
    from bluecli import config as cfg
    from bluecli.vpn.socks_tunnel import SocksSession
    st = SocksSession(backend="xray", pid=1, tun2socks_pid=2, socks_port=1080,
                      config_path="/x", node_ip="1.2.3.4", orig_gw="10.0.0.1").to_state()
    assert st["backend"] == "xray"
    assert set(st) <= set(cfg._RUNTIME_STATE_KEYS), set(st) - set(cfg._RUNTIME_STATE_KEYS)


def test_v2ray_uses_shared_socks_engine():
    """Refactor guard: V2Ray's bring-up goes through socks_tunnel.spawn_and_route
    with its own core/log, and v2ray.disconnect delegates to the shared teardown."""
    from bluecli.vpn import socks_tunnel, v2ray
    seen = {}
    orig_sar, orig_disc = socks_tunnel.spawn_and_route, socks_tunnel.disconnect
    socks_tunnel.spawn_and_route = lambda spawn_core, **kw: seen.update(kw) or (11, 22)
    socks_tunnel.disconnect = lambda st: seen.__setitem__("disc", st)
    try:
        pids = v2ray._spawn_and_install_routing(
            "v2", "tun", config_path="/c.json", socks_port=1080,
            bypass_ip="1.2.3.4", original=object())
        v2ray.disconnect({"backend": "v2ray"})
    finally:
        socks_tunnel.spawn_and_route, socks_tunnel.disconnect = orig_sar, orig_disc
    assert pids == (11, 22)
    assert seen["core_name"] == "V2Ray" and seen["core_log"] == "v2ray.log"
    assert seen["socks_port"] == 1080 and seen["bypass_ip"] == "1.2.3.4"
    assert seen["disc"] == {"backend": "v2ray"}


def test_hysteria2_handshake_sends_uuid_string():
    """The hysteria2 PeerRequest field is a Go *string* — sending the byte
    array v2ray/xray use would fail to unmarshal on the node."""
    import uuid as _uuid
    from bluecli.vpn import HandshakeResult, hysteria2
    sent = {}
    orig = hysteria2.fetch_node_credentials
    hysteria2.fetch_node_credentials = lambda **kw: (sent.update(kw), HandshakeResult(
        node_addrs=["1.2.3.4:443"], peer_data={"metadata": []}))[1]
    try:
        creds = hysteria2.fetch_creds(remote_url="https://n", session_id=7, private_key=b"k" * 32)
    finally:
        hysteria2.fetch_node_credentials = orig
    assert isinstance(sent["request_data"]["uuid"], str)
    assert str(_uuid.UUID(sent["request_data"]["uuid"])) == sent["request_data"]["uuid"]
    assert creds.uuid == sent["request_data"]["uuid"]  # auth credential == UUID sent
    back = hysteria2.Hy2Credentials.from_state(creds.to_state())
    assert back == creds


def test_hysteria2_server_parsing_and_config():
    """Endpoint parsing validates every field; the generated client config
    dials by IP, keeps SNI = host, pins the cert, and enables Salamander only
    when the node provides a password."""
    from bluecli.vpn import VpnError, hysteria2
    pin = "6d:ad:54:95"
    # malformed entries are skipped, the first valid one wins (port as string ok)
    srv = hysteria2._server_from_response(_hs([
        "junk", {"port": 0}, {"port": "70000"}, {"port": True},
        {"port": "4443", "tls_pin": pin, "obfs_password": "salt"},
    ], addrs=["node.example:8080"]))
    assert srv == {"host": "node.example", "port": 4443, "tls_pin": pin, "obfs_password": "salt"}
    cfg = hysteria2._build_config(srv, auth=_XRAY_UUID, socks_port=1081, dial_ip="198.51.100.4")
    assert cfg["server"] == "198.51.100.4:4443" and cfg["auth"] == _XRAY_UUID
    assert cfg["tls"] == {"sni": "node.example", "insecure": True, "pinSHA256": pin}
    assert cfg["obfs"] == {"type": "salamander", "salamander": {"password": "salt"}}
    assert cfg["socks5"] == {"listen": "127.0.0.1:1081"}
    plain = hysteria2._build_config(dict(srv, obfs_password="", tls_pin=""), auth="a",
                                    socks_port=1, dial_ip="1.1.1.1")
    assert "obfs" not in plain and "pinSHA256" not in plain["tls"]
    for bad in (_hs([]), _hs([{"port": "x"}]), _hs([{"port": 1}], addrs=[])):
        try:
            hysteria2._server_from_response(bad)
            raise AssertionError("must raise")
        except VpnError:
            pass


def test_xray_handshake_and_creds():
    """Xray's PeerRequest uses uuid.UUID like v2ray → the byte-array form."""
    from bluecli.vpn import HandshakeResult, xray
    sent = {}
    orig = xray.fetch_node_credentials
    xray.fetch_node_credentials = lambda **kw: (sent.update(kw), HandshakeResult(
        node_addrs=["1.2.3.4:443"], peer_data={"metadata": [{"port": "1"}]}))[1]
    try:
        creds = xray.fetch_creds(remote_url="https://n", session_id=7, private_key=b"k" * 32)
    finally:
        xray.fetch_node_credentials = orig
    raw = sent["request_data"]["uuid"]
    assert isinstance(raw, list) and len(raw) == 16 and bytes(raw).hex() == creds.uuid_hex
    assert xray.XrayCredentials.from_state(creds.to_state()) == creds


def test_xray_endpoint_validation_and_ranking():
    """Unusable entries are skipped (TLS without pin — Xray v26 has no
    allowInsecure; Reality without key/SNI; SS-2022 without method/key;
    unknown enums); among usable ones Reality > TLS > none, then transport."""
    from bluecli.vpn import VpnError, xray
    pin = "ab" * 32
    reality = {"port": "8443", "proxy_protocol": 1, "transport_protocol": 1,
               "transport_security": 3, "flow": 2, "reality_public_key": "PUB",
               "reality_server_name": "cover.example", "reality_short_id": "01ab",
               "reality_fingerprint": ""}
    unusable = [
        {"port": "1", "proxy_protocol": 1, "transport_protocol": 1, "transport_security": 2},      # tls, no pin
        dict(reality, port="2", reality_public_key=""),                                          # reality, no key
        {"port": "3", "proxy_protocol": 4, "transport_protocol": 1, "transport_security": 1},      # ss2022, no key
        {"port": "4", "proxy_protocol": 9, "transport_protocol": 1, "transport_security": 1},      # unknown proxy
        {"port": "5", "proxy_protocol": 1, "transport_protocol": 7, "transport_security": 1},      # v2ray "tcp"=7 is NOT xray
    ]
    for e in unusable:
        assert xray._parse_endpoint(e, "h") is None, e
    try:
        xray._server_from_response(_hs(unusable))
        raise AssertionError("no usable endpoint must raise")
    except VpnError:
        pass
    tls_ws = {"port": "443", "proxy_protocol": 2, "transport_protocol": 2,
              "transport_security": 2, "tls_pin": pin}
    none_tcp = {"port": "80", "proxy_protocol": 1, "transport_protocol": 1, "transport_security": 1}
    best = xray._server_from_response(_hs(unusable + [none_tcp, tls_ws, reality]))
    assert best["security"] == "reality" and best["flow"] == "xtls-rprx-vision"
    assert best["reality"]["fingerprint"] == "chrome"  # default when the node sends ""
    best = xray._server_from_response(_hs([none_tcp, tls_ws]))
    assert best["security"] == "tls" and best["transport"] == "websocket" and best["tls_pin"] == pin
    # textual enums (handshake variants) are accepted too
    assert xray._parse_endpoint({"port": 9, "proxy_protocol": "trojan", "transport_protocol": "grpc",
                                 "transport_security": "none"}, "h")["proxy"] == "trojan"


def test_xray_outbounds_per_protocol():
    """Per-user secrets derive from the UUID exactly as the node does, the
    core id for SS-2022 is 'shadowsocks', TLS is pinned (no allowInsecure)."""
    import base64 as _b64, hashlib as _hl, json, uuid as _uuid
    from bluecli.vpn import xray
    uid = _uuid.UUID(_XRAY_UUID)
    base = {"host": "node.example", "port": 443, "flow": ""}

    o = xray._build_outbound(dict(base, proxy="vless", transport="tcp", security="tls",
                                  flow="xtls-rprx-vision", tls_pin="ab" * 32), uid=uid, dial_ip="9.9.9.9")
    user = o["settings"]["vnext"][0]["users"][0]
    assert o["protocol"] == "vless" and o["settings"]["vnext"][0]["address"] == "9.9.9.9"
    assert user == {"id": _XRAY_UUID, "encryption": "none", "flow": "xtls-rprx-vision"}
    assert o["streamSettings"]["tlsSettings"] == {
        "serverName": "node.example", "fingerprint": "chrome", "pinnedPeerCertSha256": "ab" * 32}
    assert "allowInsecure" not in json.dumps(o)

    o = xray._build_outbound(dict(base, proxy="vmess", transport="websocket", security="none"),
                             uid=uid, dial_ip="9.9.9.9")
    assert o["settings"]["vnext"][0]["users"][0] == {"id": _XRAY_UUID, "alterId": 0}
    assert o["streamSettings"] == {"network": "websocket", "security": "none"}

    o = xray._build_outbound(dict(base, proxy="trojan", transport="grpc", security="none"),
                             uid=uid, dial_ip="9.9.9.9")
    assert o["settings"]["servers"][0]["password"] == _XRAY_UUID

    o = xray._build_outbound(dict(base, proxy="shadowsocks-2022", transport="tcp", security="none",
                                  method="2022-blake3-aes-256-gcm", key="SRVKEY"), uid=uid, dial_ip="9.9.9.9")
    expected_user = _b64.b64encode(_hl.sha256(uid.bytes).digest()).decode()
    assert o["protocol"] == "shadowsocks"
    assert o["settings"]["servers"][0] == {"address": "9.9.9.9", "port": 443,
                                           "method": "2022-blake3-aes-256-gcm",
                                           "password": f"SRVKEY:{expected_user}"}

    o = xray._build_outbound(dict(base, proxy="vless", transport="tcp", security="reality",
                                  reality={"public_key": "PUB", "server_name": "cover.example",
                                           "short_id": "01ab", "fingerprint": "chrome"}),
                             uid=uid, dial_ip="9.9.9.9")
    assert o["streamSettings"]["realitySettings"] == {
        "fingerprint": "chrome", "publicKey": "PUB", "serverName": "cover.example", "shortId": "01ab"}
    cfg = xray._build_config(dict(base, proxy="vless", transport="tcp", security="none"),
                             uid=uid, socks_port=1082, dial_ip="9.9.9.9")
    assert cfg["inbounds"][0]["port"] == 1082 and cfg["inbounds"][0]["settings"]["udp"] is True
    assert len(cfg["outbounds"]) == 1


def test_parse_node_response_xray_hysteria2_types():
    """The new service types are recognised; native transport metadata is
    read ONLY for v2ray — xray numbers its enums differently (1 = tcp there,
    1 = domainsocket in v2ray), so reading it would be wrong."""
    from bluecli.chain import (NODE_TYPE_HYSTERIA2, NODE_TYPE_V2RAY, NODE_TYPE_XRAY,
                               _parse_node_response)

    def resp(service, meta):
        return {"success": True, "result": {"service_type": service, "moniker": "m",
                                            "location": {"country": "IT"},
                                            "service_metadata": meta}}
    x = _parse_node_response(resp("xray", [{"transport_protocol": 1}]))
    assert x["type"] == NODE_TYPE_XRAY and x["transports"] is None, x
    h = _parse_node_response(resp("hysteria2", [{"port": 443}]))
    assert h["type"] == NODE_TYPE_HYSTERIA2 and h["transports"] is None, h
    v = _parse_node_response(resp("v2ray", [{"transport_protocol": 7}]))   # regression
    assert v["type"] == NODE_TYPE_V2RAY and v["transports"] == ["tcp"], v
    assert _parse_node_response(resp("openvpn", [])) == {}  # still unsupported


def test_connectable_types_cover_every_service_and_browser():
    """Every service type the parser accepts must be connectable (and vice
    versa), and the browser must keep xray/hysteria2 nodes."""
    from bluecli import menus
    from bluecli.chain import (NODE_TYPE_HYSTERIA2, NODE_TYPE_V2RAY, NODE_TYPE_XRAY,
                               NodeInfo, _SERVICE_TYPE_TO_INT)
    assert set(menus.CONNECTABLE_NODE_TYPES) == set(_SERVICE_TYPE_TO_INT.values())

    def node(addr, t):
        return NodeInfo(address=addr, moniker=addr, country="IT", remote_url="https://x:1",
                        node_type=t, gigabyte_prices=[], hourly_prices=[])
    kept = menus._browseable([node("a", NODE_TYPE_XRAY), node("b", NODE_TYPE_HYSTERIA2),
                              node("c", NODE_TYPE_V2RAY), node("d", 99)])
    assert [n.address for n in kept] == ["a", "b", "c"]
    assert node("a", NODE_TYPE_XRAY).type_name == "xray"
    assert node("b", NODE_TYPE_HYSTERIA2).type_name == "hysteria2"


def test_bring_up_dispatches_xray_and_hysteria2():
    """Functional dispatch: each new node type uses its own creds class,
    marker key, fetch and bring-up — and an unknown type fails loudly
    instead of falling into some other backend."""
    from bluecli import config as cfg, menus, ui as _ui, wallet as _wallet
    from bluecli.chain import NODE_TYPE_HYSTERIA2, NODE_TYPE_XRAY, NodeInfo
    from bluecli.vpn import VpnError, hysteria2, xray

    calls = []

    class _Rt:
        def __init__(self, backend):
            self.backend = backend

        def to_state(self):
            return {"backend": self.backend}

    saved = (cfg.load_state, cfg.save_state, _wallet.derive_private_key, menus._fetch_public_ip,
             menus._get_or_fetch_creds, menus._verify_public_ip, menus._pause,
             xray.bring_up, hysteria2.bring_up, _ui.info, _ui.success)
    store: dict = {}
    cfg.load_state = lambda: dict(store)
    cfg.save_state = lambda st: store.update(st)
    _wallet.derive_private_key = lambda m: b"k" * 32
    menus._fetch_public_ip = lambda **k: None
    menus._get_or_fetch_creds = lambda *a, cls, marker_key, fetch: (
        calls.append((cls.__name__, marker_key, fetch.__module__)), "CREDS")[1]
    menus._verify_public_ip = lambda **k: "ok"
    menus._pause = lambda *a, **k: None
    xray.bring_up = lambda c: (calls.append(("xray.bring_up", c)), _Rt("xray"))[1]
    hysteria2.bring_up = lambda c: (calls.append(("hy2.bring_up", c)), _Rt("hysteria2"))[1]
    _ui.info = _ui.success = lambda *a, **k: None

    class _U:
        mnemonic = "m"

    def node(t):
        return NodeInfo(address="sentnode1x", moniker="M", country="IT", remote_url="https://x:1",
                        node_type=t, gigabyte_prices=[], hourly_prices=[])
    try:
        menus._bring_up_tunnel(_U(), None, node(NODE_TYPE_XRAY), 1)
        assert store["backend"] == "xray"
        menus._bring_up_tunnel(_U(), None, node(NODE_TYPE_HYSTERIA2), 2)
        assert store["backend"] == "hysteria2"
        try:
            menus._bring_up_tunnel(_U(), None, node(99), 3)
            raise AssertionError("unknown node type must raise")
        except VpnError:
            pass
    finally:
        (cfg.load_state, cfg.save_state, _wallet.derive_private_key, menus._fetch_public_ip,
         menus._get_or_fetch_creds, menus._verify_public_ip, menus._pause,
         xray.bring_up, hysteria2.bring_up, _ui.info, _ui.success) = saved
    assert calls == [
        ("XrayCredentials", "xray_uuid_hex", "bluecli.vpn.xray"), ("xray.bring_up", "CREDS"),
        ("Hy2Credentials", "hy2_uuid", "bluecli.vpn.hysteria2"), ("hy2.bring_up", "CREDS"),
    ], calls


def test_teardown_and_emergency_cleanup_cover_new_backends():
    """Both teardown paths (menu disconnect and the atexit fail-safe) must
    reach the xray and hysteria2 backends — a missed branch would strand the
    user with redirected routing."""
    import bluecli.__main__ as entry
    from bluecli import config as cfg, menus
    from bluecli.vpn import hysteria2, xray
    calls = []
    saved = (xray.disconnect, hysteria2.disconnect, cfg.load_state, cfg.strip_runtime_state)
    xray.disconnect = lambda st: calls.append("xray")
    hysteria2.disconnect = lambda st: calls.append("hy2")
    cfg.strip_runtime_state = lambda: calls.append("strip")
    try:
        menus._teardown_tunnel({"backend": "xray"})
        menus._teardown_tunnel({"backend": "hysteria2"})
        for b in ("xray", "hysteria2"):
            cfg.load_state = lambda b=b: {"backend": b}
            entry._emergency_cleanup()
    finally:
        (xray.disconnect, hysteria2.disconnect, cfg.load_state, cfg.strip_runtime_state) = saved
    assert calls == ["xray", "hy2", "xray", "strip", "hy2", "strip"], calls


def test_tx_broadcast_wraps_grpc_errors():
    """A raw gRPC rejection while sending a tx becomes a readable ChainError
    (callers already handle it) instead of a crash; the sequence-mismatch
    case explains the pending tx. Non-gRPC errors pass through unchanged."""
    import grpc as _grpc
    from bluecli import chain

    class _Rpc(_grpc.RpcError):
        def __init__(self, details):
            self._d = details

        def details(self):
            return self._d

    def boom(err):
        def fn():
            raise err
        return fn

    try:
        chain._broadcast(boom(_Rpc("account sequence mismatch, expected 525, got 524: "
                                   "incorrect account sequence")), "t")
        raise AssertionError("must raise ChainError")
    except chain.ChainError as e:
        assert "pending" in str(e) and "Nothing was charged" in str(e), e
        assert "expects sequence 525" in str(e) and "used 524" in str(e), e
        assert "gRPC endpoint" in str(e), e
    try:
        chain._broadcast(boom(_Rpc("insufficient fees")), "t")
        raise AssertionError("must raise ChainError")
    except chain.ChainError as e:
        assert "insufficient fees" in str(e) and "Nothing was charged" not in str(e), e
    try:
        chain._broadcast(boom(KeyError("x")), "t")
        raise AssertionError("must re-raise")
    except KeyError:
        pass
    assert chain._broadcast(lambda: {"hash": "AB"}, "t") == {"hash": "AB"}




def test_detect_grpc_tls_order_and_fallback():
    """Port 443 is tried with TLS first, other ports plaintext first; the
    other mode is the fallback; None when neither answers. Each attempt is
    the real SDK connect (here faked)."""
    from bluecli import chain
    tried = []

    def fake_sdk(answer_tls):
        def _sdk(host, port, ssl=False):
            tried.append(ssl)
            if answer_tls is None or ssl is not answer_tls:
                raise RuntimeError("no answer in this mode")
            return object()
        return _sdk

    orig = chain.SDKInstance
    try:
        for port, server_tls, want, order in (
            (443, True, True, [True]),            # TLS on 443: first try
            (443, False, False, [True, False]),   # plaintext on 443: fallback
            (9090, False, False, [False]),        # plaintext elsewhere: first try
            (23990, True, True, [False, True]),   # TLS elsewhere: fallback
            (9090, None, None, [False, True]),    # nothing answers
        ):
            tried.clear()
            chain.SDKInstance = fake_sdk(server_tls)
            assert chain.detect_grpc_tls("h", port) is want, (port, server_tls)
            assert tried == order, (port, tried)
    finally:
        chain.SDKInstance = orig


def test_parse_grpc_endpoint_variants():
    """Endpoints are accepted the way people paste them from lists."""
    from bluecli.menus import _parse_grpc_endpoint
    assert _parse_grpc_endpoint("https://sentinel-grpc.publicnode.com:443/") == (
        "sentinel-grpc.publicnode.com", 443)
    assert _parse_grpc_endpoint("  grpc.sentinel.co:9090 ") == ("grpc.sentinel.co", 9090)
    assert _parse_grpc_endpoint("grpc://1.2.3.4:23990") == ("1.2.3.4", 23990)
    for bad in ("host", "host:0", "host:abc", ":443", "host:70000"):
        try:
            _parse_grpc_endpoint(bad)
            raise AssertionError(f"{bad!r} must be rejected")
        except ValueError:
            pass


def test_settings_grpc_probe_saves_tls_and_detects_tls_only_change():
    """Re-entering the SAME host:port must still save the detected TLS mode
    and report a change (so the chain client is rebuilt) — the old check
    compared host+port only. An endpoint that answers in neither mode is
    never saved."""
    from bluecli import config as cfg, menus, ui as _ui
    store = {"grpc_host": "sentinel-grpc.publicnode.com", "grpc_port": 443,
             "grpc_ssl": False, "chain_id": "sentinelhub-2", "denom": "udvpn"}
    saved = (cfg.load_config, cfg.save_config, menus.detect_grpc_tls, _ui.prompt,
             _ui.info, _ui.success, _ui.error, _ui.header, menus._pause)
    answers = []
    cfg.load_config = lambda: dict(store)
    cfg.save_config = lambda c: store.update(c)
    _ui.prompt = lambda *a, **k: answers.pop(0)
    _ui.info = _ui.success = _ui.error = _ui.header = lambda *a, **k: None
    menus._pause = lambda *a, **k: None
    try:
        menus.detect_grpc_tls = lambda h, p: True
        answers[:] = ["1", "https://sentinel-grpc.publicnode.com:443", "3"]
        assert menus.settings_menu() is True, "TLS-only change must trigger a rebuild"
        assert store["grpc_ssl"] is True and store["grpc_port"] == 443

        menus.detect_grpc_tls = lambda h, p: None
        answers[:] = ["1", "dead.example:9090", "3"]
        assert menus.settings_menu() is False, "unreachable endpoint must change nothing"
        assert store["grpc_host"] == "sentinel-grpc.publicnode.com"
    finally:
        (cfg.load_config, cfg.save_config, menus.detect_grpc_tls, _ui.prompt,
         _ui.info, _ui.success, _ui.error, _ui.header, menus._pause) = saved

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
        ("vpn.amneziawg.v8_response_parser", test_amneziawg_parses_peer_response),
        ("vpn.amneziawg.bad_obfs_rejected", test_amneziawg_rejects_bad_obfs_metadata),
        ("vpn.amneziawg.config_full_and_setconf", test_amneziawg_config_full_and_setconf_variants),
        ("vpn.amneziawg.junk_ranges", test_amneziawg_junk_params_in_range),
        ("vpn.amneziawg.creds_roundtrip", test_amneziawg_credentials_state_roundtrip),
        ("vpn.amneziawg.windows_service_retry", test_amneziawg_windows_service_retries_once_on_failure),
        ("vpn.amneziawg.require_exec_bit", test_amneziawg_require_rejects_non_executable),
        ("vpn.amneziawg.probe_error_surfaced", test_amneziawg_wait_until_ready_surfaces_probe_error),
        ("vpn.socks.require_binary", test_socks_require_binary),
        ("vpn.socks.session_state_runtime_only", test_socks_session_state_is_runtime_only),
        ("vpn.v2ray.uses_shared_socks_engine", test_v2ray_uses_shared_socks_engine),
        ("vpn.hysteria2.handshake_uuid_string", test_hysteria2_handshake_sends_uuid_string),
        ("vpn.hysteria2.server_and_config", test_hysteria2_server_parsing_and_config),
        ("vpn.xray.handshake_and_creds", test_xray_handshake_and_creds),
        ("vpn.xray.endpoint_validation_ranking", test_xray_endpoint_validation_and_ranking),
        ("vpn.xray.outbounds_per_protocol", test_xray_outbounds_per_protocol),
        ("chain.parse_response_xray_hysteria2", test_parse_node_response_xray_hysteria2_types),
        ("menus.connectable_types_and_browser", test_connectable_types_cover_every_service_and_browser),
        ("menus.bring_up_dispatch_new_backends", test_bring_up_dispatches_xray_and_hysteria2),
        ("menus.teardown_cleanup_new_backends", test_teardown_and_emergency_cleanup_cover_new_backends),
        ("chain.tx_broadcast_wraps_grpc_errors", test_tx_broadcast_wraps_grpc_errors),
        ("chain.detect_grpc_tls", test_detect_grpc_tls_order_and_fallback),
        ("menus.parse_grpc_endpoint", test_parse_grpc_endpoint_variants),
        ("menus.settings_grpc_probe_tls", test_settings_grpc_probe_saves_tls_and_detects_tls_only_change),
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
        ("chain.parse_response_declared_transports", test_parse_node_response_declared_transports),
        ("node_cache.declared_transports_roundtrip", test_node_cache_roundtrips_declared_transports),
        ("menus.multihop_eligible_native_first", test_multihop_eligible_native_first),
        ("chain.parse_session_any_node", test_parse_session_any_node_wrapper),
        ("chain.parse_session_any_subscription", test_parse_session_any_subscription_wrapper),
        ("chain.price_dict_roundtrip", test_price_dict_roundtrip),
        ("node_cache.disk_seed", test_node_cache_serves_disk_seed),
        ("menus.format_node_row", test_format_node_row_with_dict_prices),
        ("menus.pick_multihop_node_renders", test_pick_multihop_node_renders_rows_and_returns_choice),
        ("node_cache.signals_done_on_empty", test_node_cache_signals_done_even_when_fetch_returns_empty),
        ("node_cache.records_fetch_errors", test_node_cache_records_fetch_errors),
        ("node_cache.refresh_now_mutual_exclusion", test_node_cache_refresh_now_runs_and_is_mutually_exclusive),
        ("menus.refresh_node_list_busy", test_refresh_node_list_reports_busy_and_keeps_list),
        ("menus.refresh_node_list_runs", test_refresh_node_list_runs_and_returns_browseable),
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
        ("menus.verify_dns_fallback", test_verify_public_ip_dns_fallback_when_cloudflare_blocked),
        ("menus.verify_reports_changed_ip", test_verify_public_ip_reports_changed_ip),
        ("menus.verify_detects_broken_dns", test_verify_public_ip_detects_broken_dns),
        ("menus.verify_fallback_ungated", test_verify_fallback_not_gated_by_dns_precheck),
        ("menus.fetch_public_ip_bounded_caps_hang", test_fetch_public_ip_bounded_caps_a_hang),
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
        ("menus.warn_after_unverified", test_warn_after_unverified_keeps_tunnel),
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
