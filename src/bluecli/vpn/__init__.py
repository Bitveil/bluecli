"""Shared chain-side handshake with a Sentinel dVPN node.

The v8.x node (sentinel-dvpnx) exposes a single `POST /` endpoint that
accepts:

    {
      "id":        <session id, uint64>,
      "data":      "<base64 of a JSON-encoded peer-request>",
      "pub_key":   "secp256k1:<base64 33-byte compressed key>",
      "signature": "<base64 of ECDSA(SHA-256(BE(id) || data))>"
    }

and returns:

    {"success": true, "result": {"addrs": [...], "data": "<base64 JSON>"}}

The `data` in the request is protocol-specific (a wireguard public key, a
v2ray UUID, etc.) and the `data` in the response is the protocol-specific
peer descriptor. This module handles the signing and HTTP exchange; each
backend (wireguard, v2ray) builds its request_data and parses its
response_data on top.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass

import ecdsa
import requests
import urllib3
from ecdsa.util import sigencode_string_canonize

# Sentinel nodes use self-signed TLS; the chain-side signature is what
# actually authenticates us, not the cert. Silence the warning so the CLI
# output stays clean.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class VpnError(Exception):
    pass


class NodeHandshakeError(VpnError):
    """Raised when the chain-side handshake POST to the node fails.

    `status_code` is the HTTP status the node returned (0 if we never got
    that far — connection refused, DNS, etc.). Callers can branch on this
    to give the user a useful message: 409 specifically means "this
    session was registered by a prior handshake", which is unrecoverable
    without cached credentials.
    """

    def __init__(self, message: str, *, status_code: int = 0) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass
class HandshakeResult:
    """Parsed handshake response. `peer_data` is the decoded `result.data`
    JSON object; its shape depends on the protocol (see wireguard / v2ray
    modules)."""

    node_addrs: list[str]
    peer_data: dict


def fetch_node_credentials(
    *,
    remote_url: str,
    session_id: int,
    private_key: bytes,
    request_data: dict,
    timeout: int = 20,
) -> HandshakeResult:
    """Sign the request, POST it to the node, and return the parsed response.

    `private_key` must be the 32-byte secp256k1 key derived from the user's
    mnemonic. `request_data` is the protocol-specific JSON payload (e.g.
    `{"public_key": "..."}` for WireGuard, `{"uuid": "..."}` for V2Ray).
    """
    if len(private_key) != 32:
        raise NodeHandshakeError(
            f"Private key must be 32 bytes, got {len(private_key)}."
        )

    # 1. Serialize the request body bytes that the node will hash & verify.
    data_bytes = json.dumps(request_data, separators=(",", ":")).encode("utf-8")

    # 2. Sign Uint64BE(id) || data_bytes with secp256k1 (deterministic +
    #    low-S canonical, matching Cosmos verifiers).
    sk = ecdsa.SigningKey.from_string(
        private_key, curve=ecdsa.SECP256k1, hashfunc=hashlib.sha256
    )
    msg = int(session_id).to_bytes(8, "big") + data_bytes
    signature = sk.sign_deterministic(
        msg, hashfunc=hashlib.sha256, sigencode=sigencode_string_canonize
    )

    # 3. Compress the public key (33 bytes: 0x02/0x03 || x) and tag it with
    #    its Cosmos type, as utils.EncodePubKey does in the Go SDK.
    pubkey_compressed = sk.verifying_key.to_string(encoding="compressed")
    pub_key_tagged = "secp256k1:" + base64.b64encode(pubkey_compressed).decode("ascii")

    # 4. Build the JSON body. Go's json marshaller serialises []byte as base64,
    #    so the `data` field is the base64 of `data_bytes`.
    body = {
        "id": int(session_id),
        "data": base64.b64encode(data_bytes).decode("ascii"),
        "pub_key": pub_key_tagged,
        "signature": base64.b64encode(signature).decode("ascii"),
    }

    # 5. POST to the root. No trailing path components.
    url = remote_url.rstrip("/") + "/"
    try:
        resp = requests.post(
            url,
            json=body,
            headers={"Content-Type": "application/json; charset=utf-8"},
            verify=False,
            timeout=timeout,
        )
    except requests.RequestException as e:
        raise NodeHandshakeError(f"Cannot reach node: {e}") from e

    if resp.status_code != 200:
        # Try to surface the structured error code the node returns.
        try:
            err = resp.json().get("error") or {}
            detail = f"{err.get('message', resp.text)} (code={err.get('code')})"
        except ValueError:
            detail = resp.text
        raise NodeHandshakeError(
            f"Node returned HTTP {resp.status_code}: {detail}",
            status_code=resp.status_code,
        )

    try:
        body = resp.json()
    except ValueError as e:
        raise NodeHandshakeError("Node returned invalid JSON.") from e

    if not body.get("success"):
        err = body.get("error") or {}
        raise NodeHandshakeError(
            f"Node refused the handshake: {err.get('message', body)}"
        )

    result = body.get("result") or {}
    addrs = result.get("addrs") or []
    raw_data = result.get("data")
    if not raw_data:
        raise NodeHandshakeError("Node response is missing the credentials payload.")
    try:
        decoded = base64.b64decode(raw_data)
    except (ValueError, TypeError) as e:
        raise NodeHandshakeError("Node credentials are not valid base64.") from e
    try:
        peer_data = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise NodeHandshakeError("Node credentials are not valid JSON.") from e
    if not isinstance(peer_data, dict):
        raise NodeHandshakeError("Node credentials payload is not an object.")

    return HandshakeResult(node_addrs=list(addrs), peer_data=peer_data)
