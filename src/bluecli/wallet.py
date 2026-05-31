"""Wallet management.

Storage model: a single file `wallet.enc` containing AES-GCM encrypted JSON
holding the mnemonic. The key is derived from the user's password with
PBKDF2-HMAC-SHA256 (200k iterations). Nothing else touches the disk in
plaintext — the address we re-derive each time the wallet is unlocked.

We intentionally do NOT use the OS keyring: cross-platform keyring libraries
add heavy dependencies and platform quirks. A single encrypted file is
auditable, portable, and trivial to back up.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass

import bech32
from bip_utils import Bip39MnemonicValidator, Bip39SeedGenerator, Bip44, Bip44Coins
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from mnemonic import Mnemonic

from .config import WALLET_FILE, ensure_dir

PBKDF2_ITERATIONS = 200_000
SALT_LEN = 16
NONCE_LEN = 12
BECH32_HRP = "sent"


@dataclass(frozen=True)
class Wallet:
    """An unlocked wallet, held only in memory."""

    mnemonic: str
    address: str  # bech32 "sent1..."

    @property
    def secret(self) -> str:
        """The value the Sentinel SDK accepts as `secret=` (the mnemonic)."""
        return self.mnemonic


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


def exists() -> bool:
    return WALLET_FILE.is_file()


def create(password: str) -> Wallet:
    """Generate a fresh 24-word mnemonic and persist it encrypted."""
    if exists():
        raise WalletExists()
    mnemonic = Mnemonic("english").generate(strength=256)
    _persist(mnemonic, password)
    return Wallet(mnemonic=mnemonic, address=_derive_address(mnemonic))


def import_from_mnemonic(mnemonic: str, password: str) -> Wallet:
    """Validate and persist a user-supplied mnemonic."""
    if exists():
        raise WalletExists()
    mnemonic = " ".join(mnemonic.strip().lower().split())
    if not Bip39MnemonicValidator().IsValid(mnemonic):
        raise InvalidMnemonic()
    _persist(mnemonic, password)
    return Wallet(mnemonic=mnemonic, address=_derive_address(mnemonic))


def unlock(password: str) -> Wallet:
    """Decrypt the on-disk wallet and return it."""
    if not exists():
        raise NoWallet()
    with WALLET_FILE.open("rb") as f:
        blob = f.read()
    salt, nonce, ciphertext = blob[:SALT_LEN], blob[SALT_LEN:SALT_LEN + NONCE_LEN], blob[SALT_LEN + NONCE_LEN:]
    key = _derive_key(password, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception as e:  # InvalidTag etc. — keep the API surface uniform
        raise WrongPassword() from e
    payload = json.loads(plaintext.decode("utf-8"))
    mnemonic = payload["mnemonic"]
    return Wallet(mnemonic=mnemonic, address=_derive_address(mnemonic))


def delete() -> None:
    """Remove the wallet file from disk."""
    if WALLET_FILE.is_file():
        WALLET_FILE.unlink()


def derive_private_key(mnemonic: str) -> bytes:
    """Return the raw 32-byte secp256k1 private key for `mnemonic`.

    Used by the VPN handshake (it has to ECDSA-sign the session id), which
    must work for any wallet — even one with zero balance that isn't yet
    known to the chain.
    """
    return _bip44_default(mnemonic).PrivateKey().Raw().ToBytes()


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------


class WalletError(Exception):
    pass


class WalletExists(WalletError):
    pass


class NoWallet(WalletError):
    pass


class WrongPassword(WalletError):
    pass


class InvalidMnemonic(WalletError):
    pass


# --------------------------------------------------------------------------
# Internals
# --------------------------------------------------------------------------


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def _persist(mnemonic: str, password: str) -> None:
    ensure_dir()
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(password, salt)
    payload = json.dumps({"mnemonic": mnemonic}).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, payload, None)
    # Open with restrictive permissions on POSIX; on Windows the user dir is
    # already private, so we don't fight the OS.
    fd = os.open(WALLET_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(salt + nonce + ciphertext)
    except Exception:
        if WALLET_FILE.is_file():
            WALLET_FILE.unlink()
        raise


def _bip44_default(mnemonic: str):
    """Shared BIP44 derivation: mnemonic → seed → Cosmos default path
    (m/44'/118'/0'/0/0). Both the private-key and address derivations
    start here, so they can never drift apart."""
    seed = Bip39SeedGenerator(mnemonic).Generate()
    return Bip44.FromSeed(seed, Bip44Coins.COSMOS).DeriveDefaultPath()


def _derive_address(mnemonic: str) -> str:
    """Derive the Sentinel bech32 address from a BIP39 mnemonic."""
    pubkey_compressed = _bip44_default(mnemonic).PublicKey().RawCompressed().ToBytes()
    sha = hashlib.sha256(pubkey_compressed).digest()
    # RIPEMD160 via hashlib.new — falls back to cryptography on Py 3.10+.
    try:
        ripe = hashlib.new("ripemd160", sha).digest()
    except ValueError:
        # OpenSSL 3 may not expose ripemd160; pycryptodome (a sentinel-sdk
        # dependency) does.
        from Crypto.Hash import RIPEMD160  # type: ignore[import-not-found]
        r = RIPEMD160.new()
        r.update(sha)
        ripe = r.digest()
    five_bit = bech32.convertbits(ripe, 8, 5)
    return bech32.bech32_encode(BECH32_HRP, five_bit)
