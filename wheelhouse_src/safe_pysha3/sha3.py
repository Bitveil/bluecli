"""Shim for the `sha3` module from safe-pysha3.

Why: safe-pysha3 ships a C extension that has no Windows wheel on PyPI,
so installing it forces the user to have MSVC build tools. We satisfy
the import by routing requests to APIs that already ship as wheels:

  - keccak_*  → pycryptodome's Crypto.Hash.keccak
  - sha3_*    → Python stdlib hashlib (since 3.6)

The hashlib functions and pycryptodome's Keccak are wire-compatible
with what mospy-wallet expects: it only calls .update(), .digest() and
.hexdigest() on the returned objects.
"""

from __future__ import annotations

import hashlib

from Crypto.Hash import keccak as _keccak


class _Keccak:
    """API-compatible thin wrapper around pycryptodome's Keccak object.

    pycryptodome's keccak.new returns a hash object that already has
    update/digest/hexdigest/copy. We re-export only that surface so any
    attribute drift in pycryptodome doesn't leak into callers.
    """
    __slots__ = ("_h", "digest_size")

    def __init__(self, bits: int, data: bytes = b"") -> None:
        self._h = _keccak.new(digest_bits=bits)
        self.digest_size = bits // 8
        if data:
            self._h.update(data)

    def update(self, data: bytes) -> None:
        self._h.update(data)

    def digest(self) -> bytes:
        return self._h.digest()

    def hexdigest(self) -> str:
        return self._h.hexdigest()

    def copy(self) -> "_Keccak":
        c = _Keccak.__new__(_Keccak)
        c._h = self._h.copy()
        c.digest_size = self.digest_size
        return c


def keccak_224(data: bytes = b"") -> _Keccak: return _Keccak(224, data)
def keccak_256(data: bytes = b"") -> _Keccak: return _Keccak(256, data)
def keccak_384(data: bytes = b"") -> _Keccak: return _Keccak(384, data)
def keccak_512(data: bytes = b"") -> _Keccak: return _Keccak(512, data)


# SHA-3 (NIST) — different padding bytes from Keccak; stdlib has these.
def sha3_224(data: bytes = b""): return hashlib.sha3_224(data)
def sha3_256(data: bytes = b""): return hashlib.sha3_256(data)
def sha3_384(data: bytes = b""): return hashlib.sha3_384(data)
def sha3_512(data: bytes = b""): return hashlib.sha3_512(data)
