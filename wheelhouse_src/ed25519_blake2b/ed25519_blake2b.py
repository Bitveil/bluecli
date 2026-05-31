"""Stub for the `ed25519_blake2b` module.

bip-utils 2.9.0 uses this library only inside
`bip_utils.ecc.ed25519_blake2b.*` — the Nano-cryptocurrency derivation
path. BlueCLI never touches that path (Sentinel uses secp256k1), so
the symbols below only need to exist for `import ed25519_blake2b`
to succeed at module load. If any code path actually exercises them,
we raise loudly so the bug is obvious instead of silent.

The upstream `ed25519-blake2b` package ships a C extension and has no
Windows wheel on PyPI; using this stub removes the MSVC build-tools
requirement for BlueCLI installs.
"""

from __future__ import annotations


def _unreachable(*args, **kwargs):
    raise NotImplementedError(
        "ed25519_blake2b is stubbed in BlueCLI: this code path serves "
        "Nano-style wallets, which BlueCLI does not use. Reaching it "
        "means bip-utils took an unexpected branch — please report."
    )


class SigningKey:
    def __init__(self, *args, **kwargs):
        _unreachable()

    def sign(self, *args, **kwargs):
        _unreachable()

    def to_bytes(self, *args, **kwargs):
        _unreachable()

    def get_verifying_key(self, *args, **kwargs):
        _unreachable()


class VerifyingKey:
    def __init__(self, *args, **kwargs):
        _unreachable()

    def verify(self, *args, **kwargs):
        _unreachable()

    def to_bytes(self, *args, **kwargs):
        _unreachable()


def create_keypair(*args, **kwargs):
    _unreachable()
