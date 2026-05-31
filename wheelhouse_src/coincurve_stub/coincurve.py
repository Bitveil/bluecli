"""Stub for the `coincurve` module.

bip-utils 2.9.0 uses coincurve as its default secp256k1 backend, but
BlueCLI forces bip-utils onto its pure-Python `ecdsa` backend instead
(the launcher sets `EccConf.USE_COINCURVE = False` in the installed
bip-utils before first use). With that flag off, bip-utils never runs
`import coincurve`, so nothing below is ever loaded in practice.

This file exists purely to satisfy pip's dependency resolver without
compiling the real coincurve C extension — the versions bip-utils pins
have no wheel for Python 3.13+, and source builds need autotools that
most user machines lack.

The ecdsa backend produces byte-identical private keys and addresses
(verified against coincurve in BlueCLI's smoke tests), so there is no
functional difference — only a negligible speed cost on the single
key derivation BlueCLI does per session.

If anything here is ever actually called, that means the launcher's
USE_COINCURVE patch didn't apply — we raise loudly so the bug is
obvious instead of producing wrong crypto silently.
"""

from __future__ import annotations


def _unreachable(*args, **kwargs):
    raise NotImplementedError(
        "coincurve is stubbed in BlueCLI: bip-utils is supposed to be "
        "using its pure-Python ecdsa backend (USE_COINCURVE=False). "
        "Reaching this code means that patch didn't apply — please "
        "report it; do NOT trust any key derived in this state."
    )


class PublicKey:
    def __init__(self, *args, **kwargs):
        _unreachable()

    @classmethod
    def from_secret(cls, *args, **kwargs):
        _unreachable()

    @classmethod
    def from_point(cls, *args, **kwargs):
        _unreachable()

    @classmethod
    def from_valid_secret(cls, *args, **kwargs):
        _unreachable()

    def format(self, *args, **kwargs):
        _unreachable()

    def point(self, *args, **kwargs):
        _unreachable()


class PrivateKey:
    def __init__(self, *args, **kwargs):
        _unreachable()

    @classmethod
    def from_int(cls, *args, **kwargs):
        _unreachable()

    def sign(self, *args, **kwargs):
        _unreachable()

    def sign_recoverable(self, *args, **kwargs):
        _unreachable()
