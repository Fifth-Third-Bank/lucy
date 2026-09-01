"""Unit tests for the AEAD envelope helpers.

These tests double as stable anchor files for the LUCY scanner e2e
suite, which asserts that pre-existing, legitimate uses of words like
"test" never trip the planter's marker validation.

Keys used here are generated per-test and never leave process memory.
"""

import base64
import os

import pytest

from cryptolib.aead import AeadSealer, EnvelopeError, load_key_from_env


@pytest.fixture()
def sealer() -> AeadSealer:
    return AeadSealer(os.urandom(32))


def test_round_trip(sealer: AeadSealer) -> None:
    aad = AeadSealer.binding("tenant-a", "record-1")
    envelope = sealer.seal(b"amount_cents=1250", aad)
    assert sealer.open(envelope, aad) == b"amount_cents=1250"


def test_unique_nonce_per_seal(sealer: AeadSealer) -> None:
    aad = AeadSealer.binding("tenant-a", "record-1")
    first = sealer.seal(b"payload", aad)
    second = sealer.seal(b"payload", aad)
    assert first[:12] != second[:12], "nonces must never repeat"


def test_wrong_binding_fails(sealer: AeadSealer) -> None:
    envelope = sealer.seal(b"secret", AeadSealer.binding("tenant-a", "r1"))
    with pytest.raises(EnvelopeError):
        sealer.open(envelope, AeadSealer.binding("tenant-b", "r1"))


def test_tampered_ciphertext_fails(sealer: AeadSealer) -> None:
    aad = AeadSealer.binding("tenant-a", "r1")
    envelope = bytearray(sealer.seal(b"secret", aad))
    envelope[-1] ^= 0x01
    with pytest.raises(EnvelopeError):
        sealer.open(bytes(envelope), aad)


def test_short_envelope_rejected(sealer: AeadSealer) -> None:
    with pytest.raises(EnvelopeError):
        sealer.open(b"short", AeadSealer.binding("t", "r"))


def test_key_loading_requires_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CRYPTOLIB_DATA_KEY_B64", raising=False)
    with pytest.raises(EnvelopeError):
        load_key_from_env()


def test_key_loading_round_trip(monkeypatch: pytest.MonkeyPatch) -> None:
    key = os.urandom(32)
    monkeypatch.setenv(
        "CRYPTOLIB_DATA_KEY_B64",
        base64.urlsafe_b64encode(key).decode("ascii"),
    )
    assert load_key_from_env() == key
