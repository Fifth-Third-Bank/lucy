"""AES-256-GCM envelope sealing with tenant-bound associated data.

Key material is provided out-of-band as a base64url value in the
environment (populated from the secret manager at deploy time). Nothing
in this module ever logs, prints, or persists key bytes.
"""

from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_KEY_ENV_VAR = "CRYPTOLIB_DATA_KEY_B64"
_KEY_LEN_BYTES = 32  # AES-256
_NONCE_LEN_BYTES = 12  # 96-bit nonce, the GCM-recommended size


class EnvelopeError(Exception):
    """Raised when sealing or opening an envelope fails.

    The message is intentionally generic: callers must not learn whether
    a failure came from a bad key, a bad nonce, or a forged tag.
    """


def load_key_from_env(var_name: str = _KEY_ENV_VAR) -> bytes:
    """Load and validate the AES-256 key from the environment.

    Fails closed: a missing or malformed value raises EnvelopeError
    rather than falling back to any default key.
    """
    encoded = os.environ.get(var_name)
    if not encoded:
        raise EnvelopeError(f"{var_name} is not set")
    try:
        key = base64.urlsafe_b64decode(encoded)
    except (ValueError, TypeError) as exc:
        raise EnvelopeError("key material is not valid base64url") from exc
    if len(key) != _KEY_LEN_BYTES:
        raise EnvelopeError("key material has the wrong length")
    return key


class AeadSealer:
    """Seals and opens byte payloads with AES-256-GCM.

    Wire format: nonce (12 bytes) || ciphertext-with-tag. The associated
    data is not transmitted; both sides derive it from the row identity,
    which is what binds a ciphertext to its record.
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != _KEY_LEN_BYTES:
            raise EnvelopeError("AeadSealer requires a 32-byte key")
        self._aesgcm = AESGCM(key)

    @classmethod
    def from_env(cls) -> "AeadSealer":
        return cls(load_key_from_env())

    @staticmethod
    def binding(tenant_id: str, record_id: str) -> bytes:
        """Associated data that ties a ciphertext to one tenant + record."""
        return f"v1|{tenant_id}|{record_id}".encode("utf-8")

    def seal(self, plaintext: bytes, associated_data: bytes) -> bytes:
        """Encrypt with a fresh random nonce; never reuse nonces per key."""
        nonce = os.urandom(_NONCE_LEN_BYTES)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce + ciphertext

    def open(self, envelope: bytes, associated_data: bytes) -> bytes:
        """Decrypt and authenticate; raises EnvelopeError on any tamper."""
        if len(envelope) <= _NONCE_LEN_BYTES:
            raise EnvelopeError("envelope too short")
        nonce, ciphertext = (
            envelope[:_NONCE_LEN_BYTES],
            envelope[_NONCE_LEN_BYTES:],
        )
        try:
            return self._aesgcm.decrypt(nonce, ciphertext, associated_data)
        except InvalidTag as exc:
            raise EnvelopeError("envelope failed authentication") from exc
