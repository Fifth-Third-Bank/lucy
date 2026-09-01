"""Shared AEAD envelope-encryption helpers for the demo estate.

This package wraps AES-256-GCM with the small amount of policy the
platform requires of every caller:

* keys are loaded from the environment, never from source or disk;
* a fresh random 96-bit nonce is generated for every sealing operation;
* associated data binds each ciphertext to its tenant and record id so
  a ciphertext copied between rows fails to open.

The module is deliberately tiny. Anything more exotic (key rotation,
HSM-backed keys) belongs to the key-management service, not this
library.

This copy lives in the fixture estate for scanner tests and is never
imported by production code.
"""

from cryptolib.aead import (
    AeadSealer,
    EnvelopeError,
    load_key_from_env,
)

__all__ = [
    "AeadSealer",
    "EnvelopeError",
    "load_key_from_env",
]

__version__ = "1.3.0"
