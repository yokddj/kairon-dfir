"""Encryption for AI provider credentials stored in app_settings.

Provider API keys are secrets a compromised database read should not hand over,
so they are sealed with AES-GCM before they ever reach the AppSetting row and
are only opened in the request that talks to the provider. Nothing outside this
module returns plaintext to a caller that did not explicitly ask for it.
"""

from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import get_settings


TOKEN_PREFIX = "aesgcm-v1:"
_HKDF_INFO = b"kairon-ai-provider-credentials-v1"
_NONCE_BYTES = 12


class CredentialCryptoError(RuntimeError):
    """Raised when a stored credential cannot be sealed or opened."""


def _key_material() -> bytes:
    settings = get_settings()
    material = (settings.ai_secret_key or "").strip()
    if not material:
        # Falling back to the session secret keeps single-host deployments
        # working without a second secret to manage; rotating it invalidates
        # stored provider keys, which is the safe direction to fail.
        material = (settings.session_secret_key or "").strip()
    if not material:
        raise CredentialCryptoError(
            "No secret available to encrypt AI credentials: set KAIRON_AI_SECRET_KEY"
        )
    return material.encode("utf-8")


def _derive_key() -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_HKDF_INFO,
    ).derive(_key_material())


def is_sealed(value: str | None) -> bool:
    return bool(value) and str(value).startswith(TOKEN_PREFIX)


def seal(plaintext: str) -> str:
    """Encrypt a provider API key for storage."""
    if not plaintext:
        raise CredentialCryptoError("Refusing to encrypt an empty credential")
    nonce = os.urandom(_NONCE_BYTES)
    ciphertext = AESGCM(_derive_key()).encrypt(nonce, plaintext.encode("utf-8"), None)
    return TOKEN_PREFIX + base64.b64encode(nonce + ciphertext).decode("ascii")


def open_sealed(token: str | None) -> str | None:
    """Decrypt a stored provider API key, or None when nothing is stored."""
    if not token:
        return None
    if not is_sealed(token):
        raise CredentialCryptoError("Stored credential is not in the expected sealed format")
    try:
        raw = base64.b64decode(token[len(TOKEN_PREFIX):].encode("ascii"))
        nonce, ciphertext = raw[:_NONCE_BYTES], raw[_NONCE_BYTES:]
        return AESGCM(_derive_key()).decrypt(nonce, ciphertext, None).decode("utf-8")
    except InvalidTag as exc:
        raise CredentialCryptoError(
            "Stored credential could not be decrypted: the encryption secret changed. "
            "Re-enter the provider API key."
        ) from exc
    except CredentialCryptoError:
        raise
    except Exception as exc:  # noqa: BLE001 - corrupt payloads must not leak internals
        raise CredentialCryptoError("Stored credential is corrupt") from exc


def mask(plaintext: str | None) -> str | None:
    """Render a credential for display without disclosing it."""
    if not plaintext:
        return None
    tail = plaintext[-4:] if len(plaintext) > 8 else ""
    return f"{'*' * 8}{tail}" if tail else "*" * 8
