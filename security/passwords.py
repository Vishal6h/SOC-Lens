"""Versioned standard-library scrypt password credentials."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets


CREDENTIAL_SCHEME = "scrypt"
CREDENTIAL_VERSION = 1
DEFAULT_N = 1 << 14
DEFAULT_R = 8
DEFAULT_P = 1
SALT_BYTES = 16
DERIVED_BYTES = 32
MIN_PASSWORD_CHARACTERS = 12
MAX_PASSWORD_BYTES = 1024


class PasswordPolicyError(ValueError):
    pass


def validate_password(password):
    if not isinstance(password, str):
        raise PasswordPolicyError("Password must be text")
    encoded = password.encode("utf-8")
    if len(password) < MIN_PASSWORD_CHARACTERS:
        raise PasswordPolicyError(
            f"Password must contain at least {MIN_PASSWORD_CHARACTERS} characters"
        )
    if len(encoded) > MAX_PASSWORD_BYTES:
        raise PasswordPolicyError(f"Password must not exceed {MAX_PASSWORD_BYTES} bytes")
    if password.isspace() or any(ord(character) < 32 or ord(character) == 127 for character in password):
        raise PasswordPolicyError("Password must not be blank or contain control characters")
    if len(set(password)) < 4:
        raise PasswordPolicyError("Password is too repetitive")
    return encoded


def _b64(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64(value):
    if not isinstance(value, str) or not value:
        raise ValueError("invalid base64 field")
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def hash_password(password, *, n=DEFAULT_N, r=DEFAULT_R, p=DEFAULT_P, salt=None):
    encoded = validate_password(password)
    if not isinstance(n, int) or n < (1 << 12) or n > (1 << 20) or n & (n - 1):
        raise ValueError("scrypt n must be a supported power of two")
    if not isinstance(r, int) or not 1 <= r <= 32 or not isinstance(p, int) or not 1 <= p <= 16:
        raise ValueError("scrypt parameters are out of bounds")
    salt = secrets.token_bytes(SALT_BYTES) if salt is None else salt
    if not isinstance(salt, bytes) or len(salt) < SALT_BYTES:
        raise ValueError("scrypt salt is invalid")
    derived = hashlib.scrypt(encoded, salt=salt, n=n, r=r, p=p, dklen=DERIVED_BYTES)
    return f"{CREDENTIAL_SCHEME}$v={CREDENTIAL_VERSION}$n={n}$r={r}$p={p}${_b64(salt)}${_b64(derived)}"


def verify_password(password, credential):
    """Return False for wrong passwords and every malformed credential."""
    if not isinstance(password, str) or len(password.encode("utf-8", errors="ignore")) > MAX_PASSWORD_BYTES:
        return False
    try:
        parts = credential.split("$")
        if len(parts) != 7 or parts[0] != CREDENTIAL_SCHEME or parts[1] != "v=1":
            return False
        n, r, p = (int(parts[index].split("=", 1)[1]) for index in (2, 3, 4))
        if n < (1 << 12) or n > (1 << 20) or n & (n - 1) or not 1 <= r <= 32 or not 1 <= p <= 16:
            return False
        salt, expected = _unb64(parts[5]), _unb64(parts[6])
        if len(salt) < SALT_BYTES or len(expected) != DERIVED_BYTES:
            return False
        actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except (AttributeError, IndexError, TypeError, ValueError, OverflowError):
        return False


def credential_metadata(credential):
    parts = credential.split("$") if isinstance(credential, str) else []
    if len(parts) != 7:
        return None
    try:
        return {
            "scheme": parts[0], "version": int(parts[1].split("=", 1)[1]),
            "n": int(parts[2].split("=", 1)[1]), "r": int(parts[3].split("=", 1)[1]),
            "p": int(parts[4].split("=", 1)[1]),
        }
    except (IndexError, ValueError):
        return None
