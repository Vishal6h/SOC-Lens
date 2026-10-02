"""Session-bound CSRF validation helpers."""

from .sessions import csrf_valid


class CsrfInvalid(PermissionError):
    pass


def require_csrf(headers, session):
    token = headers.get("X-CSRF-Token")
    if not csrf_valid(token, session["csrf_hash"]):
        raise CsrfInvalid("CSRF token is missing or invalid")
