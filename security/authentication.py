"""Local password authentication and bounded login-abuse protection."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib

from .identity import IdentityNotFound, IdentityService, normalize_username
from .passwords import hash_password, verify_password


class InvalidCredentials(PermissionError):
    pass


class AccountDisabled(PermissionError):
    pass


class RateLimited(PermissionError):
    pass


def _now(value=None):
    return datetime.now(timezone.utc) if value is None else value.astimezone(timezone.utc)


def _parse(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class AuthenticationService:
    def __init__(self, identities: IdentityService, sessions, audit, *, attempt_limit=5,
                 window_minutes=15, block_seconds=60):
        if not 2 <= attempt_limit <= 100 or not 1 <= window_minutes <= 1440 or not 1 <= block_seconds <= 3600:
            raise ValueError("Login protection settings are out of bounds")
        self.identities, self.sessions, self.audit = identities, sessions, audit
        self.database = identities.database
        self.storage = identities.storage
        self.attempt_limit = attempt_limit
        self.window_minutes = window_minutes
        self.block_seconds = block_seconds
        # A normal scrypt credential keeps unknown-user verification timing comparable.
        self._dummy_credential = hash_password("SOCLens dummy credential 7!", **(
            {"n": identities.scrypt_n} if identities.scrypt_n else {}
        ))

    @staticmethod
    def _attempt_key(username, client):
        bounded = (str(username)[:128] + "\x00" + str(client)[:128]).encode("utf-8", errors="replace")
        return hashlib.sha256(bounded).hexdigest()

    def _attempt(self, key):
        with self.storage.connection(readonly=True, operation="security_login_attempt_read") as connection:
            return connection.execute(
                "SELECT * FROM login_attempts WHERE attempt_key=?", (key,)
            ).fetchone()

    def _blocked(self, key, now):
        row = self._attempt(key)
        return bool(row and row["blocked_until"] and now < _parse(row["blocked_until"]))

    def _failure(self, key, now):
        with self.storage.transaction(operation="security_login_attempt_write") as connection:
            row = connection.execute(
                "SELECT * FROM login_attempts WHERE attempt_key=?", (key,)
            ).fetchone()
            window_start = now - timedelta(minutes=self.window_minutes)
            if row is None or _parse(row["window_started_at"]) <= window_start:
                count, started = 1, now
            else:
                count, started = row["failure_count"] + 1, _parse(row["window_started_at"])
            blocked = now + timedelta(seconds=self.block_seconds) if count >= self.attempt_limit else None
            connection.execute(
                """INSERT INTO login_attempts(attempt_key,window_started_at,failure_count,blocked_until)
                   VALUES (?,?,?,?) ON CONFLICT(attempt_key) DO UPDATE SET
                   window_started_at=excluded.window_started_at,
                   failure_count=excluded.failure_count,blocked_until=excluded.blocked_until""",
                (key, started.isoformat(), count, blocked.isoformat() if blocked else None),
            )
        return count, blocked

    def login(self, username, password, *, client="local", now=None):
        when = _now(now)
        try:
            normalized = normalize_username(username)
        except ValueError:
            normalized = str(username)[:128].casefold()
        key = self._attempt_key(normalized, client)
        if self._blocked(key, when):
            self.audit.append("LOGIN_FAILURE", outcome="RATE_LIMITED", context={"client": str(client)[:100]}, now=when)
            raise RateLimited("Too many login attempts; try again later")
        try:
            user = self.identities.by_username(normalized, include_credential=True)
        except (IdentityNotFound, ValueError):
            user = None
        credential = user["password_credential"] if user else self._dummy_credential
        verified = verify_password(password, credential)
        if not verified:
            count, blocked = self._failure(key, when)
            self.audit.append(
                "LOGIN_FAILURE", actor_user_id=user["user_id"] if user else None,
                outcome="RATE_LIMITED" if blocked else "FAILURE",
                context={"attempt_count": count, "client": str(client)[:100]}, now=when,
            )
            if blocked:
                raise RateLimited("Too many login attempts; try again later")
            raise InvalidCredentials("Invalid username or password")
        if not user["enabled"]:
            self.audit.append("LOGIN_FAILURE", actor_user_id=user["user_id"], outcome="DENIED",
                              context={"reason": "account_disabled", "client": str(client)[:100]}, now=when)
            raise AccountDisabled("Account is disabled")
        with self.storage.transaction(operation="security_login_attempt_clear", mode="DEFERRED") as connection:
            connection.execute("DELETE FROM login_attempts WHERE attempt_key=?", (key,))
        self.identities.record_login(user["user_id"], now=when)
        created = self.sessions.create(user, now=when, client_context={"client": str(client)[:100]})
        self.audit.append("LOGIN_SUCCESS", actor_user_id=user["user_id"], outcome="SUCCESS",
                          context={"client": str(client)[:100]}, now=when)
        return user, created
