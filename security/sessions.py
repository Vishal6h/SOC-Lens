"""Opaque server-side sessions with expiry, revocation, and CSRF binding."""

from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import secrets

from .authorization import permissions_for
from .storage import connect, initialize_security_database


class SessionInvalid(PermissionError):
    pass


class SessionExpired(SessionInvalid):
    pass


def _now(value=None):
    return datetime.now(timezone.utc) if value is None else value.astimezone(timezone.utc)


def _parse(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _hash(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def csrf_valid(raw_token, expected_hash):
    if not isinstance(raw_token, str) or not raw_token or len(raw_token) > 200:
        return False
    try:
        actual = _hash(raw_token)
    except (UnicodeEncodeError, ValueError):
        return False
    return hmac.compare_digest(actual, expected_hash)


class SessionService:
    def __init__(self, database, *, idle_minutes=30, max_hours=12):
        if not 1 <= idle_minutes <= 1440 or not 1 <= max_hours <= 168:
            raise ValueError("Session durations are out of bounds")
        self.database = database
        self.idle_minutes = idle_minutes
        self.max_hours = max_hours
        initialize_security_database(database)

    def create(self, user, *, now=None, client_context=None):
        when = _now(now)
        token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        absolute = when + timedelta(hours=self.max_hours)
        idle = min(absolute, when + timedelta(minutes=self.idle_minutes))
        context = None if client_context is None else json.dumps(client_context, sort_keys=True, separators=(",", ":"))[:500]
        with closing(connect(self.database)) as connection:
            connection.execute(
                """INSERT INTO sessions
                   (session_hash,user_id,credential_version,csrf_hash,created_at,last_activity_at,
                    idle_expires_at,absolute_expires_at,revoked,revoked_at,client_context)
                   VALUES (?,?,?,?,?,?,?,?,0,NULL,?)""",
                (_hash(token), user["user_id"], user["credential_version"], _hash(csrf_token),
                 when.isoformat(), when.isoformat(), idle.isoformat(), absolute.isoformat(), context),
            )
        return {"token": token, "csrf_token": csrf_token, "absolute_expires_at": absolute.isoformat()}

    def authenticate(self, token, *, now=None, touch=True):
        if not isinstance(token, str) or not 20 <= len(token) <= 200:
            raise SessionInvalid("Authentication is required")
        when = _now(now)
        with closing(connect(self.database)) as connection:
            row = connection.execute(
                """SELECT s.*,u.username,u.display_name,u.role,u.enabled,u.updated_at,
                          u.password_changed_at,u.credential_version AS current_credential_version
                   FROM sessions s JOIN users u ON u.user_id=s.user_id WHERE s.session_hash=?""",
                (_hash(token),),
            ).fetchone()
            if row is None or row["revoked"]:
                raise SessionInvalid("Authentication is required")
            if (when >= _parse(row["idle_expires_at"]) or when >= _parse(row["absolute_expires_at"])):
                connection.execute(
                    "UPDATE sessions SET revoked=1,revoked_at=? WHERE session_hash=?",
                    (when.isoformat(), row["session_hash"]),
                )
                raise SessionExpired("Session has expired")
            if not row["enabled"] or row["credential_version"] != row["current_credential_version"]:
                connection.execute(
                    "UPDATE sessions SET revoked=1,revoked_at=? WHERE session_hash=?",
                    (when.isoformat(), row["session_hash"]),
                )
                raise SessionInvalid("Authentication is required")
            idle_expires = min(
                _parse(row["absolute_expires_at"]), when + timedelta(minutes=self.idle_minutes)
            )
            if touch:
                connection.execute(
                    "UPDATE sessions SET last_activity_at=?,idle_expires_at=? WHERE session_hash=?",
                    (when.isoformat(), idle_expires.isoformat(), row["session_hash"]),
                )
        return {
            "session_hash": row["session_hash"], "user_id": row["user_id"],
            "username": row["username"], "display_name": row["display_name"],
            "role": row["role"], "permissions": sorted(permissions_for(row["role"])),
            "csrf_hash": row["csrf_hash"], "created_at": row["created_at"],
            "last_activity_at": when.isoformat() if touch else row["last_activity_at"],
            "idle_expires_at": idle_expires.isoformat(),
            "absolute_expires_at": row["absolute_expires_at"],
        }

    def issue_csrf(self, session_hash):
        token = secrets.token_urlsafe(32)
        with closing(connect(self.database)) as connection:
            cursor = connection.execute(
                "UPDATE sessions SET csrf_hash=? WHERE session_hash=? AND revoked=0",
                (_hash(token), session_hash),
            )
        if cursor.rowcount != 1:
            raise SessionInvalid("Authentication is required")
        return token

    def revoke(self, token, *, now=None):
        when = _now(now).isoformat()
        if not isinstance(token, str) or not 20 <= len(token) <= 200:
            return False
        with closing(connect(self.database)) as connection:
            cursor = connection.execute(
                "UPDATE sessions SET revoked=1,revoked_at=? WHERE session_hash=? AND revoked=0",
                (when, _hash(token)),
            )
        return cursor.rowcount > 0

    def revoke_user(self, user_id, *, except_session_hash=None, now=None):
        when = _now(now).isoformat()
        query = "UPDATE sessions SET revoked=1,revoked_at=? WHERE user_id=? AND revoked=0"
        parameters = [when, user_id]
        if except_session_hash:
            query += " AND session_hash<>?"
            parameters.append(except_session_hash)
        with closing(connect(self.database)) as connection:
            cursor = connection.execute(query, parameters)
        return cursor.rowcount

    def rotate(self, token, user, *, now=None, client_context=None):
        self.revoke(token, now=now)
        return self.create(user, now=now, client_context=client_context)
