"""Local SOCLens user identities stored outside assessment history."""

from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import re
import sqlite3
import unicodedata
import uuid

from .authorization import ROLES
from .passwords import hash_password, verify_password
from .storage import connect, initialize_security_database


USERNAME = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")


class IdentityConflict(ValueError):
    pass


class IdentityNotFound(LookupError):
    pass


def utc_now():
    return datetime.now(timezone.utc)


def timestamp(value=None):
    return (utc_now() if value is None else value).astimezone(timezone.utc).isoformat()


def normalize_username(username):
    if not isinstance(username, str):
        raise ValueError("Username must be text")
    value = unicodedata.normalize("NFKC", username).strip().casefold()
    if not USERNAME.fullmatch(value):
        raise ValueError(
            "Username must be 3-64 characters using lowercase letters, numbers, dot, underscore, or hyphen"
        )
    return value


def validate_display_name(display_name):
    if not isinstance(display_name, str):
        raise ValueError("Display name must be text")
    value = unicodedata.normalize("NFKC", display_name).strip()
    if not value or len(value) > 100 or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("Display name must be 1-100 control-character-safe characters")
    return value


def validate_role(role):
    value = str(role).strip().upper()
    if value not in ROLES:
        raise ValueError("Unknown security role")
    return value


def _public(row):
    return {
        "user_id": row["user_id"], "username": row["username"],
        "display_name": row["display_name"], "role": row["role"],
        "enabled": bool(row["enabled"]), "created_at": row["created_at"],
        "updated_at": row["updated_at"], "password_changed_at": row["password_changed_at"],
        "last_login_at": row["last_login_at"],
    }


class IdentityService:
    def __init__(self, database, *, scrypt_n=None):
        self.database = database
        self.scrypt_n = scrypt_n
        initialize_security_database(database)

    def create(self, username, display_name, role, password, *, now=None):
        username = normalize_username(username)
        display_name = validate_display_name(display_name)
        role = validate_role(role)
        credential = hash_password(password, **({"n": self.scrypt_n} if self.scrypt_n else {}))
        when = timestamp(now)
        user_id = str(uuid.uuid4())
        try:
            with closing(connect(self.database)) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """INSERT INTO users
                       (user_id,username,display_name,role,password_credential,credential_version,
                        enabled,created_at,updated_at,password_changed_at,last_login_at)
                       VALUES (?,?,?,?,?,1,1,?,?,?,NULL)""",
                    (user_id, username, display_name, role, credential, when, when, when),
                )
                connection.commit()
        except sqlite3.IntegrityError as exc:
            raise IdentityConflict("A user with that username already exists") from exc
        return self.get(user_id)

    def get(self, user_id, *, include_credential=False):
        with closing(connect(self.database)) as connection:
            row = connection.execute("SELECT * FROM users WHERE user_id=?", (user_id,)).fetchone()
        if row is None:
            raise IdentityNotFound("User not found")
        result = _public(row)
        if include_credential:
            result["password_credential"] = row["password_credential"]
            result["credential_version"] = row["credential_version"]
        return result

    def by_username(self, username, *, include_credential=False):
        username = normalize_username(username)
        with closing(connect(self.database)) as connection:
            row = connection.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if row is None:
            raise IdentityNotFound("User not found")
        result = _public(row)
        if include_credential:
            result["password_credential"] = row["password_credential"]
            result["credential_version"] = row["credential_version"]
        return result

    def list(self):
        with closing(connect(self.database)) as connection:
            rows = connection.execute("SELECT * FROM users ORDER BY username").fetchall()
        return [_public(row) for row in rows]

    def admin_count(self):
        with closing(connect(self.database)) as connection:
            return connection.execute(
                "SELECT count(*) FROM users WHERE role='ADMIN'"
            ).fetchone()[0]

    def update(self, user_id, *, role=None, enabled=None, display_name=None, now=None):
        changes = {}
        if role is not None:
            changes["role"] = validate_role(role)
        if enabled is not None:
            if not isinstance(enabled, bool):
                raise ValueError("enabled must be a boolean")
            changes["enabled"] = int(enabled)
        if display_name is not None:
            changes["display_name"] = validate_display_name(display_name)
        if not changes:
            raise ValueError("At least one user field must be changed")
        changes["updated_at"] = timestamp(now)
        assignment = ",".join(f"{name}=?" for name in changes)
        with closing(connect(self.database)) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute("SELECT * FROM users WHERE user_id=?", (user_id,)).fetchone()
                if row is None:
                    raise IdentityNotFound("User not found")
                if row["role"] == "ADMIN" and bool(row["enabled"]) and (
                    changes.get("role", "ADMIN") != "ADMIN" or changes.get("enabled", 1) == 0
                ):
                    count = connection.execute(
                        "SELECT count(*) FROM users WHERE role='ADMIN' AND enabled=1"
                    ).fetchone()[0]
                    if count <= 1:
                        raise ValueError("The last enabled administrator cannot be disabled or demoted")
                connection.execute(
                    f"UPDATE users SET {assignment} WHERE user_id=?",
                    (*changes.values(), user_id),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return self.get(user_id)

    def _enabled_admin_count(self):
        with closing(connect(self.database)) as connection:
            return connection.execute(
                "SELECT count(*) FROM users WHERE role='ADMIN' AND enabled=1"
            ).fetchone()[0]

    def change_password(self, user_id, current_password, new_password, *, now=None):
        user = self.get(user_id, include_credential=True)
        if not verify_password(current_password, user["password_credential"]):
            raise ValueError("Current password is incorrect")
        return self.reset_password(user_id, new_password, now=now)

    def reset_password(self, user_id, new_password, *, now=None):
        self.get(user_id)
        credential = hash_password(new_password, **({"n": self.scrypt_n} if self.scrypt_n else {}))
        when = timestamp(now)
        with closing(connect(self.database)) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """UPDATE users SET password_credential=?, credential_version=credential_version+1,
                   password_changed_at=?, updated_at=? WHERE user_id=?""",
                (credential, when, when, user_id),
            )
            connection.commit()
        return self.get(user_id)

    def record_login(self, user_id, *, now=None):
        when = timestamp(now)
        with closing(connect(self.database)) as connection:
            connection.execute(
                "UPDATE users SET last_login_at=?, updated_at=? WHERE user_id=?",
                (when, when, user_id),
            )
