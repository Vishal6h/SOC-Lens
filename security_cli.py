"""Bounded local security administration for SOCLens."""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from config import ConfigurationError, initialize_runtime_directories, load_config
from security import (
    AuditChainError, IdentityConflict, IdentityNotFound, IdentityService,
    SecurityAuditLog, SessionService,
)
from security.passwords import PasswordPolicyError


def _username(value):
    return value if value else input("Username: ").strip()


def _password(prompt="Password: "):
    first = getpass.getpass(prompt)
    second = getpass.getpass("Confirm password: ")
    if first != second:
        raise ValueError("Passwords do not match")
    return first


def _services(config):
    identities = IdentityService(config.security_database_path, scrypt_n=config.password_scrypt_n)
    sessions = SessionService(
        config.security_database_path,
        idle_minutes=config.session_idle_minutes,
        max_hours=config.session_max_hours,
    )
    return identities, sessions, SecurityAuditLog(config.security_database_path)


def build_parser():
    parser = argparse.ArgumentParser(description="SOCLens local security administration")
    commands = parser.add_subparsers(dest="command", required=True)
    create_admin = commands.add_parser("create-admin", help="bootstrap the first administrator")
    create_admin.add_argument("--username")
    create_admin.add_argument("--display-name")
    create_user = commands.add_parser("create-user", help="create a local user")
    create_user.add_argument("--username")
    create_user.add_argument("--display-name")
    create_user.add_argument("--role", required=True, choices=("ADMIN", "SUPERVISOR", "ASSESSOR", "REVIEWER", "AUDITOR"))
    for name in ("disable-user", "enable-user", "reset-password", "revoke-sessions"):
        command = commands.add_parser(name)
        command.add_argument("username")
    commands.add_parser("list-users")
    commands.add_parser("verify-audit-chain")
    return parser


def main(argv=None):
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        config = load_config()
        initialize_runtime_directories(config)
        identities, sessions, audit = _services(config)
        command = arguments.command
        if command == "create-admin":
            if identities.admin_count():
                raise ValueError("An administrator already exists; use create-user for deliberate additional accounts")
            username = _username(arguments.username)
            display_name = arguments.display_name or input("Display name: ").strip()
            user = identities.create(username, display_name, "ADMIN", _password("Admin password: "))
            audit.append("USER_CREATED", target_type="user", target_id=user["user_id"],
                         context={"role": "ADMIN", "method": "bootstrap"})
            result = {"created": True, "user": user}
        elif command == "create-user":
            username = _username(arguments.username)
            display_name = arguments.display_name or input("Display name: ").strip()
            user = identities.create(username, display_name, arguments.role, _password())
            audit.append("USER_CREATED", target_type="user", target_id=user["user_id"],
                         context={"role": user["role"], "method": "cli"})
            result = {"created": True, "user": user}
        elif command == "list-users":
            result = {"users": identities.list()}
        elif command in {"disable-user", "enable-user"}:
            user = identities.by_username(arguments.username)
            enabled = command == "enable-user"
            updated = identities.update(user["user_id"], enabled=enabled)
            audit.append("USER_ENABLED" if enabled else "USER_DISABLED", target_type="user",
                         target_id=user["user_id"], context={"method": "cli"})
            revoked = 0 if enabled else sessions.revoke_user(user["user_id"])
            if revoked:
                audit.append("SESSION_REVOKED", target_type="user", target_id=user["user_id"],
                             context={"count": revoked, "method": "cli"})
            result = {"updated": True, "user": updated, "sessions_revoked": revoked}
        elif command == "reset-password":
            user = identities.by_username(arguments.username)
            updated = identities.reset_password(user["user_id"], _password("New password: "))
            revoked = sessions.revoke_user(user["user_id"])
            audit.append("PASSWORD_CHANGED", target_type="user", target_id=user["user_id"],
                         context={"method": "cli_reset"})
            result = {"updated": True, "user": updated, "sessions_revoked": revoked}
        elif command == "revoke-sessions":
            user = identities.by_username(arguments.username)
            revoked = sessions.revoke_user(user["user_id"])
            audit.append("SESSION_REVOKED", target_type="user", target_id=user["user_id"],
                         context={"count": revoked, "method": "cli"})
            result = {"user_id": user["user_id"], "sessions_revoked": revoked}
        else:
            result = audit.verify()
    except (ConfigurationError, IdentityConflict, IdentityNotFound, PasswordPolicyError,
            AuditChainError, OSError, ValueError) as exc:
        parser.exit(1, f"SOCLens security operation failed: {exc}\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
