import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from email.message import Message
from io import BytesIO, StringIO
from pathlib import Path
from unittest import mock

import server as server_module
import security_cli
from assessment_history import initialize_database
from config import ConfigurationError, initialize_runtime_directories, load_config
from security import (
    AuditChainError, AuthenticationService, IdentityConflict, IdentityService,
    InvalidCredentials, RateLimited, SecurityAuditLog, SessionExpired,
    SessionInvalid, SessionService, allowed,
)
from security.passwords import hash_password, verify_password
from security.storage import connect, initialize_security_database


ROOT = Path(__file__).parent
PASSWORD = "Correct horse battery! 42"


class SecurityFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.config = load_config({
            "SOCLENS_ENV": "test", "SOCLENS_DATA_DIR": self.temporary.name,
            "SOCLENS_PASSWORD_SCRYPT_N": "4096", "SOCLENS_LOGIN_ATTEMPT_LIMIT": "3",
            "SOCLENS_LOGIN_BLOCK_SECONDS": "30",
        }, root=ROOT)
        initialize_runtime_directories(self.config)
        initialize_database(self.config.database_path)
        initialize_security_database(self.config.security_database_path)
        self.identities = IdentityService(self.config.security_database_path, scrypt_n=4096)
        self.sessions = SessionService(self.config.security_database_path, idle_minutes=30, max_hours=12)
        self.audit = SecurityAuditLog(self.config.security_database_path)


class PasswordAndIdentityTests(SecurityFixture):
    def test_no_default_credentials_and_admin_creation_is_unique(self):
        self.assertEqual(self.identities.list(), [])
        first = self.identities.create("Admin.User", "Primary Admin", "ADMIN", PASSWORD)
        self.assertEqual(first["username"], "admin.user")
        self.assertNotIn("password_credential", first)
        with self.assertRaises(IdentityConflict):
            self.identities.create("ADMIN.USER", "Duplicate", "ADMIN", PASSWORD)

    def test_password_hashing_salts_verifies_and_rejects_malformed_values(self):
        first, second = hash_password(PASSWORD, n=4096), hash_password(PASSWORD, n=4096)
        self.assertNotEqual(first, second)
        self.assertTrue(verify_password(PASSWORD, first))
        self.assertFalse(verify_password("Wrong password! 42", first))
        for malformed in (None, "", "scrypt$v=1$broken", "not-a-credential"):
            self.assertFalse(verify_password(PASSWORD, malformed))

    def test_bootstrap_cli_prompts_securely_and_refuses_second_bootstrap(self):
        environment = {
            "SOCLENS_ENV": "test", "SOCLENS_DATA_DIR": self.temporary.name,
            "SOCLENS_PASSWORD_SCRYPT_N": "4096",
        }
        with mock.patch.dict(os.environ, environment, clear=True), \
             mock.patch("getpass.getpass", side_effect=[PASSWORD, PASSWORD]), \
             mock.patch("sys.stdout", new_callable=StringIO) as output:
            self.assertEqual(security_cli.main(["create-admin", "--username", "root-admin", "--display-name", "Root Admin"]), 0)
            self.assertNotIn(PASSWORD, output.getvalue())
        with mock.patch.dict(os.environ, environment, clear=True), self.assertRaises(SystemExit):
            security_cli.main(["create-admin", "--username", "another", "--display-name", "Another"])


class SessionAndAuditTests(SecurityFixture):
    def setUp(self):
        super().setUp()
        self.user = self.identities.create("admin", "Admin", "ADMIN", PASSWORD)

    def test_session_creation_expiry_revocation_and_disabled_user(self):
        now = datetime(2026, 10, 2, tzinfo=timezone.utc)
        short = SessionService(self.config.security_database_path, idle_minutes=1, max_hours=1)
        user = self.identities.get(self.user["user_id"], include_credential=True)
        created = short.create(user, now=now)
        self.assertEqual(short.authenticate(created["token"], now=now)["user_id"], user["user_id"])
        with self.assertRaises(SessionExpired):
            short.authenticate(created["token"], now=now + timedelta(minutes=2))
        active = short.create(user, now=now)
        self.assertTrue(short.revoke(active["token"], now=now))
        with self.assertRaises(SessionInvalid):
            short.authenticate(active["token"], now=now)
        assessor = self.identities.create("assessor", "Assessor", "ASSESSOR", PASSWORD)
        assessor_private = self.identities.get(assessor["user_id"], include_credential=True)
        disabled = short.create(assessor_private, now=now)
        self.identities.update(assessor["user_id"], enabled=False, now=now)
        with self.assertRaises(SessionInvalid):
            short.authenticate(disabled["token"], now=now)

    def test_login_rate_limit_is_bounded_and_generic(self):
        authentication = AuthenticationService(
            self.identities, self.sessions, self.audit, attempt_limit=3,
            window_minutes=15, block_seconds=30,
        )
        for username in ("unknown", "admin"):
            with self.assertRaises(InvalidCredentials) as raised:
                authentication.login(username, "Wrong password! 42", client="test")
            self.assertEqual(str(raised.exception), "Invalid username or password")
        with self.assertRaises(InvalidCredentials):
            authentication.login("admin", "Wrong password! 42", client="test")
        with self.assertRaises(RateLimited):
            authentication.login("admin", "Wrong password! 42", client="test")
        event_types = [event["event_type"] for event in self.audit.list(limit=20)]
        self.assertTrue(all(event == "LOGIN_FAILURE" for event in event_types))

    def test_audit_chain_detects_edit_and_tail_deletion_and_rejects_sensitive_context(self):
        self.audit.append("USER_CREATED", target_type="user", target_id=self.user["user_id"])
        self.audit.append("LOGIN_SUCCESS", actor_user_id=self.user["user_id"])
        self.assertEqual(self.audit.verify()["entries"], 2)
        with self.assertRaises(ValueError):
            self.audit.append("LOGIN_FAILURE", context={"password": "must-not-appear"})
        with connect(self.config.security_database_path) as connection:
            connection.execute("UPDATE security_audit_events SET outcome='FAILURE' WHERE sequence=1")
        with self.assertRaises(AuditChainError):
            self.audit.verify()
        with connect(self.config.security_database_path) as connection:
            connection.execute("UPDATE security_audit_events SET outcome='SUCCESS' WHERE sequence=1")
            connection.execute("DELETE FROM security_audit_events WHERE sequence=2")
        with self.assertRaises(AuditChainError):
            self.audit.verify()

    def test_role_matrix_defaults_to_deny(self):
        self.assertTrue(allowed("ASSESSOR", "evidence.import"))
        self.assertFalse(allowed("ASSESSOR", "security.user.read"))
        self.assertTrue(allowed("AUDITOR", "report.export"))
        self.assertFalse(allowed("UNKNOWN", "assessment.read"))
        self.assertFalse(allowed("ADMIN", "not.a.permission"))


class SecurityHttpTests(SecurityFixture):
    def setUp(self):
        super().setUp()
        self.admin = self.identities.create("admin", "Admin User", "ADMIN", PASSWORD)
        self.reviewer = self.identities.create("reviewer", "Review User", "REVIEWER", PASSWORD)
        self.original_config, self.original_database = server_module.CONFIG, server_module.DB
        server_module.CONFIG, server_module.DB = self.config, self.config.database_path

    def tearDown(self):
        server_module.CONFIG, server_module.DB = self.original_config, self.original_database
        super().tearDown()

    def request(self, method, path, body=b"", headers=None):
        handler = object.__new__(server_module.Handler)
        handler.command, handler.path = method, path
        handler.request_version, handler.requestline = "HTTP/1.1", f"{method} {path} HTTP/1.1"
        handler.client_address, handler.server = ("127.0.0.1", 1), object()
        handler.wfile, handler.rfile, handler.headers = BytesIO(), BytesIO(body), Message()
        if body:
            handler.headers["Content-Length"] = str(len(body))
            handler.headers["Content-Type"] = "application/json"
        for name, value in (headers or {}).items():
            handler.headers[name] = value
        getattr(handler, f"do_{method}")()
        head, payload = handler.wfile.getvalue().split(b"\r\n\r\n", 1)
        lines = head.splitlines()
        response_headers = Message()
        for line in lines[1:]:
            name, value = line.decode().split(":", 1)
            response_headers[name] = value.strip()
        content_type = response_headers.get_content_type()
        parsed = json.loads(payload) if content_type == "application/json" else payload
        return int(lines[0].split()[1]), parsed, response_headers

    def login(self, username="admin", password=PASSWORD):
        status, body, headers = self.request(
            "POST", "/api/auth/login",
            json.dumps({"username": username, "password": password}).encode(),
        )
        cookie_header = headers.get("Set-Cookie", "")
        cookie = cookie_header.split(";", 1)[0] if cookie_header else ""
        return status, body, headers, {"Cookie": cookie, "X-CSRF-Token": body.get("csrf_token", "")}

    def test_anonymous_boundary_login_cookie_session_and_logout(self):
        status, body, _ = self.request("GET", "/api/history?scope=demo")
        self.assertEqual((status, body["error"]["code"]), (401, "AUTHENTICATION_REQUIRED"))
        status, body, _ = self.request("GET", "/api/health")
        self.assertEqual((status, body["status"]), (200, "ok"))
        status, session, headers, auth = self.login()
        self.assertEqual(status, 200)
        cookie = headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertNotIn("Secure", cookie)
        self.assertNotIn("session_token", json.dumps(session).casefold())
        status, current, _ = self.request("GET", "/api/auth/session", headers={"Cookie": auth["Cookie"]})
        self.assertEqual((status, current["user"]["role"]), (200, "ADMIN"))
        auth["X-CSRF-Token"] = current["csrf_token"]
        status, _, _ = self.request("POST", "/api/auth/logout", body=b"{}", headers=auth)
        self.assertEqual(status, 200)
        status, body, _ = self.request("GET", "/api/auth/session", headers={"Cookie": auth["Cookie"]})
        self.assertEqual((status, body["error"]["code"]), (401, "AUTHENTICATION_REQUIRED"))

    def test_generic_login_failure_disabled_user_and_rate_limit(self):
        unknown = self.login("nobody", "Wrong password! 42")
        wrong = self.login("admin", "Wrong password! 42")
        self.assertEqual(unknown[1]["error"]["message"], wrong[1]["error"]["message"])
        self.identities.update(self.reviewer["user_id"], enabled=False)
        status, body, _, _ = self.login("reviewer")
        self.assertEqual((status, body["error"]["code"]), (403, "ACCOUNT_DISABLED"))

    def test_csrf_rbac_user_admin_password_change_and_audit(self):
        status, _, _, admin_auth = self.login()
        self.assertEqual(status, 200)
        baseline = (ROOT / "data" / "baseline.json").read_bytes()
        status, body, _ = self.request("POST", "/api/assess", baseline, headers={"Cookie": admin_auth["Cookie"]})
        self.assertEqual((status, body["error"]["code"]), (403, "CSRF_INVALID"))
        status, report, headers = self.request("POST", "/api/assess", baseline, headers=admin_auth)
        self.assertEqual((status, report["score"]), (200, 83.4))
        assessment_id = headers["X-Assessment-ID"]
        status, _, _ = self.request("GET", "/api/report/" + assessment_id, headers={"Cookie": admin_auth["Cookie"]})
        self.assertEqual(status, 200)

        status, created, _ = self.request(
            "POST", "/api/security/users",
            json.dumps({"username": "assessor", "display_name": "Assessor", "role": "ASSESSOR", "password": PASSWORD}).encode(),
            headers=admin_auth,
        )
        self.assertEqual((status, created["user"]["role"]), (201, "ASSESSOR"))
        status, _, _, reviewer_auth = self.login("reviewer")
        self.assertEqual(status, 200)
        status, denied, _ = self.request("GET", "/api/security/users", headers={"Cookie": reviewer_auth["Cookie"]})
        self.assertEqual((status, denied["error"]["code"]), (403, "PERMISSION_DENIED"))
        status, denied, _ = self.request("POST", "/api/assess", baseline, headers=reviewer_auth)
        self.assertEqual((status, denied["error"]["code"]), (403, "PERMISSION_DENIED"))

        change = json.dumps({"current_password": PASSWORD, "new_password": "A newer secure password! 73"}).encode()
        status, changed, changed_headers = self.request("POST", "/api/auth/password", change, headers=admin_auth)
        self.assertEqual(status, 200)
        self.assertIn("Set-Cookie", changed_headers)
        status, _, _ = self.request("GET", "/api/auth/session", headers={"Cookie": admin_auth["Cookie"]})
        self.assertEqual(status, 401)
        events = [event["event_type"] for event in self.audit.list(limit=100)]
        self.assertIn("ASSESSMENT_CREATED", events)
        self.assertIn("ASSESSMENT_EXPORTED", events)
        self.assertIn("AUTHORIZATION_DENIED", events)
        self.assertIn("PASSWORD_CHANGED", events)

    def test_admin_reset_revokes_old_session_and_is_distinctly_audited(self):
        _, _, _, admin_auth = self.login()
        status, _, _, reviewer_auth = self.login("reviewer")
        self.assertEqual(status, 200)
        replacement = "Replacement secure password! 91"
        status, _, _ = self.request(
            "POST", f"/api/security/users/{self.reviewer['user_id']}/reset-password",
            json.dumps({"new_password": replacement}).encode(), headers=admin_auth,
        )
        self.assertEqual(status, 200)
        status, _, _ = self.request("GET", "/api/auth/session", headers={"Cookie": reviewer_auth["Cookie"]})
        self.assertEqual(status, 401)
        self.assertEqual(self.login("reviewer", PASSWORD)[0], 401)
        self.assertEqual(self.login("reviewer", replacement)[0], 200)
        events = self.audit.list(limit=50)
        reset = next(event for event in events if event["event_type"] == "PASSWORD_CHANGED")
        self.assertEqual(reset["context"]["method"], "admin_reset")
        self.assertNotIn(replacement, json.dumps(events))

    def test_import_and_history_authorization(self):
        assessor = self.identities.create("assessor", "Assessor", "ASSESSOR", PASSWORD)
        status, _, _, assessor_auth = self.login("assessor")
        self.assertEqual(status, 200)
        raw = (ROOT / "data/ingestion/generic-controls.json").read_bytes()
        path = "/api/import?profile=generic-controls%401&filename=controls.json&format=json"
        status, job, _ = self.request(
            "POST", path, raw,
            headers={**assessor_auth, "Content-Type": "application/json"},
        )
        self.assertEqual((status, job["status"]), (201, "ready"))
        status, denied, _ = self.request("GET", "/api/history?scope=demo", headers={"Cookie": assessor_auth["Cookie"]})
        self.assertEqual((status, denied["error"]["code"]), (403, "PERMISSION_DENIED"))
        _, _, _, reviewer_auth = self.login("reviewer")
        status, history, _ = self.request("GET", "/api/history?scope=demo", headers={"Cookie": reviewer_auth["Cookie"]})
        self.assertEqual((status, history["scope"]), (200, "demo"))
        status, denied, _ = self.request("POST", path, raw, headers=reviewer_auth)
        self.assertEqual((status, denied["error"]["code"]), (403, "PERMISSION_DENIED"))

    def test_readiness_requires_authentication_and_reports_security_state(self):
        self.assertEqual(self.request("GET", "/api/ready")[0], 401)
        _, _, _, auth = self.login()
        status, ready, _ = self.request("GET", "/api/ready", headers={"Cookie": auth["Cookie"]})
        self.assertEqual((status, ready["status"]), (200, "ready"))
        self.assertTrue(ready["security"]["administrator_ready"])
        self.assertTrue(ready["security"]["audit_chain_ready"])
        self.assertNotIn(self.temporary.name, json.dumps(ready))

    def test_cross_site_login_is_rejected(self):
        status, body, _ = self.request(
            "POST", "/api/auth/login",
            json.dumps({"username": "admin", "password": PASSWORD}).encode(),
            headers={"Sec-Fetch-Site": "cross-site", "Origin": "https://attacker.invalid", "Host": "localhost"},
        )
        self.assertEqual((status, body["error"]["code"]), (403, "CSRF_INVALID"))

    def test_secure_cookie_in_production_configuration(self):
        production = load_config({"SOCLENS_ENV": "production", "SOCLENS_DATA_DIR": self.temporary.name}, root=ROOT)
        server_module.CONFIG = production
        handler = object.__new__(server_module.Handler)
        self.assertIn("Secure", handler._session_cookie("opaque"))


class SecurityConfigurationTests(unittest.TestCase):
    def test_unsafe_production_auth_and_cookie_configurations_fail(self):
        with self.assertRaises(ConfigurationError):
            load_config({"SOCLENS_ENV": "production", "SOCLENS_AUTH_MODE": "disabled"}, root=ROOT)
        with self.assertRaises(ConfigurationError):
            load_config({"SOCLENS_ENV": "production", "SOCLENS_COOKIE_SECURE": "false"}, root=ROOT)

    def test_sensitive_posix_runtime_modes_are_restricted(self):
        if os.name != "posix":
            self.skipTest("POSIX mode assertion")
        with tempfile.TemporaryDirectory() as directory:
            config = load_config({"SOCLENS_ENV": "test", "SOCLENS_DATA_DIR": directory}, root=ROOT)
            initialize_runtime_directories(config)
            initialize_database(config.database_path)
            initialize_security_database(config.security_database_path)
            self.assertEqual(config.data_dir.stat().st_mode & 0o077, 0)
            self.assertEqual(config.database_path.stat().st_mode & 0o077, 0)
            self.assertEqual(config.security_database_path.stat().st_mode & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
