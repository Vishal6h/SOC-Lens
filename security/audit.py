"""Bounded append-only-style security events with a SHA-256 hash chain."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
import uuid

from .storage import SecurityStorage


GENESIS_HASH = "0" * 64
EVENT_TYPE = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
OUTCOMES = {"SUCCESS", "FAILURE", "DENIED", "RATE_LIMITED", "ATTEMPTED"}
SENSITIVE_KEY_PARTS = ("password", "credential", "token", "csrf", "secret", "evidence", "payload", "session")
MAX_CONTEXT_BYTES = 2048


class AuditChainError(RuntimeError):
    pass


def _timestamp(now=None):
    return (datetime.now(timezone.utc) if now is None else now).astimezone(timezone.utc).isoformat()


def _context(value):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("Security audit context must be an object")
    clean = {}
    for key, item in value.items():
        name = str(key)
        if any(part in name.casefold() for part in SENSITIVE_KEY_PARTS):
            raise ValueError("Sensitive fields are not permitted in security audit context")
        if isinstance(item, (str, int, float, bool)) or item is None:
            if isinstance(item, str) and any(ord(character) < 32 or ord(character) == 127 for character in item):
                raise ValueError("Security audit context strings must not contain control characters")
            clean[name[:80]] = item if not isinstance(item, str) else item[:300]
        elif isinstance(item, list) and len(item) <= 20 and all(
            isinstance(entry, (str, int, float, bool)) or entry is None for entry in item
        ):
            clean[name[:80]] = [entry[:100] if isinstance(entry, str) else entry for entry in item]
        else:
            raise ValueError("Security audit context contains an unsupported value")
    encoded = json.dumps(clean, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(encoded.encode("utf-8")) > MAX_CONTEXT_BYTES:
        raise ValueError("Security audit context is too large")
    return clean


def _label(name, value, maximum, *, required=False):
    if value is None and not required:
        return None
    if not isinstance(value, str) or (required and not value) or len(value) > maximum:
        raise ValueError(f"Invalid security audit {name}")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"Invalid security audit {name}")
    return value


def _canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _entry_hash(document):
    return hashlib.sha256(_canonical(document).encode("utf-8")).hexdigest()


class SecurityAuditLog:
    def __init__(self, database, *, storage=None):
        self.storage = storage or SecurityStorage(database)
        self.database = self.storage.path
        self.storage.initialize()

    def append(self, event_type, *, actor_user_id=None, target_type=None, target_id=None,
               outcome="SUCCESS", context=None, now=None):
        if not isinstance(event_type, str) or not EVENT_TYPE.fullmatch(event_type):
            raise ValueError("Invalid security audit event type")
        if outcome not in OUTCOMES:
            raise ValueError("Invalid security audit outcome")
        actor_user_id = _label("actor_user_id", actor_user_id, 100)
        target_type = _label("target_type", target_type, 80)
        target_id = _label("target_id", target_id, 300)
        context = _context(context)
        event_id, when = str(uuid.uuid4()), _timestamp(now)
        with self.storage.transaction(operation="security_audit_append") as connection:
            previous = connection.execute(
                "SELECT sequence,entry_hash FROM security_audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            state = connection.execute(
                "SELECT entry_count,head_hash FROM security_audit_chain_state WHERE singleton=1"
            ).fetchone()
            if state is None or state["entry_count"] != (previous["sequence"] if previous else 0) or state["head_hash"] != (previous["entry_hash"] if previous else GENESIS_HASH):
                raise AuditChainError("Security audit chain state does not match the event log")
            previous_hash = previous["entry_hash"] if previous else GENESIS_HASH
            document = {
                "event_id": event_id, "timestamp": when,
                "actor_user_id": actor_user_id, "event_type": event_type,
                "target_type": target_type, "target_id": target_id,
                "outcome": outcome, "context": context, "previous_hash": previous_hash,
            }
            digest = _entry_hash(document)
            cursor = connection.execute(
                """INSERT INTO security_audit_events
                   (event_id,timestamp,actor_user_id,event_type,target_type,target_id,outcome,
                    context_json,previous_hash,entry_hash) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (event_id, when, actor_user_id, event_type, target_type, target_id, outcome,
                 _canonical(context), previous_hash, digest),
            )
            sequence = cursor.lastrowid
            connection.execute(
                "UPDATE security_audit_chain_state SET entry_count=?,head_hash=? WHERE singleton=1",
                (sequence, digest),
            )
        document.update({"sequence": sequence, "entry_hash": digest})
        return document

    def list(self, *, limit=100, before_sequence=None):
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        query = "SELECT * FROM security_audit_events"
        parameters = []
        if before_sequence is not None:
            if not isinstance(before_sequence, int) or before_sequence < 1:
                raise ValueError("before_sequence must be a positive integer")
            query += " WHERE sequence < ?"
            parameters.append(before_sequence)
        query += " ORDER BY sequence DESC LIMIT ?"
        parameters.append(limit)
        with self.storage.connection(readonly=True, operation="security_audit_list") as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [self._document(row) for row in rows]

    @staticmethod
    def _document(row):
        return {
            "sequence": row["sequence"], "event_id": row["event_id"],
            "timestamp": row["timestamp"], "actor_user_id": row["actor_user_id"],
            "event_type": row["event_type"], "target_type": row["target_type"],
            "target_id": row["target_id"], "outcome": row["outcome"],
            "context": json.loads(row["context_json"]),
            "previous_hash": row["previous_hash"], "entry_hash": row["entry_hash"],
        }

    def verify(self):
        with self.storage.connection(readonly=True, operation="security_audit_verify") as connection:
            rows = connection.execute(
                "SELECT * FROM security_audit_events ORDER BY sequence"
            ).fetchall()
            state = connection.execute(
                "SELECT entry_count,head_hash FROM security_audit_chain_state WHERE singleton=1"
            ).fetchone()
        previous_hash = GENESIS_HASH
        expected_sequence = 1
        for row in rows:
            event = self._document(row)
            if event["sequence"] != expected_sequence:
                raise AuditChainError(f"Security audit sequence gap before entry {event['sequence']}")
            if event["previous_hash"] != previous_hash:
                raise AuditChainError(f"Security audit linkage failed at entry {event['sequence']}")
            hashed = {key: event[key] for key in (
                "event_id", "timestamp", "actor_user_id", "event_type", "target_type",
                "target_id", "outcome", "context", "previous_hash",
            )}
            if _entry_hash(hashed) != event["entry_hash"]:
                raise AuditChainError(f"Security audit hash failed at entry {event['sequence']}")
            previous_hash = event["entry_hash"]
            expected_sequence += 1
        if state is None or state["entry_count"] != len(rows) or state["head_hash"] != previous_hash:
            raise AuditChainError("Security audit chain head or entry count does not match")
        return {"valid": True, "entries": len(rows), "head_hash": previous_hash}
