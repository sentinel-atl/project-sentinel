"""
Tamper-evident audit logging with SHA-256 hash chain.
Compatible with the TypeScript AuditLog format (JSONL).
"""

from __future__ import annotations

import json
import hashlib
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


GENESIS_HASH = "0" * 64

AUDIT_EVENT_TYPES = {
    "identity_created", "handshake_init", "handshake_complete", "handshake_failed",
    "vc_issued", "vc_verified", "vc_revoked", "intent_created", "intent_validated",
    "intent_rejected", "session_created", "session_terminated", "reputation_vouch",
    "reputation_negative", "emergency_revoke", "key_rotated", "key_backup_created",
    "key_recovered",
}


@dataclass
class AuditEntry:
    """A single audit log entry."""
    timestamp: str
    event_type: str
    actor_did: str
    target_did: Optional[str] = None
    intent_id: Optional[str] = None
    result: str = "success"
    reason: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None
    prev_hash: str = GENESIS_HASH
    entry_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict matching TypeScript JSONL format."""
        d: dict[str, Any] = {
            "timestamp": self.timestamp,
            "eventType": self.event_type,
            "actorDid": self.actor_did,
            "result": self.result,
            "prevHash": self.prev_hash,
            "entryHash": self.entry_hash,
        }
        if self.target_did:
            d["targetDid"] = self.target_did
        if self.intent_id:
            d["intentId"] = self.intent_id
        if self.reason:
            d["reason"] = self.reason
        if self.metadata:
            d["metadata"] = self.metadata
        return d

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "AuditEntry":
        return AuditEntry(
            timestamp=data["timestamp"],
            event_type=data["eventType"],
            actor_did=data["actorDid"],
            target_did=data.get("targetDid"),
            intent_id=data.get("intentId"),
            result=data.get("result", "success"),
            reason=data.get("reason"),
            metadata=data.get("metadata"),
            prev_hash=data.get("prevHash", GENESIS_HASH),
            entry_hash=data.get("entryHash", ""),
        )


def _sort_deep(value: Any) -> Any:
    """Recursively sort dict keys for deterministic hashing."""
    if isinstance(value, dict):
        return {k: _sort_deep(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [_sort_deep(v) for v in value]
    return value


def _compute_entry_hash(entry_dict: dict[str, Any]) -> str:
    """Compute SHA-256 hash of an entry (excluding entryHash)."""
    without_hash = {k: v for k, v in entry_dict.items() if k != "entryHash"}
    canonical = json.dumps(_sort_deep(without_hash), separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLog:
    """
    Append-only, hash-chain integrity audit log.
    
    Compatible with TypeScript @sentinel-atl/audit JSONL format.
    Can verify logs produced by the TypeScript SDK and vice versa.
    """

    def __init__(self, log_path: str):
        self.log_path = log_path
        self._last_hash = GENESIS_HASH
        self._initialized = False

    def init(self) -> None:
        """Initialize: read last hash from existing file."""
        if self._initialized:
            return

        path = Path(self.log_path)
        if path.exists():
            content = path.read_text("utf-8").strip()
            if content:
                lines = content.split("\n")
                last_line = lines[-1]
                last_entry = json.loads(last_line)
                self._last_hash = last_entry.get("entryHash", GENESIS_HASH)

        self._initialized = True

    def log(
        self,
        event_type: str,
        actor_did: str,
        result: str = "success",
        target_did: Optional[str] = None,
        intent_id: Optional[str] = None,
        reason: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> AuditEntry:
        """Append an audit event. Returns the entry with its hash."""
        self.init()

        entry_dict: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "eventType": event_type,
            "actorDid": actor_did,
            "result": result,
            "prevHash": self._last_hash,
        }
        if target_did:
            entry_dict["targetDid"] = target_did
        if intent_id:
            entry_dict["intentId"] = intent_id
        if reason:
            entry_dict["reason"] = reason
        if metadata:
            entry_dict["metadata"] = metadata

        entry_hash = _compute_entry_hash(entry_dict)
        entry_dict["entryHash"] = entry_hash

        # Append to file
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry_dict) + "\n")

        self._last_hash = entry_hash

        return AuditEntry.from_dict(entry_dict)

    def verify_integrity(self) -> dict[str, Any]:
        """
        Verify the hash chain integrity of the audit log.
        Returns {valid, total_entries, broken_at?, error?}.
        """
        path = Path(self.log_path)
        if not path.exists():
            return {"valid": True, "total_entries": 0}

        content = path.read_text("utf-8").strip()
        if not content:
            return {"valid": True, "total_entries": 0}

        lines = content.split("\n")
        expected_prev_hash = GENESIS_HASH

        for i, line in enumerate(lines):
            entry = json.loads(line)

            # Check chain link
            if entry.get("prevHash") != expected_prev_hash:
                return {
                    "valid": False,
                    "total_entries": len(lines),
                    "broken_at": i,
                    "error": f"Chain broken at entry {i}",
                }

            # Recompute hash
            recomputed = _compute_entry_hash(entry)
            if recomputed != entry.get("entryHash"):
                return {
                    "valid": False,
                    "total_entries": len(lines),
                    "broken_at": i,
                    "error": f"Hash mismatch at entry {i}: possible tampering",
                }

            expected_prev_hash = entry["entryHash"]

        return {"valid": True, "total_entries": len(lines)}

    def read_all(self) -> list[AuditEntry]:
        """Read all audit entries."""
        path = Path(self.log_path)
        if not path.exists():
            return []

        content = path.read_text("utf-8").strip()
        if not content:
            return []

        return [AuditEntry.from_dict(json.loads(line)) for line in content.split("\n")]
