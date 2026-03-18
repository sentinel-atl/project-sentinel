"""
TrustedAgent — the main developer-facing API.
Mirrors the TypeScript createTrustedAgent() pattern.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from typing import Any, Optional

from sentinel_atl.core import AgentIdentity, create_identity
from sentinel_atl.credentials import VerifiableCredential, issue_vc, verify_vc
from sentinel_atl.reputation import ReputationEngine, ReputationScore
from sentinel_atl.audit import AuditLog
from sentinel_atl.safety import SafetyPipeline, SafetyCheckResult, RegexClassifier


class TrustedAgent:
    """
    A trusted AI agent with identity, credentials, reputation, and audit.

    Usage:
        agent = create_trusted_agent("my-agent")
        vc = agent.issue_credential(peer_did, "AgentAuthorization", ["read"])
        result = agent.verify_credential(vc)
        agent.vouch(peer_did, "positive", 0.8)
    """

    def __init__(
        self,
        identity: AgentIdentity,
        audit_log: AuditLog,
        reputation_engine: ReputationEngine,
        safety_pipeline: Optional[SafetyPipeline] = None,
    ):
        self._identity = identity
        self._audit = audit_log
        self._reputation = reputation_engine
        self._safety = safety_pipeline

    @property
    def did(self) -> str:
        return self._identity.did

    @property
    def key_id(self) -> str:
        return self._identity.key_id

    @property
    def public_key(self) -> bytes:
        return self._identity.public_key

    def issue_credential(
        self,
        subject_did: str,
        credential_type: str = "AgentAuthorization",
        scope: list[str] | None = None,
        expires_in_seconds: int = 86400,
        sensitivity_level: str = "standard",
        max_delegation_depth: int = 0,
    ) -> VerifiableCredential:
        """Issue a signed Verifiable Credential."""
        vc = issue_vc(
            issuer_did=self._identity.did,
            issuer_key_id=self._identity.key_id,
            issuer_private_key=self._identity.private_key,
            subject_did=subject_did,
            credential_type=credential_type,
            scope=scope,
            expires_in_seconds=expires_in_seconds,
            sensitivity_level=sensitivity_level,
            max_delegation_depth=max_delegation_depth,
        )

        self._audit.log(
            event_type="vc_issued",
            actor_did=self._identity.did,
            target_did=subject_did,
            metadata={"type": credential_type, "scope": scope or []},
        )

        return vc

    def verify_credential(self, vc: VerifiableCredential) -> dict[str, Any]:
        """Verify a Verifiable Credential."""
        result = verify_vc(vc)

        self._audit.log(
            event_type="vc_verified",
            actor_did=self._identity.did,
            result="success" if result["valid"] else "failure",
            reason=result.get("error"),
        )

        return result

    def vouch(
        self,
        peer_did: str,
        polarity: str,
        weight: float,
        reason: str = "",
    ) -> dict:
        """Submit a reputation vouch for a peer agent."""
        result = self._reputation.vouch(
            voucher_did=self._identity.did,
            target_did=peer_did,
            polarity=polarity,
            weight=weight,
            reason=reason,
        )

        if result["allowed"]:
            event_type = "reputation_vouch" if polarity == "positive" else "reputation_negative"
            self._audit.log(
                event_type=event_type,
                actor_did=self._identity.did,
                target_did=peer_did,
                metadata={"weight": weight, "polarity": polarity},
            )

        return result

    def get_reputation(self, did: str) -> ReputationScore:
        """Get reputation score for any agent."""
        return self._reputation.compute_score(did)

    async def check_safety(self, text: str) -> Optional[SafetyCheckResult]:
        """Check content safety. Returns None if safety pipeline is not configured."""
        if self._safety is None:
            return None
        return await self._safety.check(text)

    def get_audit_entries(self) -> list:
        """Get all audit log entries."""
        return self._audit.read_all()

    def verify_audit_integrity(self) -> dict[str, Any]:
        """Verify audit log integrity."""
        return self._audit.verify_integrity()


def create_trusted_agent(
    name: str,
    audit_log_path: Optional[str] = None,
    enable_safety: bool = True,
) -> TrustedAgent:
    """
    Create a trusted agent with a single function call.

    Args:
        name: Agent name (used for audit log file naming)
        audit_log_path: Custom path for audit log (default: temp dir)
        enable_safety: Enable content safety pipeline (default: True)

    Returns:
        A TrustedAgent ready to issue credentials, vouch, and verify.
    """
    identity = create_identity(name)

    if audit_log_path is None:
        audit_dir = os.path.join(tempfile.gettempdir(), "sentinel")
        os.makedirs(audit_dir, exist_ok=True)
        audit_log_path = os.path.join(audit_dir, f"{name}-audit.jsonl")

    audit_log = AuditLog(audit_log_path)
    reputation_engine = ReputationEngine()
    safety_pipeline = SafetyPipeline([RegexClassifier()]) if enable_safety else None

    audit_log.log(
        event_type="identity_created",
        actor_did=identity.did,
        metadata={"name": name},
    )

    return TrustedAgent(
        identity=identity,
        audit_log=audit_log,
        reputation_engine=reputation_engine,
        safety_pipeline=safety_pipeline,
    )
