"""
sentinel-atl — The Agent Trust Layer for AI agents (Python SDK)

Identity, credentials, and reputation for AI agents.

Quick start:
    from sentinel_atl import create_trusted_agent

    agent = create_trusted_agent("my-agent")
    vc = agent.issue_credential(agent.did, "AgentAuthorization", ["read"])
    result = agent.verify_credential(vc)
"""

from sentinel_atl.core import (
    generate_keypair,
    sign,
    verify,
    sha256_hash,
    bytes_to_did,
    did_to_public_key,
    create_identity,
    AgentIdentity,
)
from sentinel_atl.credentials import (
    issue_vc,
    verify_vc,
    VerifiableCredential,
)
from sentinel_atl.reputation import (
    ReputationEngine,
    ReputationScore,
)
from sentinel_atl.audit import AuditLog, AuditEntry
from sentinel_atl.safety import SafetyPipeline, RegexClassifier
from sentinel_atl.agent import TrustedAgent, create_trusted_agent

__version__ = "0.1.2"

__all__ = [
    "create_trusted_agent",
    "TrustedAgent",
    "generate_keypair",
    "sign",
    "verify",
    "sha256_hash",
    "bytes_to_did",
    "did_to_public_key",
    "create_identity",
    "AgentIdentity",
    "issue_vc",
    "verify_vc",
    "VerifiableCredential",
    "ReputationEngine",
    "ReputationScore",
    "AuditLog",
    "AuditEntry",
    "SafetyPipeline",
    "RegexClassifier",
]
