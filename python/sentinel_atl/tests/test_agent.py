"""Tests for the TrustedAgent high-level API."""
import os
import tempfile
import pytest
from sentinel_atl.agent import create_trusted_agent


def test_create_trusted_agent():
    agent = create_trusted_agent("test-agent")
    assert agent.did.startswith("did:key:z")
    assert agent.key_id.startswith(agent.did)


def test_issue_and_verify_credential():
    agent = create_trusted_agent("issuer")
    peer = create_trusted_agent("peer")

    vc = agent.issue_credential(
        subject_did=peer.did,
        credential_type="AgentAuthorization",
        scope=["read", "write"],
    )

    result = agent.verify_credential(vc)
    assert result["valid"] is True


def test_reputation_vouch():
    agent = create_trusted_agent("agent1")
    peer = create_trusted_agent("agent2")

    result = agent.vouch(peer.did, "positive", 0.9, "reliable partner")
    assert result["allowed"] is True

    score = agent.get_reputation(peer.did)
    assert score.score > 50
    assert score.positive_vouches == 1


def test_audit_logging():
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        path = f.name

    try:
        agent = create_trusted_agent("audit-test", audit_log_path=path)
        agent.issue_credential(agent.did, "Test")

        entries = agent.get_audit_entries()
        assert len(entries) >= 2  # identity_created + vc_issued

        integrity = agent.verify_audit_integrity()
        assert integrity["valid"] is True
    finally:
        os.unlink(path)


def test_self_vouch_denied():
    agent = create_trusted_agent("self-voucher")
    result = agent.vouch(agent.did, "positive", 1.0)
    assert result["allowed"] is False
