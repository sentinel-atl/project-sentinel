"""Tests for Verifiable Credentials."""
import pytest
from sentinel_atl.core import create_identity
from sentinel_atl.credentials import issue_vc, verify_vc


def test_issue_and_verify_vc():
    issuer = create_identity("issuer")
    subject = create_identity("subject")

    vc = issue_vc(
        issuer_did=issuer.did,
        issuer_key_id=issuer.key_id,
        issuer_private_key=issuer.private_key,
        subject_did=subject.did,
        credential_type="AgentAuthorization",
        scope=["read", "write"],
    )

    assert vc.issuer == issuer.did
    assert vc.credential_subject["id"] == subject.did
    assert vc.credential_subject["scope"] == ["read", "write"]
    assert vc.proof["type"] == "Ed25519Signature2020"

    result = verify_vc(vc)
    assert result["valid"] is True


def test_verify_tampered_vc():
    issuer = create_identity("issuer")
    subject = create_identity("subject")

    vc = issue_vc(
        issuer_did=issuer.did,
        issuer_key_id=issuer.key_id,
        issuer_private_key=issuer.private_key,
        subject_did=subject.did,
        scope=["read"],
    )

    # Tamper with the credential
    vc.credential_subject["scope"] = ["admin"]

    result = verify_vc(vc)
    assert result["valid"] is False


def test_verify_wrong_issuer():
    issuer = create_identity("issuer")
    attacker = create_identity("attacker")
    subject = create_identity("subject")

    vc = issue_vc(
        issuer_did=issuer.did,
        issuer_key_id=issuer.key_id,
        issuer_private_key=issuer.private_key,
        subject_did=subject.did,
        scope=["read"],
    )

    # Swap the issuer DID (but signature was from original issuer's key)
    vc.issuer = attacker.did

    result = verify_vc(vc)
    assert result["valid"] is False
