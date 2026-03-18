"""
Verifiable Credentials — W3C VC Data Model compatible.
Issues and verifies Ed25519-signed credentials.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from sentinel_atl.core import sign, verify, did_to_public_key, sha256_hash


# ─── Types ───────────────────────────────────────────────────────────

@dataclass
class VerifiableCredential:
    """W3C Verifiable Credential Data Model v2.0 compatible credential."""
    context: list[str] = field(default_factory=lambda: [
        "https://www.w3.org/ns/credentials/v2",
        "https://sentinel-atl.github.io/context/v1",
    ])
    id: str = ""
    type: list[str] = field(default_factory=lambda: ["VerifiableCredential"])
    issuer: str = ""
    issuance_date: str = ""
    expiration_date: str = ""
    credential_subject: dict[str, Any] = field(default_factory=dict)
    proof: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "@context": self.context,
            "id": self.id,
            "type": self.type,
            "issuer": self.issuer,
            "issuanceDate": self.issuance_date,
            "expirationDate": self.expiration_date,
            "credentialSubject": self.credential_subject,
            "proof": self.proof,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "VerifiableCredential":
        return VerifiableCredential(
            context=data.get("@context", []),
            id=data.get("id", ""),
            type=data.get("type", []),
            issuer=data.get("issuer", ""),
            issuance_date=data.get("issuanceDate", ""),
            expiration_date=data.get("expirationDate", ""),
            credential_subject=data.get("credentialSubject", {}),
            proof=data.get("proof", {}),
        )


# ─── Canonicalization ────────────────────────────────────────────────

def _sort_deep(value: Any) -> Any:
    """Recursively sort dict keys for deterministic serialization."""
    if isinstance(value, dict):
        return {k: _sort_deep(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [_sort_deep(v) for v in value]
    return value


def _canonicalize_vc(vc_dict: dict[str, Any]) -> bytes:
    """Canonical JSON bytes for signing (excludes proof)."""
    without_proof = {k: v for k, v in vc_dict.items() if k != "proof"}
    canonical = json.dumps(_sort_deep(without_proof), separators=(",", ":"), ensure_ascii=True)
    return canonical.encode("utf-8")


# ─── Issue / Verify ──────────────────────────────────────────────────

def issue_vc(
    issuer_did: str,
    issuer_key_id: str,
    issuer_private_key: bytes,
    subject_did: str,
    credential_type: str = "AgentAuthorization",
    scope: list[str] | None = None,
    expires_in_seconds: int = 86400,
    sensitivity_level: str = "standard",
    max_delegation_depth: int = 0,
) -> VerifiableCredential:
    """Issue a signed Verifiable Credential."""
    now = datetime.now(timezone.utc)

    vc = VerifiableCredential(
        id=f"urn:uuid:{secrets.token_hex(16)}",
        type=["VerifiableCredential", credential_type],
        issuer=issuer_did,
        issuance_date=now.isoformat(),
        expiration_date=(now + timedelta(seconds=expires_in_seconds)).isoformat(),
        credential_subject={
            "id": subject_did,
            "scope": scope or [],
            "sensitivityLevel": sensitivity_level,
            "maxDelegationDepth": max_delegation_depth,
        },
    )

    # Sign
    vc_dict = vc.to_dict()
    payload = _canonicalize_vc(vc_dict)
    signature = sign(payload, issuer_private_key)

    import base64
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")

    vc.proof = {
        "type": "Ed25519Signature2020",
        "created": now.isoformat(),
        "verificationMethod": issuer_key_id,
        "proofPurpose": "assertionMethod",
        "proofValue": sig_b64,
    }

    return vc


def verify_vc(vc: VerifiableCredential) -> dict[str, Any]:
    """Verify a Verifiable Credential's signature and expiry."""
    # Check expiry
    if vc.expiration_date:
        try:
            exp = datetime.fromisoformat(vc.expiration_date)
            if exp < datetime.now(timezone.utc):
                return {"valid": False, "error": "Credential expired"}
        except ValueError:
            return {"valid": False, "error": "Invalid expiration date format"}

    # Extract issuer public key
    issuer_did = vc.issuer
    try:
        public_key = did_to_public_key(issuer_did)
    except ValueError as e:
        return {"valid": False, "error": f"Cannot resolve issuer DID: {e}"}

    # Verify signature
    proof_value = vc.proof.get("proofValue", "")
    if not proof_value:
        return {"valid": False, "error": "No proof value"}

    import base64
    # Add padding
    padding = 4 - len(proof_value) % 4
    if padding != 4:
        proof_value += "=" * padding
    
    try:
        signature = base64.urlsafe_b64decode(proof_value)
    except Exception:
        return {"valid": False, "error": "Invalid proof encoding"}

    vc_dict = vc.to_dict()
    payload = _canonicalize_vc(vc_dict)

    if verify(signature, payload, public_key):
        return {"valid": True}
    else:
        return {"valid": False, "error": "Invalid signature"}
