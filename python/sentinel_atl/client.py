"""
STP Client — HTTP client for the Sentinel Trust Protocol server.
Enables Python agents to talk to a TypeScript STP server.
"""

from __future__ import annotations

from typing import Any, Optional
import httpx


class STPClient:
    """
    HTTP client for the Sentinel Trust Protocol (STP) server.
    
    Usage:
        client = STPClient("http://localhost:3000")
        identity = await client.create_identity()
        vc = await client.issue_credential(
            subject_did=identity["did"],
            scope=["read"],
            token=token,
        )
    """

    def __init__(self, base_url: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(timeout=timeout)

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    # ─── Discovery ────────────────────────────────────────────────

    async def get_configuration(self) -> dict[str, Any]:
        """Get STP server configuration (/.well-known/sentinel-configuration)."""
        resp = await self._client.get(f"{self.base_url}/.well-known/sentinel-configuration")
        resp.raise_for_status()
        return resp.json()

    # ─── Identity ─────────────────────────────────────────────────

    async def create_identity(self) -> dict[str, Any]:
        """Create a new agent identity on the server."""
        resp = await self._client.post(f"{self.base_url}/v1/identity")
        resp.raise_for_status()
        return resp.json()

    async def resolve_did(self, did: str) -> dict[str, Any]:
        """Resolve a DID document."""
        resp = await self._client.get(f"{self.base_url}/v1/identity/{did}")
        resp.raise_for_status()
        return resp.json()

    # ─── Credentials ──────────────────────────────────────────────

    async def issue_credential(
        self,
        subject_did: str,
        token: str,
        credential_type: str = "AgentAuthorization",
        scope: list[str] | None = None,
    ) -> dict[str, Any]:
        """Issue a Verifiable Credential via the server."""
        resp = await self._client.post(
            f"{self.base_url}/v1/credentials",
            headers={"Authorization": f"STP {token}"},
            json={
                "subjectDid": subject_did,
                "type": credential_type,
                "scope": scope or [],
            },
        )
        resp.raise_for_status()
        return resp.json()

    async def verify_credential(self, vc: dict[str, Any]) -> dict[str, Any]:
        """Verify a Verifiable Credential via the server."""
        resp = await self._client.post(
            f"{self.base_url}/v1/credentials/verify",
            json=vc,
        )
        resp.raise_for_status()
        return resp.json()

    # ─── Reputation ───────────────────────────────────────────────

    async def get_reputation(self, did: str) -> dict[str, Any]:
        """Query an agent's reputation score."""
        resp = await self._client.get(f"{self.base_url}/v1/reputation/{did}")
        resp.raise_for_status()
        return resp.json()

    async def vouch(
        self,
        target_did: str,
        polarity: str,
        weight: float,
        token: str,
        reason: str = "",
    ) -> dict[str, Any]:
        """Submit a reputation vouch."""
        resp = await self._client.post(
            f"{self.base_url}/v1/reputation/vouch",
            headers={"Authorization": f"STP {token}"},
            json={
                "targetDid": target_did,
                "polarity": polarity,
                "weight": weight,
                "reason": reason,
            },
        )
        resp.raise_for_status()
        return resp.json()

    # ─── Safety ───────────────────────────────────────────────────

    async def check_safety(self, text: str) -> dict[str, Any]:
        """Check content safety via the server."""
        resp = await self._client.post(
            f"{self.base_url}/v1/safety/check",
            json={"text": text},
        )
        resp.raise_for_status()
        return resp.json()

    # ─── Revocation ───────────────────────────────────────────────

    async def check_revocation(self, did: str) -> dict[str, Any]:
        """Check if a DID is revoked."""
        resp = await self._client.get(f"{self.base_url}/v1/revocation/status/{did}")
        resp.raise_for_status()
        return resp.json()

    # ─── Tokens ───────────────────────────────────────────────────

    async def get_token(self, did: str, private_key_hex: str) -> dict[str, Any]:
        """Get an STP token for authentication."""
        resp = await self._client.post(
            f"{self.base_url}/v1/token",
            json={"did": did, "privateKeyHex": private_key_hex},
        )
        resp.raise_for_status()
        return resp.json()

    # ─── Audit ────────────────────────────────────────────────────

    async def get_audit_entries(self) -> list[dict[str, Any]]:
        """Get audit log entries from the server."""
        resp = await self._client.get(f"{self.base_url}/v1/audit")
        resp.raise_for_status()
        return resp.json()
