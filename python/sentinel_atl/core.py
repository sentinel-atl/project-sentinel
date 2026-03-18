"""
Core cryptographic primitives: Ed25519 keypair, DID:key, signing, verification.
Uses PyNaCl (libsodium bindings) for Ed25519 — same curve as the TypeScript SDK.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass
from typing import Optional

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

# ─── Multicodec / Multibase ─────────────────────────────────────────

# Ed25519 public key multicodec prefix: 0xed01
ED25519_MULTICODEC_PREFIX = bytes([0xED, 0x01])

# Base58btc alphabet (Bitcoin alphabet)
_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(data: bytes) -> str:
    """Encode bytes to base58btc string."""
    n = int.from_bytes(data, "big")
    result = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(_B58_ALPHABET[r:r+1])
    # Leading zeros
    for byte in data:
        if byte == 0:
            result.append(b"1")
        else:
            break
    return b"".join(reversed(result)).decode("ascii")


def _b58decode(s: str) -> bytes:
    """Decode base58btc string to bytes."""
    n = 0
    for c in s:
        n = n * 58 + _B58_ALPHABET.index(c.encode("ascii"))
    # Count leading '1's for leading zeros
    leading_zeros = 0
    for c in s:
        if c == "1":
            leading_zeros += 1
        else:
            break
    result = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * leading_zeros + result


# ─── Types ───────────────────────────────────────────────────────────

@dataclass
class KeyPair:
    """Ed25519 key pair."""
    private_key: bytes  # 32 bytes seed
    public_key: bytes   # 32 bytes

@dataclass
class AgentIdentity:
    """Agent identity with DID and keys."""
    did: str
    key_id: str
    public_key: bytes
    private_key: bytes


# ─── Crypto Primitives ───────────────────────────────────────────────

def generate_keypair() -> KeyPair:
    """Generate a new Ed25519 key pair."""
    signing_key = SigningKey.generate()
    return KeyPair(
        private_key=bytes(signing_key),
        public_key=bytes(signing_key.verify_key),
    )


def sign(message: bytes, private_key: bytes) -> bytes:
    """Sign a message with an Ed25519 private key. Returns 64-byte signature."""
    signing_key = SigningKey(private_key)
    signed = signing_key.sign(message)
    return signed.signature  # 64 bytes


def verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
    """Verify an Ed25519 signature. Returns True if valid."""
    try:
        verify_key = VerifyKey(public_key)
        verify_key.verify(message, signature)
        return True
    except BadSignatureError:
        return False


def sha256_hash(data: bytes) -> bytes:
    """SHA-256 hash of data."""
    return hashlib.sha256(data).digest()


def secure_random(n: int) -> bytes:
    """Generate n cryptographically random bytes."""
    return secrets.token_bytes(n)


# ─── DID:key ─────────────────────────────────────────────────────────

def bytes_to_did(public_key: bytes) -> str:
    """Convert an Ed25519 public key to a did:key identifier."""
    multicodec = ED25519_MULTICODEC_PREFIX + public_key
    multibase = "z" + _b58encode(multicodec)
    return f"did:key:{multibase}"


def did_to_public_key(did: str) -> bytes:
    """Extract the Ed25519 public key from a did:key identifier."""
    if not did.startswith("did:key:z"):
        raise ValueError(f"Unsupported DID method: {did}")
    multibase = did.split(":")[-1]
    decoded = _b58decode(multibase[1:])  # Skip 'z' prefix
    if decoded[:2] != ED25519_MULTICODEC_PREFIX:
        raise ValueError("Not an Ed25519 multicodec key")
    return decoded[2:]


def create_identity(name: Optional[str] = None) -> AgentIdentity:
    """Create a new agent identity with a DID:key."""
    kp = generate_keypair()
    did = bytes_to_did(kp.public_key)
    key_id = f"{did}#{did.split(':')[-1]}"
    return AgentIdentity(
        did=did,
        key_id=key_id,
        public_key=kp.public_key,
        private_key=kp.private_key,
    )
