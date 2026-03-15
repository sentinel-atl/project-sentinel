# Agent Identity Document (AID) Specification v0.1

**Status:** Draft  
**Authors:** Project Sentinel Contributors  
**Date:** March 2026  
**License:** Apache 2.0  

---

## Abstract

This document specifies the Agent Identity Document (AID) protocol — a trust layer for autonomous AI agents. AID provides decentralized identity, verifiable credentials, a zero-trust handshake protocol, proof of intent, and tamper-evident audit logging. It is designed to interoperate with existing agent frameworks (MCP, A2A) without requiring changes to those protocols.

---

## 1. Terminology

| Term | Definition |
|---|---|
| **Agent** | An autonomous software entity that acts on behalf of a principal. |
| **Principal** | The human or organization that ultimately authorized the agent's actions. |
| **DID** | Decentralized Identifier per [W3C DID Core](https://www.w3.org/TR/did-core/). |
| **VC** | Verifiable Credential per [W3C VC Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/). |
| **Intent Envelope** | A signed, time-bounded, non-replayable declaration of what an agent intends to do and who authorized it. |
| **Handshake** | A mutual verification protocol between two agents before any data exchange. |
| **Passport** | A machine-readable trust profile published by an agent. |
| **Vouch** | A reputation signal (positive or negative) from one agent about another. |
| **Delegation Chain** | An ordered sequence of VCs from principal → agent → sub-agent, each narrowing scope. |

---

## 2. Identity

### 2.1 DID Method

AID v0.1 uses the `did:key` method with Ed25519 public keys.

**Format:**

```
did:key:z<base58btc( 0xed01 || public_key_bytes )>
```

- Multicodec prefix: `0xed01` (Ed25519 public key)
- Public key: 32 bytes
- Encoding: `z` prefix + base58btc (Bitcoin alphabet)

**Example:**

```
did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP
```

### 2.2 DID Document

Resolved from the DID string itself (no external registry needed):

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1"
  ],
  "id": "did:key:z6Mkf5rG...",
  "verificationMethod": [{
    "id": "did:key:z6Mkf5rG...#z6Mkf5rG...",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:key:z6Mkf5rG...",
    "publicKeyMultibase": "z6Mkf5rG..."
  }],
  "authentication": ["did:key:z6Mkf5rG...#z6Mkf5rG..."],
  "assertionMethod": ["did:key:z6Mkf5rG...#z6Mkf5rG..."]
}
```

### 2.3 Key Storage

Private keys MUST NOT be stored in plaintext. Implementations SHOULD use OS-native secure storage (macOS Keychain, Windows DPAPI, Linux Secret Service). The `KeyProvider` interface abstracts storage so HSM backends can be swapped.

### 2.4 Key Recovery

Key loss is catastrophic (all VCs become unverifiable). Implementations MUST support Shamir's Secret Sharing:

- **Default scheme:** 3-of-5
- **Field:** GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1
- **Share format:** JSON with `index` (1-based), `data` (base64url), `totalShares`, `threshold`

---

## 3. Verifiable Credentials

### 3.1 Data Model

All VCs follow [W3C VC Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/) with the Sentinel context:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://sentinel-protocol.org/ns/v1"
  ],
  "id": "urn:uuid:<random>",
  "type": ["VerifiableCredential", "<CredentialType>"],
  "issuer": "<issuer DID>",
  "issuanceDate": "<ISO 8601>",
  "expirationDate": "<ISO 8601>",
  "credentialSubject": {
    "id": "<subject DID>",
    "scope": ["<permission>", ...],
    "maxDelegationDepth": <integer>,
    "sensitivityLevel": "low" | "medium" | "high" | "critical"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "<ISO 8601>",
    "verificationMethod": "<issuer DID>#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "<base64url signature>"
  }
}
```

### 3.2 Credential Types

| Type | Purpose |
|---|---|
| `AgentAuthorizationCredential` | Principal authorizes an agent with specific scope |
| `DelegationCredential` | Agent delegates subset of scope to a sub-agent |
| `ComplianceCredential` | Attests compliance with a standard (e.g., SOC2) |
| `ReputationCredential` | Positive reputation vouch |
| `NegativeReputationCredential` | Negative reputation vouch with reason |
| `CodeAttestationCredential` | Binds agent DID to a verified code hash |

### 3.3 Signature Scheme

1. Remove the `proof` field from the VC
2. Recursively sort all object keys alphabetically (deep sort)
3. Serialize to JSON (`JSON.stringify`)
4. Sign the UTF-8 bytes with Ed25519
5. Encode the signature as base64url (no padding)

### 3.4 Verification

A VC is valid if and only if:

1. **Issuer DID resolves** — the `issuer` field is a valid `did:key` from which a public key can be extracted
2. **Signature verifies** — the Ed25519 signature over the canonicalized VC body matches the issuer's public key
3. **Not expired** — `expirationDate` has not passed (with ±30 second clock tolerance)

### 3.5 Scope Narrowing

Delegation MUST only narrow scope, never widen. Given a parent VC with scope `[A, B, C]`, a child DelegationCredential may have scope `[A]` or `[A, B]` but NOT `[A, D]`.

Formally: `childScope ⊆ parentScope` (strict set subset using string equality).

### 3.6 Delegation Chain Validation

A delegation chain `[VC₀, VC₁, ..., VCₙ]` is valid if:

1. Each VCᵢ passes individual verification (§3.4)
2. For all i > 0: `VCᵢ.scope ⊆ VCᵢ₋₁.scope`
3. For all i: `i < VCᵢ₋₁.maxDelegationDepth` (if defined)

---

## 4. Handshake Protocol

### 4.1 Overview

Two agents MUST complete a 5-step mutual verification before exchanging any task data. The protocol ensures both parties prove identity, present credentials, and demonstrate liveness.

```
Agent A                                 Agent B
   |                                       |
   |── 1. HandshakeInit ─────────────────>|
   |                                       |
   |<── 2. HandshakeResponse ─────────────|
   |                                       |
   |── 3. VCExchange (A → B) ────────────>|
   |                                       |
   |<── 4. VCExchange (B → A) ────────────|
   |                                       |
   |── 5. SessionEstablished ─────────────>|
   |                                       |
```

### 4.2 Message Formats

#### HandshakeInit

```json
{
  "type": "handshake_init",
  "protocolVersion": "1.0",
  "initiatorDid": "<DID>",
  "supportedVCTypes": ["AgentAuthorizationCredential", ...],
  "nonce": "<64 hex chars (32 bytes)>",
  "timestamp": "<ISO 8601>",
  "passport": { ... }
}
```

#### HandshakeResponse

```json
{
  "type": "handshake_response",
  "protocolVersion": "1.0",
  "responderDid": "<DID>",
  "requestedVCTypes": ["DelegationCredential", ...],
  "nonce": "<64 hex chars (32 bytes)>",
  "timestamp": "<ISO 8601>",
  "passport": { ... }
}
```

#### VCExchange

```json
{
  "type": "vc_exchange",
  "senderDid": "<DID>",
  "credentials": [ <VerifiableCredential>, ... ],
  "proofOfLiveness": "<base64url signature>"
}
```

The `proofOfLiveness` is an Ed25519 signature over `peer_nonce + JSON.stringify(credential_ids)`, proving the sender is live and responding to the specific handshake session.

#### SessionEstablished

```json
{
  "type": "session_established",
  "sessionId": "<32 hex chars (16 bytes)>",
  "negotiatedVersion": "1.0",
  "initiatorDid": "<DID>",
  "responderDid": "<DID>",
  "createdAt": "<ISO 8601>",
  "expiresAt": "<ISO 8601>"
}
```

### 4.3 Error Codes

| Code | Meaning |
|---|---|
| `VERSION_MISMATCH` | No common protocol version |
| `VC_VERIFICATION_FAILED` | A presented VC failed verification |
| `RATE_LIMITED` | Too many handshake attempts from this DID |
| `TIMEOUT` | Handshake did not complete within deadline |
| `CLOCK_SKEW` | Timestamp exceeds ±30s tolerance |
| `TRUST_REQUIREMENTS_NOT_MET` | Passport requirements not satisfiable |
| `CIRCUIT_OPEN` | Circuit breaker open after repeated failures |

### 4.4 Rate Limiting

Implementations MUST enforce per-DID rate limits on handshake initiations:

- **Default:** 10 handshakes per minute per DID
- **Window:** Sliding 60-second window
- On breach: return `RATE_LIMITED` error with `retryAfterMs`

### 4.5 Circuit Breaker

Repeated failures from the same DID trigger a circuit breaker:

- **Threshold:** 5 consecutive failures
- **Cool-off:** 60 seconds
- **Recovery:** Half-open state allows one attempt after cool-off

### 4.6 Clock Tolerance

All timestamp comparisons MUST allow ±30 seconds of clock skew. This applies to handshake timestamps, VC expiration checks, and intent expiry.

---

## 5. Proof of Intent

### 5.1 Purpose

The Intent Envelope is Sentinel's primary differentiator. It binds every agent action to:
- **What** the agent is doing (action + scope)
- **Who** authorized it (principal DID + delegation chain)
- **When** authorization expires
- **Proof** it cannot be replayed (nonce)

No other agent trust protocol provides this linkage.

### 5.2 Envelope Format

```json
{
  "intentId": "<UUIDv7-like>",
  "version": "1.0",
  "action": "<human-readable action>",
  "scope": ["<permission>", ...],
  "principalDid": "<DID of human/org principal>",
  "agentDid": "<DID of executing agent>",
  "delegationChain": ["<VC ID>", ...],
  "expiry": "<ISO 8601>",
  "nonce": "<64 hex chars (32 bytes)>",
  "signature": "<base64url Ed25519 signature>"
}
```

### 5.3 Signing

1. Construct the envelope body (all fields except `signature`)
2. Recursively sort all object keys alphabetically
3. JSON-serialize and encode as UTF-8 bytes
4. Sign with the agent's Ed25519 private key
5. Encode as base64url

### 5.4 Validation

An intent is valid if:

1. **Nonce** is exactly 64 hex characters (32 bytes) and has NOT been seen before
2. **Not expired** — `expiry` has not passed (±30s clock tolerance)
3. **Scope non-empty** — at least one permission listed
4. **Signature valid** — Ed25519 signature verifies against `agentDid`'s public key

Implementations MUST track seen nonces to prevent replay attacks.

### 5.5 Intent ID Format

Time-ordered identifier for natural chronological sorting:

```
<48-bit timestamp hex>-<random>-7<random>-<random>-<random>
```

---

## 6. Agent Passport

### 6.1 Format

```json
{
  "@context": ["https://sentinel-protocol.org/v1"],
  "did": "<DID>",
  "name": "<human-readable name>",
  "version": "<semver>",
  "capabilities": ["<capability>", ...],
  "requiredCredentials": ["<CredentialType>", ...],
  "offeredCredentials": ["<CredentialType>", ...],
  "trustRoots": ["<DID>", ...],
  "maxDelegationDepth": <integer>,
  "protocolVersions": ["1.0"],
  "endpoints": {
    "handshake": "<url>",
    "reputation": "<url>"
  },
  "minPeerReputation": <0-100>,
  "contentSafetyCompliant": <boolean>
}
```

### 6.2 Compatibility Check

Two passports are compatible for handshake if:

1. They share at least one common `protocolVersions` entry
2. The initiator's `offeredCredentials` satisfies the responder's `requiredCredentials`
3. The responder's `offeredCredentials` satisfies the initiator's `requiredCredentials`

---

## 7. Audit Log

### 7.1 Format

Append-only JSON Lines file. Each line is a JSON object:

```json
{
  "timestamp": "<ISO 8601>",
  "eventType": "<event type>",
  "actorDid": "<DID>",
  "targetDid": "<DID | undefined>",
  "intentId": "<intent ID | undefined>",
  "result": "success" | "failure",
  "reason": "<string | undefined>",
  "metadata": { ... },
  "prevHash": "<64 hex chars SHA-256>",
  "entryHash": "<64 hex chars SHA-256>"
}
```

### 7.2 Event Types

| Event Type | Description |
|---|---|
| `identity_created` | New agent identity generated |
| `handshake_init` | Handshake initiated |
| `handshake_complete` | Handshake succeeded |
| `handshake_failed` | Handshake failed |
| `vc_issued` | VC issued |
| `vc_verified` | VC verified |
| `vc_revoked` | VC revoked |
| `intent_created` | Intent envelope created |
| `intent_validated` | Intent validated by a peer |
| `intent_rejected` | Intent rejected |
| `session_created` | Session established |
| `session_terminated` | Session ended |
| `reputation_vouch` | Positive vouch recorded |
| `reputation_negative` | Negative vouch recorded |
| `emergency_revoke` | Emergency kill switch activated |
| `key_rotated` | Key rotation completed |
| `key_backup_created` | Key split into shares |
| `key_recovered` | Key reconstructed from shares |

### 7.3 Hash Chain Integrity

- The first entry's `prevHash` MUST be `"0000...0000"` (64 zero characters)
- Each subsequent entry's `prevHash` MUST equal the previous entry's `entryHash`
- `entryHash` = SHA-256 of the JSON-serialized entry (excluding `entryHash` itself), with keys sorted alphabetically

### 7.4 Integrity Verification

Walk entries sequentially. The chain is broken if:
1. Any entry's `prevHash` doesn't match the previous entry's `entryHash`
2. Any entry's `entryHash` doesn't match the recomputed hash of its contents

---

## 8. Reputation System

### 8.1 Scoring Formula

```
score = 50 + Σ(polarity × vouch_weight × time_decay × verified_factor) × 10
```

- **Base score:** 50 (neutral)
- **Range:** clamped to [0, 100]
- **Polarity:** +1 for positive, -1 for negative
- **Negative weight multiplier:** 2× (safety bias)
- **Time decay:** exponential with 90-day half-life: `0.5^(age_ms / half_life_ms)`
- **Verified factor:** `min(weight, 0.3)` for unverified vouchers; `weight` for verified

### 8.2 Vouch Format

```json
{
  "voucherDid": "<DID>",
  "subjectDid": "<DID>",
  "polarity": "positive" | "negative",
  "weight": <0.0 - 1.0>,
  "voucherVerified": <boolean>,
  "reason": "<NegativeReason | undefined>",
  "timestamp": "<ISO 8601>"
}
```

### 8.3 Negative Reasons

| Reason | Description |
|---|---|
| `timeout` | Agent failed to respond in time |
| `incorrect_output` | Agent produced wrong results |
| `scope_violation` | Agent exceeded authorized scope |
| `content_safety` | Agent produced unsafe content |
| `unresponsive` | Agent became unresponsive |
| `data_leak` | Agent leaked sensitive data |

### 8.4 Rate Limits

| Rule | Limit |
|---|---|
| Self-vouch | Prohibited |
| Per-peer | 1 vouch per 24 hours |
| Burst detection | >10 vouches/hour suppresses voucher |

### 8.5 Quarantine

An agent is quarantined when **3 or more independent verified agents** issue negative vouches. Quarantined agents SHOULD be refused handshakes by compliant implementations.

---

## 9. Security Considerations

### 9.1 Key Compromise

If an agent's private key is compromised:
1. Immediately issue a revocation (Phase 2 feature)
2. Rotate to a new keypair
3. Re-issue VCs from the new identity
4. All VCs signed by the compromised key become untrusted

### 9.2 Replay Attacks

- Intent nonces MUST be tracked and rejected on reuse
- Handshake nonces provide session uniqueness
- VCs have expiration dates limiting replay windows

### 9.3 Clock Skew

All time-sensitive operations allow ±30 seconds of tolerance. Implementations in high-precision environments MAY tighten this window.

### 9.4 Sybil Resistance

- Unverified agents have capped reputation influence (0.3)
- Quarantine requires independent verified sources
- Burst detection suppresses rapid vouch flooding

---

## 10. Conformance

An implementation is AID v0.1 conformant if it:

1. Uses `did:key` with Ed25519 for identity
2. Issues and verifies VCs per §3
3. Implements the 5-step handshake per §4
4. Supports Intent Envelope creation and validation per §5
5. Maintains an append-only audit log with hash-chain integrity per §7
6. Enforces scope narrowing in delegation chains per §3.5

---

## Appendix A: Wire Format Summary

| Message | Direction | Required Fields |
|---|---|---|
| `handshake_init` | A → B | `protocolVersion`, `initiatorDid`, `nonce`, `timestamp`, `passport` |
| `handshake_response` | B → A | `protocolVersion`, `responderDid`, `nonce`, `timestamp`, `passport` |
| `vc_exchange` | Both | `senderDid`, `credentials[]`, `proofOfLiveness` |
| `session_established` | A → B | `sessionId`, `negotiatedVersion`, `initiatorDid`, `responderDid`, `createdAt`, `expiresAt` |
| `handshake_error` | Either | `code`, `message` |
| `intent_envelope` | Agent → Peer | `intentId`, `version`, `action`, `scope[]`, `principalDid`, `agentDid`, `delegationChain[]`, `expiry`, `nonce`, `signature` |

## Appendix B: Cryptographic Parameters

| Parameter | Value |
|---|---|
| Signing algorithm | Ed25519 |
| Hash algorithm | SHA-256 |
| Key size | 256 bits (32 bytes) |
| Signature size | 512 bits (64 bytes) |
| Nonce size | 256 bits (32 bytes) |
| Session ID size | 128 bits (16 bytes) |
| Clock tolerance | ±30,000 ms |
| Secret sharing field | GF(2^8), polynomial x^8 + x^4 + x^3 + x + 1 |
| Default share scheme | 3-of-5 |
