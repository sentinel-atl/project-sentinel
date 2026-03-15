# Sentinel Trust Protocol (STP) — v1.0 Specification

**Status**: Draft  
**Version**: 1.0.0  
**Date**: 2026-03-15  
**Authors**: Project Sentinel Contributors  
**License**: Apache-2.0  

---

## Abstract

The Sentinel Trust Protocol (STP) defines a language-agnostic, HTTP-based protocol for establishing identity, issuing credentials, tracking reputation, and auditing actions of autonomous AI agents. STP is designed to be the "OAuth for AI agents" — any language or framework can implement the protocol and interoperate with other STP-compliant systems.

## 1. Introduction

### 1.1 Problem

AI agents today operate without standardized identity, authorization, or reputation. Unlike human users who have OAuth 2.0 and OpenID Connect, agents have no protocol for proving who they are, what they're allowed to do, or how trustworthy they are.

### 1.2 Goals

- **Language-agnostic**: Any implementation MUST be able to interoperate via HTTP + JSON
- **Self-sovereign**: Agent identities MUST NOT require a central registry
- **Verifiable**: All claims MUST be cryptographically signed and independently verifiable
- **Auditable**: All trust decisions MUST be logged in a tamper-evident manner
- **Composable**: Implementations MAY support any subset of STP capabilities

### 1.3 Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).

---

## 2. Discovery

### 2.1 Well-Known Configuration

An STP-compliant server MUST expose a configuration document at:

```
GET /.well-known/sentinel-configuration
```

**Response** (`application/json`):

```json
{
  "issuer": "https://trust.example.com",
  "protocol_version": "STP/1.0",
  "server_did": "did:key:z6Mk...",
  "endpoints": {
    "identity": "/v1/identity",
    "credentials_issue": "/v1/credentials",
    "credentials_verify": "/v1/credentials/verify",
    "credentials_revoke": "/v1/credentials/revoke",
    "reputation_query": "/v1/reputation",
    "reputation_vouch": "/v1/reputation/vouch",
    "handshake": "/v1/handshake",
    "intent_create": "/v1/intents",
    "intent_validate": "/v1/intents/validate",
    "revocation_status": "/v1/revocation/status",
    "revocation_list": "/v1/revocation/list",
    "safety_check": "/v1/safety/check",
    "audit": "/v1/audit",
    "gateway": "/v1/gateway/verify"
  },
  "supported_credential_types": [
    "AgentAuthorizationCredential",
    "DelegationCredential",
    "ComplianceCredential",
    "ReputationCredential",
    "NegativeReputationCredential",
    "CodeAttestationCredential"
  ],
  "supported_did_methods": ["did:key"],
  "cryptographic_suites": ["Ed25519Signature2020"],
  "reputation_algorithm": "sentinel-weighted-decay-v1",
  "safety_categories": [
    "prompt_injection", "jailbreak", "pii_exposure",
    "harmful_content", "data_exfiltration"
  ],
  "capabilities": [
    "identity", "credentials", "reputation", "handshake",
    "intent", "revocation", "safety", "audit", "gateway"
  ]
}
```

Implementations MAY omit endpoints for capabilities they do not support. The `capabilities` array MUST accurately reflect which features are available.

### 2.2 Capability Levels

An STP server MUST declare which `capabilities` it supports. Implementations are categorized:

| Level | Capabilities Required | Use Case |
|-------|----------------------|----------|
| **STP-Lite** | `identity`, `credentials` | Basic agent auth |
| **STP-Standard** | + `reputation`, `revocation`, `audit` | Production trust |
| **STP-Full** | + `handshake`, `intent`, `safety`, `gateway` | Zero-trust agent networks |

---

## 3. Identity

### 3.1 DID Format

STP uses the `did:key` method with Ed25519 keys:

```
did:key:z6Mk<base58btc(0xed01 || public_key_32_bytes)>
```

- **Key type**: Ed25519 (RFC 8032)
- **Multicodec prefix**: `0xed01`
- **Encoding**: base58btc with `z` prefix
- **Key size**: 256 bits (32 bytes)

#### 3.1.1 Create Identity

```
POST /v1/identity
Content-Type: application/json

{
  "label": "my-travel-agent"
}
```

**Response** (`201 Created`):

```json
{
  "did": "did:key:z6Mk...",
  "keyId": "my-travel-agent",
  "publicKey": "<base64url-encoded 32-byte Ed25519 public key>",
  "createdAt": "2026-03-15T10:00:00.000Z"
}
```

The server MUST generate the keypair server-side and store it securely. Clients that manage their own keys SHOULD use the SDK directly.

#### 3.1.2 Resolve DID

```
GET /v1/identity/{did}
```

**Response** (`200 OK`):

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
  "id": "did:key:z6Mk...",
  "verificationMethod": [{
    "id": "did:key:z6Mk...#key-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:key:z6Mk...",
    "publicKeyMultibase": "z6Mk..."
  }],
  "authentication": ["did:key:z6Mk...#key-1"],
  "assertionMethod": ["did:key:z6Mk...#key-1"]
}
```

Any implementation MUST be able to resolve a `did:key` DID locally by decoding the multicodec-prefixed public key from the DID string. No network request is required.

---

## 4. Verifiable Credentials

### 4.1 Credential Format

STP credentials follow the [W3C Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/):

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://sentinel-protocol.org/v1"
  ],
  "id": "urn:uuid:<uuid>",
  "type": ["VerifiableCredential", "<CredentialType>"],
  "issuer": "<issuer-did>",
  "issuanceDate": "<ISO 8601>",
  "expirationDate": "<ISO 8601>",
  "credentialSubject": {
    "id": "<subject-did>",
    "scope": ["<resource>:<action>", ...],
    "maxDelegationDepth": 3,
    "sensitivityLevel": "medium"
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "<ISO 8601>",
    "verificationMethod": "<issuer-did>#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "<base64url(Ed25519_signature)>"
  }
}
```

### 4.2 Credential Types

| Type | Purpose | Required Subject Fields |
|------|---------|----------------------|
| `AgentAuthorizationCredential` | Grant agent permissions | `scope` |
| `DelegationCredential` | Delegate to sub-agent | `scope`, `maxDelegationDepth` |
| `ComplianceCredential` | Attest regulatory compliance | `scope` |
| `ReputationCredential` | Positive reputation attestation | — |
| `NegativeReputationCredential` | Negative reputation attestation | `reason` |
| `CodeAttestationCredential` | Code integrity proof | `codeHash` |

### 4.3 Signature Algorithm

1. Construct the **signing payload**: `JSON.stringify(vc_without_proof)` using deterministic JSON serialization (keys sorted lexicographically at each level)
2. Compute `SHA-256(signing_payload)` to get a 32-byte digest
3. Sign the digest with the issuer's Ed25519 private key
4. Encode the 64-byte signature as base64url (RFC 4648 §5, no padding)

### 4.4 Scope Format

Scopes follow the `<resource>:<action>` convention:

```
flights:book
email:send
files:read
admin:*
*
```

The wildcard `*` matches all resources or all actions. An empty scope array grants no permissions.

### 4.5 Scope Narrowing Rule

When issuing a `DelegationCredential`, the child scope MUST be a strict subset of the parent scope. Implementations MUST enforce:

```
∀ childScope ∈ child.scope: ∃ parentScope ∈ parent.scope where parentScope covers childScope
```

A scope `A` covers scope `B` if:
- `A === '*'` (universal), OR
- `A === B` (exact match), OR
- `A === '<resource>:*'` and `B` starts with `<resource>:`, OR
- `A` starts with `B + ':'` (A is more specific — NOT covered)

### 4.6 Issue Credential

```
POST /v1/credentials
Content-Type: application/json
Authorization: Bearer <STP-Token>

{
  "type": "AgentAuthorizationCredential",
  "subjectDid": "did:key:z6Mk...",
  "scope": ["flights:book", "flights:search"],
  "maxDelegationDepth": 2,
  "sensitivityLevel": "medium",
  "expiresInMs": 3600000
}
```

**Response** (`201 Created`): The full `VerifiableCredential` JSON.

### 4.7 Verify Credential

```
POST /v1/credentials/verify
Content-Type: application/json

{
  "credential": { ... }
}
```

**Response** (`200 OK`):

```json
{
  "valid": true,
  "checks": {
    "signature": true,
    "expiry": true,
    "issuerResolvable": true,
    "revocation": true,
    "scopeNarrowing": true
  }
}
```

An implementation MUST verify ALL of: signature validity, non-expiry (with ±30s clock tolerance), issuer DID resolvability, and non-revocation.

---

## 5. Authentication

### 5.1 STP Token (Agent Trust Token)

STP defines a standard token format for authenticating HTTP requests. An **STP Token** is a compact, URL-safe string:

```
STP.<header-base64url>.<payload-base64url>.<signature-base64url>
```

This is structurally similar to JWT but uses Ed25519 and carries agent-specific claims.

#### 5.1.1 Header

```json
{
  "alg": "EdDSA",
  "typ": "STP+jwt",
  "kid": "<did>#key-1"
}
```

#### 5.1.2 Payload (Claims)

```json
{
  "iss": "<agent-did>",
  "sub": "<target-server-did or resource>",
  "aud": "<server-url>",
  "iat": 1742036400,
  "exp": 1742040000,
  "nonce": "<64-hex-chars>",
  "scope": ["flights:book"],
  "vcIds": ["urn:uuid:..."],
  "intentId": "<intent-id>",
  "reputation": 75
}
```

| Claim | Required | Description |
|-------|----------|-------------|
| `iss` | REQUIRED | Agent's DID |
| `sub` | RECOMMENDED | Target server DID or resource identifier |
| `aud` | RECOMMENDED | Server URL this token is intended for |
| `iat` | REQUIRED | Issued-at timestamp (Unix seconds) |
| `exp` | REQUIRED | Expiration timestamp (Unix seconds) |
| `nonce` | REQUIRED | 32-byte random hex string (replay protection) |
| `scope` | OPTIONAL | Requested scopes |
| `vcIds` | OPTIONAL | VC IDs backing the claimed scopes |
| `intentId` | OPTIONAL | Associated intent envelope ID |
| `reputation` | OPTIONAL | Self-reported reputation (server MUST re-verify) |

#### 5.1.3 Signature

```
Ed25519_Sign(private_key, base64url(header) + "." + base64url(payload))
```

The signature is over the concatenation of the base64url-encoded header and payload, separated by `.`.

#### 5.1.4 Usage

```http
POST /v1/credentials
Authorization: STP <token>
Content-Type: application/json
```

Servers MUST:
1. Decode the header and extract the `kid` (DID + key fragment)
2. Resolve the DID to extract the public key
3. Verify the Ed25519 signature
4. Check `exp` > now (with ±30s tolerance)
5. Check `nonce` is unique (not seen before within the token's lifetime)
6. Optionally verify `aud` matches the server's URL

---

## 6. Reputation

### 6.1 Reputation Score

A reputation score represents the trustworthiness of an agent as assessed by its peers:

```json
{
  "did": "did:key:z6Mk...",
  "score": 72.5,
  "totalVouches": 15,
  "positiveVouches": 12,
  "negativeVouches": 3,
  "isQuarantined": false,
  "quarantineReason": null,
  "lastUpdated": "2026-03-15T10:00:00.000Z",
  "source": "live"
}
```

- `score`: Float in range `[0, 100]`. Default for unknown agents: `50`.
- `source`: `"live"` (real-time), `"cached"` (from local cache), or `"unavailable"`
- `isQuarantined`: `true` if the agent has been flagged for repeated negative behavior

### 6.2 Scoring Algorithm (`sentinel-weighted-decay-v1`)

The canonical reputation scoring algorithm:

```
score = clamp(50 + Σ(contribution_i) × 10, 0, 100)
```

Where for each vouch `i`:

```
polarity_factor = polarity === 'positive' ? 1 : -1
negative_multiplier = polarity === 'negative' ? 2 : 1
verified_factor = voucherVerified ? 1.0 : 0.3
time_decay = 2^(-(now - timestamp) / HALF_LIFE_90_DAYS)
contribution_i = polarity_factor × weight × negative_multiplier × verified_factor × time_decay
```

**Constants**:

| Constant | Value | Description |
|----------|-------|-------------|
| `NEUTRAL_SCORE` | 50 | Starting score for unknown agents |
| `HALF_LIFE_MS` | 7,776,000,000 | 90 days in milliseconds |
| `NEGATIVE_WEIGHT_MULTIPLIER` | 2 | Safety bias: negatives count double |
| `UNVERIFIED_CAP` | 0.3 | Max influence from unverified agents |
| `QUARANTINE_THRESHOLD` | 3 | Verified negatives before quarantine |
| `MAX_VOUCHES_PER_PEER_PER_DAY` | 1 | Rate limit per peer pair |
| `BURST_THRESHOLD_PER_HOUR` | 10 | Anti-Sybil burst detection |

**Quarantine rule**: If an agent receives ≥3 negative vouches from distinct verified agents, it MUST be quarantined. Quarantined agents SHOULD be denied service.

### 6.3 Query Reputation

```
GET /v1/reputation/{did}
```

**Response** (`200 OK`): The `ReputationScore` JSON.

### 6.4 Submit Vouch

```
POST /v1/reputation/vouch
Authorization: STP <token>
Content-Type: application/json

{
  "subjectDid": "did:key:z6Mk...",
  "polarity": "positive",
  "weight": 0.8,
  "reason": null
}
```

**Response** (`201 Created`):

```json
{
  "accepted": true,
  "newScore": 73.2
}
```

**Rate limits**: Servers MUST enforce:
- Self-vouching (`iss === subjectDid`) MUST be rejected
- Max 1 vouch per peer pair per 24 hours
- Max 10 vouches per hour from any single agent

**Negative vouch reasons** (for `polarity: "negative"`):

```
timeout | incorrect_output | scope_violation | content_safety | unresponsive | data_leak
```

### 6.5 Reputation Federation

STP servers MAY federate reputation data. When querying reputation, a server:

1. MUST check its local vouch store first
2. MAY query other known STP servers via their `reputation_query` endpoint
3. MUST merge remote scores using the CRDT Last-Writer-Wins strategy (latest timestamp wins per vouch)
4. MUST mark federated scores with `source: "federated"` in the response

---

## 7. Intent Envelopes

### 7.1 Format

An intent envelope cryptographically declares what an agent intends to do and who authorized it:

```json
{
  "intentId": "<time-ordered-uuid>",
  "version": "1.0",
  "action": "book_flight",
  "scope": ["flights:book"],
  "principalDid": "<human-authorizer-did>",
  "agentDid": "<executing-agent-did>",
  "delegationChain": ["urn:uuid:vc1", "urn:uuid:vc2"],
  "expiry": "2026-03-15T10:05:00.000Z",
  "nonce": "<64-hex-chars = 32-random-bytes>",
  "signature": "<base64url(Ed25519_signature)>"
}
```

### 7.2 Create Intent

```
POST /v1/intents
Authorization: STP <token>
Content-Type: application/json

{
  "action": "book_flight",
  "scope": ["flights:book"],
  "principalDid": "did:key:z6Mk...",
  "delegationChain": ["urn:uuid:..."],
  "expiresInMs": 300000
}
```

### 7.3 Validate Intent

```
POST /v1/intents/validate
Content-Type: application/json

{
  "intent": { ... }
}
```

**Response** (`200 OK`):

```json
{
  "valid": true,
  "checks": {
    "signature": true,
    "expiry": true,
    "nonce": true,
    "scopeValid": true
  }
}
```

Validation MUST check:
1. **Signature**: Valid Ed25519 signature by `agentDid`
2. **Expiry**: `expiry > now` (with ±30s tolerance)
3. **Nonce**: Not previously seen (replay protection)
4. **Scope**: All requested scopes are valid and within the agent's authorized scope

Default expiry: 5 minutes from creation.

---

## 8. Handshake Protocol

### 8.1 Overview

STP defines a 5-step mutual verification handshake:

```
Initiator                             Responder
    |                                     |
    |-- 1. HandshakeInit ---------------→ |
    |                                     |
    | ←-- 2. HandshakeResponse ---------- |
    |                                     |
    |-- 3. VCExchange (+ liveness) ----→  |
    |                                     |
    | ←-- 4. VCExchange (+ liveness) ---  |
    |                                     |
    |-- 5. SessionEstablished ----------→ |
    |                                     |
```

### 8.2 Messages

#### Step 1: Init
```json
{
  "type": "handshake-init",
  "version": "STP/1.0",
  "initiatorDid": "<did>",
  "initiatorPassport": { ... },
  "nonce": "<64-hex>",
  "timestamp": "<ISO 8601>"
}
```

#### Step 2: Response
```json
{
  "type": "handshake-response",
  "version": "STP/1.0",
  "responderDid": "<did>",
  "responderPassport": { ... },
  "initiatorNonce": "<echo>",
  "responderNonce": "<64-hex>",
  "accepted": true,
  "timestamp": "<ISO 8601>"
}
```

#### Steps 3-4: VC Exchange
```json
{
  "type": "vc-exchange",
  "senderDid": "<did>",
  "credentials": [ ... ],
  "nonceProof": "<base64url(sign(peer_nonce))>",
  "timestamp": "<ISO 8601>"
}
```

The `nonceProof` is the Ed25519 signature of the peer's nonce, proving liveness.

#### Step 5: Session Established
```json
{
  "type": "session-established",
  "sessionId": "<128-bit-hex>",
  "initiatorDid": "<did>",
  "responderDid": "<did>",
  "establishedAt": "<ISO 8601>",
  "expiresAt": "<ISO 8601>"
}
```

### 8.3 HTTP Endpoint

```
POST /v1/handshake
Content-Type: application/json

{
  "step": 1,
  "message": { ... }
}
```

The server responds with the next step's message. The handshake MUST complete within 30 seconds.

### 8.4 Rate Limiting

- Max 10 handshake initiations per DID per minute
- Circuit breaker: After 5 consecutive failures from a DID, block for 60 seconds

---

## 9. Revocation

### 9.1 Check Revocation Status

```
GET /v1/revocation/status/{did}
```

**Response**:

```json
{
  "did": "did:key:z6Mk...",
  "trusted": true,
  "revokedCredentials": [],
  "didRevoked": false
}
```

### 9.2 Revoke Credential

```
POST /v1/credentials/revoke
Authorization: STP <token>
Content-Type: application/json

{
  "credentialId": "urn:uuid:...",
  "reason": "key_compromise"
}
```

**Revocation reasons**: `key_compromise`, `credential_expired_early`, `policy_violation`, `scope_violation`, `agent_decommissioned`, `emergency`, `key_rotation`, `manual`

### 9.3 Signed Revocation List

Servers MUST publish a signed revocation list:

```
GET /v1/revocation/list
```

**Response**:

```json
{
  "version": 1,
  "issuerDid": "<server-did>",
  "entries": [
    {
      "credentialId": "urn:uuid:...",
      "revokedAt": "<ISO 8601>",
      "reason": "key_compromise"
    }
  ],
  "signature": "<base64url(Ed25519_sign(canonical(entries)))>"
}
```

Other STP servers SHOULD periodically fetch and cache revocation lists from peers.

### 9.4 Kill Switch

```
POST /v1/revocation/kill-switch
Authorization: STP <token>
Content-Type: application/json

{
  "targetDid": "did:key:z6Mk...",
  "reason": "Compromised agent",
  "cascade": true,
  "downstreamDids": ["did:key:z6Mk..."]
}
```

Kill switch MUST:
1. Immediately revoke the target DID
2. Revoke all VCs issued TO the target
3. If `cascade: true`, revoke all downstream delegatees
4. Log to audit trail

---

## 10. Gateway Verification

### 10.1 Verify Tool Call

The STP gateway endpoint provides a single unified verification for MCP tool calls:

```
POST /v1/gateway/verify
Authorization: STP <token>
Content-Type: application/json

{
  "toolName": "search_flights",
  "callerDid": "did:key:z6Mk...",
  "credentials": [ ... ],
  "intent": { ... },
  "payload": "user wants to book a flight to Paris"
}
```

**Response** (`200 OK`):

```json
{
  "allowed": true,
  "checks": {
    "identity": true,
    "credentials": true,
    "reputation": true,
    "intent": true,
    "scope": true,
    "revocation": true,
    "attestation": true,
    "safety": true
  },
  "callerReputation": { ... },
  "gatewayLatencyMs": 12
}
```

---

## 11. Audit

### 11.1 Log Format

Audit entries form a tamper-evident hash chain:

```json
{
  "timestamp": "<ISO 8601>",
  "eventType": "<event-type>",
  "actorDid": "<did>",
  "targetDid": "<did>",
  "result": "success",
  "reason": "...",
  "metadata": { ... },
  "prevHash": "<sha256-hex-of-previous-entry>"
}
```

Genesis entry uses `prevHash: "0000...0000"` (64 zeros).

### 11.2 Event Types

```
identity_created    | handshake_init    | handshake_complete  | handshake_failed
vc_issued          | vc_verified       | vc_revoked
intent_created     | intent_validated  | intent_rejected
session_created    | session_terminated
reputation_vouch   | emergency_revoke  | key_rotated
kill_switch_activated | attestation_verified
```

### 11.3 Verify Integrity

```
POST /v1/audit/verify
```

**Response**:

```json
{
  "valid": true,
  "totalEntries": 1542,
  "verified": true
}
```

---

## 12. Content Safety

### 12.1 Check Content

```
POST /v1/safety/check
Content-Type: application/json

{
  "text": "..."
}
```

**Response**:

```json
{
  "safe": true,
  "blocked": false,
  "violations": [],
  "totalLatencyMs": 3
}
```

### 12.2 Safety Categories

| Category | Description |
|----------|-------------|
| `prompt_injection` | Attempts to override system instructions |
| `jailbreak` | Attempts to bypass safety guardrails |
| `pii_exposure` | Social security numbers, emails, phone numbers |
| `harmful_content` | Violence, hate speech, self-harm |
| `data_exfiltration` | Unauthorized data extraction patterns |

### 12.3 Severity Levels

`low` → `medium` → `high` → `critical`

Servers SHOULD block at `high` severity by default. The threshold is configurable.

---

## 13. Error Format

All error responses MUST follow this format:

```json
{
  "error": {
    "code": "REPUTATION_QUARANTINED",
    "message": "Agent is quarantined due to repeated policy violations",
    "details": {
      "did": "did:key:z6Mk...",
      "quarantineReason": "3 verified negative vouches"
    }
  }
}
```

### 13.1 Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_DID` | 400 | DID format is invalid |
| `DID_NOT_FOUND` | 404 | DID cannot be resolved |
| `INVALID_SIGNATURE` | 401 | Signature verification failed |
| `TOKEN_EXPIRED` | 401 | STP token has expired |
| `NONCE_REUSE` | 401 | Nonce was already used |
| `CREDENTIAL_EXPIRED` | 401 | Presented VC has expired |
| `CREDENTIAL_REVOKED` | 403 | Presented VC was revoked |
| `DID_REVOKED` | 403 | Agent's DID was revoked |
| `INSUFFICIENT_SCOPE` | 403 | Missing required scope |
| `INSUFFICIENT_REPUTATION` | 403 | Score below threshold |
| `REPUTATION_QUARANTINED` | 403 | Agent is quarantined |
| `RATE_LIMITED` | 429 | Too many requests |
| `SAFETY_VIOLATION` | 422 | Content safety violation |
| `INTENT_REQUIRED` | 400 | Intent envelope required but not provided |
| `INTENT_INVALID` | 400 | Intent validation failed |
| `TOOL_BLOCKED` | 403 | Tool is blocked by policy |
| `HANDSHAKE_TIMEOUT` | 408 | Handshake took too long |
| `INTERNAL_ERROR` | 500 | Server error |

---

## 14. Conformance

### 14.1 Levels

| Level | Requirements |
|-------|-------------|
| **STP-Lite** | `.well-known` discovery, DID resolution, VC issue/verify, STP Token auth |
| **STP-Standard** | + Reputation query/vouch, revocation check/list, audit log |
| **STP-Full** | + Handshake, intent create/validate, safety check, gateway verify |

### 14.2 Interoperability Test Suite

Implementations SHOULD pass the STP Conformance Test Suite (published as `@sentinel/conformance`). The test suite verifies:

1. **Discovery**: `/.well-known/sentinel-configuration` returns valid JSON
2. **Identity**: Can resolve any `did:key` DID to a DIDDocument
3. **Credentials**: Can issue, verify, and detect tampered VCs
4. **Token**: Can create and verify STP tokens
5. **Reputation**: Scoring matches reference implementation within ±0.1
6. **Handshake**: Full 5-step handshake completes successfully
7. **Revocation**: Revoked credentials are detected
8. **Audit**: Hash chain integrity is maintained
9. **Safety**: Known prompt injections are detected

---

## 15. Security Considerations

- **Replay attacks**: All tokens and intents include nonces. Servers MUST track nonces within the token/intent lifetime.
- **Clock skew**: All time-based checks MUST allow ±30 seconds of tolerance.
- **Key compromise**: Agents MUST use the kill switch immediately on suspected compromise. STP supports key rotation with dual-signature proof.
- **Sybil attacks**: Reputation rate limiting (1 vouch/peer/day, 10/hour burst cap) and quarantine on 3 verified negatives.
- **Man-in-the-middle**: Handshake nonce proofs bind the exchange to specific key material.
- **Denial of service**: Rate limiting and circuit breakers on all endpoints.

---

## Appendix A: Quick Reference

### HTTP Headers
```
Authorization: STP <token>
Content-Type: application/json
Accept: application/json
```

### Common Flows

**Flow 1: Agent authenticates to a server**
```
1. Agent creates STP token signed with its Ed25519 key
2. Agent sends request with Authorization: STP <token>
3. Server resolves agent DID, verifies token signature
4. Server checks reputation, revocation status
5. Server returns result
```

**Flow 2: Agent-to-agent trust establishment**
```
1. Agents discover each other's STP config via .well-known
2. Agents complete 5-step handshake
3. Agent A issues VC to Agent B (scoped authorization)
4. Agent B creates intent envelope for each action
5. All interactions are audited on both sides
```

**Flow 3: MCP tool call through gateway**
```
1. Client sends tool call to gateway with STP token + VCs
2. Gateway runs 8-step verification pipeline
3. If allowed, gateway forwards to upstream MCP server
4. Gateway checks response safety before returning
5. Outcome recorded in audit log
```
