# Revocation Protocol Specification v0.1

**Status:** Draft  
**Authors:** Project Sentinel Contributors  
**Date:** March 2026  
**License:** Apache 2.0  

---

## Abstract

This document specifies the revocation protocol for Sentinel agents, covering credential revocation, DID revocation, key rotation, emergency kill switch, and signed revocation lists.

---

## 1. Overview

The revocation subsystem provides mechanisms to:

- Invalidate individual Verifiable Credentials
- Revoke entire agent identities (DIDs)
- Rotate compromised keys with dual-signature proof
- Execute emergency kill switches for immediate termination
- Publish signed revocation lists for offline verification

## 2. VC Revocation

### 2.1 Revocation Entry

| Field | Type | Description |
|---|---|---|
| `credentialId` | `string` | ID of the revoked VC |
| `issuerDid` | `string` | DID of the issuer who revoked |
| `reason` | `RevocationReason` | Reason for revocation |
| `detail` | `string` | Human-readable explanation |
| `timestamp` | `string` | ISO 8601 timestamp |
| `signature` | `string` | Ed25519 signature by the issuer |

### 2.2 Revocation Reasons

| Reason | Description |
|---|---|
| `key_compromise` | Private key suspected compromised |
| `privilege_escalation` | Agent exceeded authorized scope |
| `policy_violation` | Agent violated operational policy |
| `expired` | Credential expired (explicit early revocation) |
| `superseded` | Replaced by a newer credential |
| `manual` | Administrative revocation |

### 2.3 Verification

To check if a VC is revoked:
1. Look up `credentialId` in the revocation registry
2. If found, the VC is revoked
3. The revocation signature SHOULD be verified against the issuer's public key

## 3. DID Revocation

A DID can be fully revoked, making the agent untrusted for all operations:

| Field | Type | Description |
|---|---|---|
| `did` | `string` | The revoked DID |
| `revokedBy` | `string` | DID of the revoker |
| `reason` | `string` | Explanation |
| `timestamp` | `string` | ISO 8601 timestamp |

### 3.1 Trust Check

`isTrusted(did)` returns:
- `{ trusted: true }` if the DID has no revocation records
- `{ trusted: false, reason: "..." }` if the DID is revoked or kill-switched

## 4. Key Rotation

When a key is compromised or scheduled for rotation:

### 4.1 Key Rotation Notice

| Field | Type | Description |
|---|---|---|
| `oldDid` | `string` | Previous DID |
| `newDid` | `string` | New DID |
| `oldKeySignature` | `string` | Signature by the old key proving ownership |
| `newKeySignature` | `string` | Signature by the new key proving ownership |
| `timestamp` | `string` | ISO 8601 timestamp |

### 4.2 Dual-Signature Requirement

Both the old and new keys MUST sign the rotation notice. This proves:
- The old key holder authorized the rotation
- The new key holder accepts the new identity

### 4.3 DID Resolution

After rotation, `resolveCurrentDid(oldDid)` follows the rotation chain to return the latest DID. This supports chained rotations: A → B → C resolves A to C.

## 5. Emergency Kill Switch

For immediate, unconditional termination of an agent:

### 5.1 Kill Switch Event

| Field | Type | Description |
|---|---|---|
| `targetDid` | `string` | DID being terminated |
| `issuedBy` | `string` | DID of the principal |
| `reason` | `string` | Justification |
| `cascade` | `boolean` | Whether to revoke delegates too |
| `timestamp` | `string` | ISO 8601 timestamp |
| `signature` | `string` | Ed25519 signature by the issuer |

### 5.2 Cascade Behavior

When `cascade: true`, all VCs issued by the target DID are also revoked. This prevents a compromised agent's delegates from continuing to operate.

## 6. Signed Revocation Lists

### 6.1 List Format

| Field | Type | Description |
|---|---|---|
| `version` | `number` | Monotonically increasing version |
| `issuerDid` | `string` | DID of the list publisher |
| `entries` | `RevocationEntry[]` | All revoked credentials |
| `publishedAt` | `string` | ISO 8601 timestamp |
| `signature` | `string` | Ed25519 signature over the list |

### 6.2 Distribution

Revocation lists SHOULD be:
- Published periodically (e.g., every 5 minutes)
- Cached by offline agents for degraded-mode verification
- Distributed via the trust registry (when available)

## 7. Audit Integration

All revocation events MUST be logged:

| Event | When |
|---|---|
| `vc_revoked` | Credential revoked |
| `did_revoked` | DID revoked |
| `key_rotated` | Key pair rotated |
| `kill_switch_activated` | Kill switch executed |

## 8. Security Considerations

- Only the VC issuer or a higher-privilege principal SHOULD be able to revoke
- Kill switch access SHOULD be restricted to human principals
- Key rotation MUST require dual signatures to prevent unauthorized takeover
- Revocation lists MUST be signed to prevent forgery
- Revocation is irreversible — there is no "un-revoke" operation
