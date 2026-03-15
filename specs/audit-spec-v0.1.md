# Audit Log Specification v0.1

**Status:** Draft  
**Authors:** Project Sentinel Contributors  
**Date:** March 2026  
**License:** Apache 2.0  

---

## Abstract

This document specifies the append-only, hash-chain integrity audit log used by all Sentinel components. The audit log provides tamper-evident recording of all trust-related events.

---

## 1. Overview

Every trust decision, identity operation, credential event, and safety check is recorded in an append-only log. Each entry contains a SHA-256 hash of the previous entry, forming a hash chain that detects any tampering.

## 2. Entry Format

Each audit entry is stored as a single JSON line (JSONL format):

| Field | Type | Required | Description |
|---|---|---|---|
| `timestamp` | `string` | Yes | ISO 8601 timestamp |
| `eventType` | `AuditEventType` | Yes | Type of event (see §3) |
| `actorDid` | `string` | No | DID of the agent performing the action |
| `targetDid` | `string` | No | DID of the agent being acted upon |
| `result` | `string` | Yes | `"success"` or `"failure"` |
| `reason` | `string` | No | Human-readable explanation |
| `metadata` | `object` | No | Additional structured data |
| `prevHash` | `string` | Yes | SHA-256 hex hash of the previous entry |

### 2.1 Genesis Entry

The first entry in any log uses the genesis hash:

```
prevHash = "0000000000000000000000000000000000000000000000000000000000000000"
```

## 3. Event Types

| Event Type | Description |
|---|---|
| `identity_created` | New DID generated |
| `vc_issued` | Verifiable Credential issued |
| `vc_verified` | VC verification attempted |
| `vc_revoked` | VC revoked |
| `handshake_initiated` | Handshake started |
| `handshake_completed` | Handshake succeeded |
| `handshake_failed` | Handshake failed |
| `intent_declared` | Intent envelope created |
| `intent_verified` | Intent verification attempted |
| `reputation_vouch` | Reputation vouch submitted |
| `reputation_quarantine` | Agent quarantined |
| `key_rotated` | Key pair rotated |
| `kill_switch_activated` | Emergency kill switch |
| `delegation_checked` | Delegation chain verified |
| `attestation_created` | Code attestation created |
| `attestation_verified` | Code attestation verified |
| `stepup_challenged` | Step-up auth challenge issued |
| `stepup_completed` | Step-up auth completed |
| `safety_violation` | Content safety violation detected |
| `tool_call_verified` | MCP tool call verified |

## 4. Hash Chain

### 4.1 Hash Computation

For entry $n$:

$$h_n = \text{SHA-256}(\text{JSON.stringify}(\text{sortDeep}(e_n)))$$

Where `sortDeep()` recursively sorts all object keys to ensure deterministic serialization.

### 4.2 Chain Linking

Each entry stores the hash of the _serialized_ previous entry:

$$e_n.\text{prevHash} = h_{n-1}$$

### 4.3 Integrity Verification

To verify the chain:
1. Read all entries sequentially
2. For each entry $n > 0$: compute $h_{n-1}$ and compare with $e_n.\text{prevHash}$
3. If any mismatch: report the first invalid entry index

## 5. Storage

### 5.1 File Format

Entries are stored in JSONL (JSON Lines) format — one JSON object per line, newline-separated.

### 5.2 File Path

The default log path is configurable via `AuditLogConfig.logPath`. If the directory does not exist, it is created automatically.

## 6. Security Considerations

- The log MUST be append-only; entries MUST NOT be modified or deleted
- `sortDeep()` canonicalization prevents hash mismatches from key ordering differences
- In a production deployment, the log SHOULD be replicated to multiple storage backends
- The hash chain detects tampering but does not prevent it — combine with signed entries for non-repudiation
- Metadata fields SHOULD NOT contain secrets or PII
