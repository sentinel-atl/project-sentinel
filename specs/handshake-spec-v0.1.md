# Handshake Protocol Specification v0.1

**Status:** Draft  
**Authors:** Project Sentinel Contributors  
**Date:** March 2026  
**License:** Apache 2.0  

---

## Abstract

This document specifies the zero-trust mutual verification handshake protocol used by Sentinel agents. The protocol establishes a cryptographically-bound session between two agents through a 5-step message exchange.

---

## 1. Overview

Before any data exchange, two agents must complete a handshake that:

1. Verifies both parties hold valid DIDs
2. Exchanges and verifies Verifiable Credentials
3. Establishes a time-bounded session with a shared nonce
4. Supports rate limiting and circuit breaking for DoS protection

## 2. Message Flow

```
Initiator                          Responder
    |                                  |
    |--- HandshakeInit --------------->|   (Step 1: Init with DID + nonce)
    |                                  |
    |<-- HandshakeResponse ------------|   (Step 2: Accept with DID + nonce)
    |                                  |
    |--- VCExchange ------------------>|   (Step 3: Signed VC bundle)
    |                                  |
    |<-- VCExchange -------------------|   (Step 4: Responder's VCs)
    |                                  |
    |--- SessionEstablished ---------->|   (Step 5: Session token)
    |                                  |
```

## 3. Message Types

### 3.1 HandshakeInit

| Field | Type | Description |
|---|---|---|
| `type` | `"handshake_init"` | Message discriminator |
| `version` | `string` | Protocol version (e.g., `"1.0"`) |
| `initiatorDid` | `string` | DID of the initiator |
| `nonce` | `string` | Cryptographic nonce (hex-encoded, 32 bytes) |
| `timestamp` | `string` | ISO 8601 timestamp |
| `credentials` | `VC[]` | Optional initial credential set |

### 3.2 HandshakeResponse

| Field | Type | Description |
|---|---|---|
| `type` | `"handshake_response"` | Message discriminator |
| `responderDid` | `string` | DID of the responder |
| `initiatorNonce` | `string` | Echo of initiator's nonce |
| `responderNonce` | `string` | Responder's own nonce |
| `accepted` | `boolean` | Whether the handshake is accepted |

### 3.3 VCExchange

| Field | Type | Description |
|---|---|---|
| `type` | `"vc_exchange"` | Message discriminator |
| `senderDid` | `string` | DID of the sender |
| `credentials` | `VC[]` | Verifiable Credentials to exchange |
| `signature` | `string` | Ed25519 signature over the exchange payload |

### 3.4 SessionEstablished

| Field | Type | Description |
|---|---|---|
| `type` | `"session_established"` | Message discriminator |
| `sessionId` | `string` | Unique session identifier |
| `initiatorDid` | `string` | DID of the initiator |
| `responderDid` | `string` | DID of the responder |
| `channelBinding` | `string` | SHA-256 of concatenated nonces |
| `establishedAt` | `string` | ISO 8601 timestamp |

## 4. Rate Limiting

A `HandshakeRateLimiter` SHOULD be applied to prevent abuse:

| Parameter | Default | Description |
|---|---|---|
| `maxPerWindow` | 10 | Max handshakes per DID per window |
| `windowMs` | 60000 | Window size in milliseconds |

When the limit is exceeded, the responder MUST reject with reason `"rate_limited"`.

## 5. Circuit Breaker

A `HandshakeCircuitBreaker` SHOULD protect against cascading failures:

| State | Description |
|---|---|
| `closed` | Normal operation, counting failures |
| `open` | All handshakes rejected (too many failures) |
| `half_open` | Allowing one probe to test recovery |

| Parameter | Default | Description |
|---|---|---|
| `failureThreshold` | 5 | Failures before opening |
| `resetTimeMs` | 30000 | Time before moving to half-open |

## 6. Security Considerations

- Nonces MUST be cryptographically random (32 bytes minimum)
- Channel binding prevents session hijacking
- All timestamps MUST be validated within a clock-skew tolerance
- Failed handshakes MUST be logged to the audit trail
- The handshake MUST complete within a configurable timeout (default: 30s)
