# Reputation Protocol Specification v0.1

**Status:** Draft  
**Authors:** Project Sentinel Contributors  
**Date:** March 2026  
**License:** Apache 2.0  

---

## Abstract

This document specifies the reputation scoring protocol used by Sentinel agents. The protocol provides weighted, decaying reputation scores with Sybil resistance, negative vouches, quarantine mechanisms, and CRDT-based offline merge.

---

## 1. Overview

Reputation quantifies an agent's trustworthiness based on vouches from other agents. The system is designed to:

- Resist Sybil attacks through rate limiting
- Weight negative feedback more heavily than positive
- Decay scores over time so recent behavior matters more
- Support offline operation through CRDT merge

## 2. Vouch Model

A **vouch** is a signed reputation signal from one agent (source) about another (target).

| Field | Type | Description |
|---|---|---|
| `sourceDid` | `string` | DID of the vouching agent |
| `targetDid` | `string` | DID of the agent being vouched |
| `score` | `number` | Score in range [-1.0, 1.0] |
| `evidence` | `string` | Human-readable justification |
| `timestamp` | `string` | ISO 8601 timestamp |

### 2.1 Score Interpretation

| Range | Meaning |
|---|---|
| [0.8, 1.0] | Highly trusted |
| [0.5, 0.8) | Generally trusted |
| [0.0, 0.5) | Neutral / unknown |
| [-0.5, 0.0) | Somewhat untrusted |
| [-1.0, -0.5) | Highly untrusted (may trigger quarantine) |

## 3. Scoring Algorithm

### 3.1 Weighted Average with Decay

The reputation score for an agent is computed as:

$$\text{score}(d) = \frac{\sum_{i} w_i \cdot v_i \cdot \text{decay}(t_i)}{\sum_{i} w_i \cdot \text{decay}(t_i)}$$

Where:
- $v_i$ is the vouch score
- $w_i$ is the weight (1.0 for positive, 2.0 for negative)
- $\text{decay}(t) = 2^{-(t_{\text{now}} - t_i) / t_{\text{half}}}$
- $t_{\text{half}} = 90$ days (half-life)

### 3.2 Negative Weight Multiplier

Negative vouches ($v_i < 0$) carry a 2x weight multiplier. This ensures that a single credible negative vouch outweighs a single positive vouch of equal magnitude.

### 3.3 Time Decay

All vouches decay exponentially with a 90-day half-life. A vouch from 90 days ago has half the influence of a vouch from today.

## 4. Quarantine

An agent is **quarantined** when it accumulates 3 or more verified negative vouches (score < 0). Quarantined agents:

- Cannot issue VCs to other agents
- Have their tool calls rejected by MCP guards
- Must wait for positive vouches to exit quarantine

## 5. Rate Limiting

To prevent Sybil vouching:

| Rule | Value |
|---|---|
| Max vouches per source→target pair | 1 per 24 hours |
| Duplicate vouch behavior | Rejected with `rate_limited` |

## 6. CRDT Offline Merge

For offline operation, reputation state is maintained as a **Last-Writer-Wins (LWW) register** per DID:

| Field | Type | Description |
|---|---|---|
| `did` | `string` | Target agent DID |
| `score` | `number` | Latest known score |
| `nodeId` | `string` | ID of the node that recorded this |
| `timestamp` | `number` | Unix timestamp of the recording |

### 6.1 Merge Rule

When merging two states for the same DID:
1. The entry with the **higher timestamp** wins
2. On timestamp tie, the entry with the **lexicographically greater nodeId** wins

This guarantees deterministic convergence across all nodes.

## 7. Audit Integration

All reputation events MUST be logged:

| Event Type | When |
|---|---|
| `reputation_vouch` | A vouch is submitted |
| `reputation_quarantine` | An agent enters quarantine |
| `reputation_rate_limited` | A vouch is rate-limited |

## 8. Security Considerations

- Vouches SHOULD be signed by the source agent (verification optional in v0.1)
- Self-vouching (sourceDid === targetDid) MUST be rejected
- Score values outside [-1.0, 1.0] MUST be rejected
- The quarantine threshold SHOULD be configurable per deployment
