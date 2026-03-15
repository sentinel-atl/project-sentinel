# Content Safety Specification v0.1

**Status:** Draft  
**Authors:** Project Sentinel Contributors  
**Date:** March 2026  
**License:** Apache 2.0  

---

## Abstract

This document specifies the content safety pipeline used by Sentinel to inspect agent inputs and outputs for harmful content, prompt injection, PII leakage, and other violations.

---

## 1. Overview

The safety pipeline provides two inspection points:

1. **Pre-dispatch** — inspect the input before a tool is executed
2. **Post-response** — inspect the output before it is returned

Each inspection runs content through a chain of classifiers. If any classifier detects a violation above the configured severity threshold, the content is blocked.

## 2. Classification Model

### 2.1 Safety Categories

| Category | Description |
|---|---|
| `prompt_injection` | Attempts to override system instructions |
| `jailbreak` | Attempts to bypass safety guidelines |
| `pii` | Personally identifiable information (SSN, email, etc.) |
| `harmful_content` | Toxic, violent, or illegal content |
| `data_exfiltration` | Attempts to extract sensitive data |
| `custom` | User-defined category |

### 2.2 Severity Levels

| Level | Priority | Default Action |
|---|---|---|
| `low` | 0 | Log only |
| `medium` | 1 | Warn |
| `high` | 2 | Block |
| `critical` | 3 | Block + alert |

### 2.3 Safety Violation

| Field | Type | Description |
|---|---|---|
| `category` | `SafetyCategory` | Type of violation |
| `severity` | `SafetySeverity` | Severity level |
| `description` | `string` | Human-readable explanation |
| `matchedPattern` | `string` | The pattern or rule that matched |
| `span` | `[number, number]` | Optional: start/end index in content |

## 3. Classifier Interface

All classifiers implement:

```typescript
interface ContentClassifier {
  name: string;
  classify(content: string): Promise<ClassificationResult>;
}

interface ClassificationResult {
  violations: SafetyViolation[];
}
```

### 3.1 Built-in Classifiers

#### RegexClassifier

Matches content against a set of regex patterns. Default rules:

| Rule | Category | Severity | Pattern |
|---|---|---|---|
| Prompt injection | `prompt_injection` | `critical` | `ignore\s+(previous\|above\|all)\s+(instructions?\|prompts?\|rules?)` |
| Jailbreak | `jailbreak` | `critical` | `(DAN\|do anything now\|developer mode\|unrestricted mode)` |
| SSN detection | `pii` | `high` | `\b\d{3}-\d{2}-\d{4}\b` |
| Email detection | `pii` | `medium` | `\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b` |

#### KeywordClassifier

Matches content against a configurable deny-list of keywords. All matches are reported as severity `high` in the `harmful_content` category.

## 4. Safety Pipeline

### 4.1 Configuration

| Field | Type | Default | Description |
|---|---|---|---|
| `classifiers` | `ContentClassifier[]` | `[RegexClassifier()]` | Ordered list of classifiers |
| `blockThreshold` | `SafetySeverity` | `"high"` | Minimum severity to block |
| `auditLog` | `AuditLog` | — | Optional audit log for recording violations |

### 4.2 Execution Flow

1. Run content through each classifier in order
2. Collect all violations
3. If any violation meets or exceeds `blockThreshold`:
   - Set `blocked = true`
   - Log to audit trail (if configured)
4. Return `SafetyCheckResult`

### 4.3 Safety Check Result

| Field | Type | Description |
|---|---|---|
| `safe` | `boolean` | `true` if no blocking violations |
| `blocked` | `boolean` | `true` if content was blocked |
| `violations` | `SafetyViolation[]` | All detected violations |

## 5. MCP Integration

When integrated with `SentinelGuard`:

1. Pre-dispatch runs on the tool call arguments
2. If blocked, the tool call is denied with reason `"safety_violation"`
3. The violation details are included in the `VerifyResult`

## 6. Security Considerations

- Regex classifiers are not a substitute for ML-based classifiers in production
- Pattern matching can be evaded with encoding tricks; defense-in-depth is essential
- PII patterns should be tuned per jurisdiction (GDPR, CCPA, etc.)
- Safety violations MUST be logged for compliance and forensics
- The pipeline SHOULD be extensible — organizations can add custom classifiers
