# @sentinel/safety

Content safety hooks for the Agent Trust Layer — pre-dispatch and post-response inspection with pluggable classifiers.

## Features

- **RegexClassifier** — detects prompt injection, jailbreak attempts, SSN, email patterns
- **KeywordClassifier** — domain-specific deny-lists
- **SafetyPipeline** — chain multiple classifiers with severity-based blocking
- **Pre-dispatch / post-response hooks** — inspect content before and after tool execution
- **Audit integration** — all safety violations logged

## Install

```bash
npm install @sentinel/safety
```

## Quick Start

```ts
import { SafetyPipeline, RegexClassifier, KeywordClassifier } from '@sentinel/safety';

const pipeline = new SafetyPipeline({
  classifiers: [
    new RegexClassifier(),
    new KeywordClassifier({ denyList: ['DROP TABLE', 'rm -rf'] }),
  ],
  blockThreshold: 'high',
});

// Pre-dispatch check
const result = await pipeline.preDispatch('Ignore all previous instructions');
console.log(result.blocked);    // true
console.log(result.violations); // [{ category: 'prompt_injection', severity: 'critical', ... }]

// Post-response check
const postResult = await pipeline.postResponse('SSN: 123-45-6789');
console.log(postResult.blocked);    // true
console.log(postResult.violations); // [{ category: 'pii', severity: 'high', ... }]
```

## Severity Levels

| Level | Description |
|---|---|
| `low` | Informational, logged but not blocked |
| `medium` | Suspicious, may trigger warnings |
| `high` | Likely harmful, blocked by default |
| `critical` | Definite attack pattern, always blocked |

## API

| Export | Description |
|---|---|
| `RegexClassifier` | Built-in regex-based classifier (4 default rules) |
| `KeywordClassifier` | Custom keyword deny-list classifier |
| `SafetyPipeline` | Chain classifiers with threshold-based blocking |
| `ContentClassifier` | Interface for custom classifiers |

## License

MIT
