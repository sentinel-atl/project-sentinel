# @sentinel/reputation

Weighted reputation scoring with negative vouches, Sybil resistance, and rate-limited vouching.

## Features

- **Weighted scoring** — 90-day half-life exponential decay
- **Negative vouches** — 2x weight multiplier for accountability
- **Quarantine** — automatic at 3+ verified negative vouches
- **Sybil resistance** — rate-limited vouching (1 vouch per source→target per 24h)

## Install

```bash
npm install @sentinel/reputation
```

## Quick Start

```ts
import { ReputationEngine } from '@sentinel/reputation';

const engine = new ReputationEngine();

engine.vouch({
  sourceDid: 'did:key:z6MkAlice...',
  targetDid: 'did:key:z6MkBob...',
  score: 0.9,
  evidence: 'Completed task successfully',
});

const rep = engine.getReputation('did:key:z6MkBob...');
console.log(rep.score);       // 0.9
console.log(rep.quarantined); // false
```

## API

| Method | Description |
|---|---|
| `new ReputationEngine()` | Create a reputation engine |
| `vouch(vouch)` | Submit a vouch (positive or negative) |
| `getReputation(did)` | Get current reputation score |
| `isQuarantined(did)` | Check quarantine status |

## License

MIT
