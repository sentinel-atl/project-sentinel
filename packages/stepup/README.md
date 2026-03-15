# @sentinel/stepup

Step-up authentication — re-prompt humans for sensitive agent actions.

## Features

- **Policy-based triggers** — define when step-up auth is required (scope, risk, time-based)
- **Challenge-response** — time-bounded, single-use approval tokens
- **Multi-factor** — support for TOTP, biometric, and custom challenge types
- **Audit integration** — all step-up events logged

## Install

```bash
npm install @sentinel/stepup
```

## Quick Start

```ts
import { StepUpManager } from '@sentinel/stepup';

const mgr = new StepUpManager({
  auditLog,
  policies: [
    { trigger: 'scope', scopes: ['admin:*'], challengeType: 'totp' },
    { trigger: 'risk_score', threshold: 0.8, challengeType: 'biometric' },
  ],
});

// Check if step-up is needed
const result = mgr.evaluate({
  agentDid: 'did:key:z6Mk...',
  requestedScopes: ['admin:delete'],
});

if (result.required) {
  // Present challenge to human
  const challenge = mgr.createChallenge(result);
  // ... human responds ...
  const approval = mgr.verifyResponse(challenge, response);
}
```

## API

| Method | Description |
|---|---|
| `new StepUpManager(config)` | Create manager with policies |
| `evaluate(context)` | Check if step-up is required |
| `createChallenge(result)` | Create a time-bounded challenge |
| `verifyResponse(challenge, response)` | Verify human response |

## License

MIT
