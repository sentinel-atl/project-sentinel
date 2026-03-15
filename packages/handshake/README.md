# @sentinel-atl/handshake

Zero-trust handshake protocol with versioning, channel binding, and rate limiting.

## Features

- **5-step mutual verification** — init → response → VC exchange → verify → session
- **Rate limiting** — configurable per-DID request throttling
- **Circuit breaker** — automatic failure-based cutoff with recovery window
- **Channel binding** — cryptographic session tokens

## Install

```bash
npm install @sentinel-atl/handshake
```

## Quick Start

```ts
import {
  createHandshakeInit,
  processInitAndRespond,
  createVCExchange,
  verifyVCExchange,
  createSessionEstablished,
} from '@sentinel-atl/handshake';

// Step 1: Initiator sends init
const init = createHandshakeInit({
  did: initiatorDid,
  credentials: [vc],
  protocolVersion: '1.0',
});

// Step 2: Responder processes init and responds
const response = processInitAndRespond(init, { did: responderDid });

// Step 3: Exchange VCs
const exchange = await createVCExchange(keyProvider, { ... });

// Step 4: Verify exchange
const verified = await verifyVCExchange(exchange);

// Step 5: Establish session
const session = createSessionEstablished(init, response);
```

## API

| Export | Description |
|---|---|
| `createHandshakeInit(config)` | Create a handshake init message |
| `processInitAndRespond(init, config)` | Process init and respond |
| `createVCExchange(kp, options)` | Create signed VC exchange |
| `verifyVCExchange(exchange)` | Verify VC exchange |
| `createSessionEstablished(init, response)` | Establish session |
| `HandshakeRateLimiter` | Per-DID rate limiter |
| `HandshakeCircuitBreaker` | Failure-based circuit breaker |

## License

MIT
