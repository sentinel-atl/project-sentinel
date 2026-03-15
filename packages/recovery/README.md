# @sentinel/recovery

Key backup and recovery via Shamir's Secret Sharing (3-of-5 threshold).

## Features

- **Shamir's Secret Sharing** — split any secret into 5 shares, reconstruct with any 3
- **GF(256) arithmetic** — constant-time field operations
- **Threshold flexibility** — configurable k-of-n parameters

## Install

```bash
npm install @sentinel/recovery
```

## Quick Start

```ts
import { splitSecret, reconstructSecret } from '@sentinel/recovery';

const secret = new Uint8Array([1, 2, 3, 4, 5]);

// Split into 5 shares (threshold = 3)
const shares = splitSecret(secret, 5, 3);

// Reconstruct with any 3 shares
const recovered = reconstructSecret([shares[0], shares[2], shares[4]]);
console.log(recovered); // Uint8Array [1, 2, 3, 4, 5]
```

## API

| Export | Description |
|---|---|
| `splitSecret(secret, n, k)` | Split secret into `n` shares with threshold `k` |
| `reconstructSecret(shares)` | Reconstruct secret from `k` or more shares |
| `Share` | Type: `{ x: number; y: Uint8Array }` |

## License

MIT
