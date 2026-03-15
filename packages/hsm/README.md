# @sentinel/hsm

HSM and secure enclave KeyProvider backends for the Agent Trust Layer.

## Providers

| Provider | Status | Dependencies |
|---|---|---|
| `EncryptedFileKeyProvider` | **Fully functional** | None (Node.js crypto) |
| `AWSCloudHSMKeyProvider` | Stub (interface ready) | `pkcs11js` |
| `AzureManagedHSMKeyProvider` | Stub (interface ready) | `@azure/keyvault-keys` |
| `PKCS11KeyProvider` | Stub (interface ready) | `pkcs11js` |

## Install

```bash
npm install @sentinel/hsm
```

## EncryptedFileKeyProvider

Production-ready encrypted file storage using AES-256-GCM with scrypt key derivation.

```ts
import { EncryptedFileKeyProvider } from '@sentinel/hsm';

const provider = new EncryptedFileKeyProvider({
  directory: './keys',
  passphrase: process.env.KEY_PASSPHRASE!,
});

// Use as a drop-in replacement for InMemoryKeyProvider
const kp = await provider.generate('my-agent-key');
const sig = await provider.sign('my-agent-key', data);
```

**Security properties:**
- AES-256-GCM authenticated encryption
- scrypt key derivation (N=16384, r=8, p=1)
- Random salt per key, random IV per encryption
- Path traversal prevention on key IDs

## HSM Stubs

The HSM stubs implement the `KeyProvider` interface and throw informative errors telling you which SDK to install:

```ts
import { AWSCloudHSMKeyProvider } from '@sentinel/hsm';

const provider = new AWSCloudHSMKeyProvider({
  clusterId: 'cluster-abc',
  pkcs11LibPath: '/opt/cloudhsm/lib/libcloudhsm_pkcs11.so',
  pin: process.env.HSM_PIN!,
});
```

## License

MIT
