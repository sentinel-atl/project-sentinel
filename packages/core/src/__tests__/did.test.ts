import { describe, it, expect } from 'vitest';
import { InMemoryKeyProvider } from '../key-provider.js';
import {
  publicKeyToDid,
  didToPublicKey,
  resolveDid,
  createIdentity,
} from '../did.js';
import { toHex } from '../crypto.js';

describe('publicKeyToDid / didToPublicKey', () => {
  it('creates a did:key from a public key and reverses it', async () => {
    const kp = new InMemoryKeyProvider();
    const identity = await createIdentity(kp, 'test');
    const did = publicKeyToDid(identity.publicKey);

    expect(did).toMatch(/^did:key:z6Mk/);

    const recovered = didToPublicKey(did);
    expect(toHex(recovered)).toBe(toHex(identity.publicKey));
  });

  it('round-trips multiple keys without collision', async () => {
    const kp = new InMemoryKeyProvider();
    const ids = await Promise.all(
      Array.from({ length: 5 }, (_, i) => createIdentity(kp, `key-${i}`))
    );
    const dids = new Set(ids.map((id) => id.did));
    expect(dids.size).toBe(5);

    for (const id of ids) {
      const recovered = didToPublicKey(id.did);
      expect(toHex(recovered)).toBe(toHex(id.publicKey));
    }
  });

  it('rejects non-did:key strings', () => {
    expect(() => didToPublicKey('did:web:example.com')).toThrow('Unsupported DID method');
    expect(() => didToPublicKey('not-a-did')).toThrow('Unsupported DID method');
  });
});

describe('resolveDid', () => {
  it('produces a valid DID Document', async () => {
    const kp = new InMemoryKeyProvider();
    const identity = await createIdentity(kp, 'resolve-test');
    const doc = resolveDid(identity.did);

    expect(doc['@context']).toContain('https://www.w3.org/ns/did/v1');
    expect(doc.id).toBe(identity.did);
    expect(doc.verificationMethod).toHaveLength(1);
    expect(doc.verificationMethod[0].type).toBe('Ed25519VerificationKey2020');
    expect(doc.verificationMethod[0].controller).toBe(identity.did);
    expect(doc.authentication).toHaveLength(1);
    expect(doc.assertionMethod).toHaveLength(1);
  });
});

describe('createIdentity', () => {
  it('returns a complete AgentIdentity', async () => {
    const kp = new InMemoryKeyProvider();
    const identity = await createIdentity(kp, 'my-agent');

    expect(identity.did).toMatch(/^did:key:z/);
    expect(identity.keyId).toBe('my-agent');
    expect(identity.publicKey).toBeInstanceOf(Uint8Array);
    expect(identity.publicKey.length).toBe(32);
    expect(identity.createdAt).toBeTruthy();
    expect(new Date(identity.createdAt).getTime()).not.toBeNaN();
  });

  it('stores the key in the provider', async () => {
    const kp = new InMemoryKeyProvider();
    const identity = await createIdentity(kp, 'stored');

    expect(await kp.has('stored')).toBe(true);
    const pubKey = await kp.getPublicKey('stored');
    expect(toHex(pubKey)).toBe(toHex(identity.publicKey));
  });

  it('generates a key ID when none is provided', async () => {
    const kp = new InMemoryKeyProvider();
    const identity = await createIdentity(kp);
    expect(identity.keyId).toMatch(/^agent-\d+$/);
  });
});
