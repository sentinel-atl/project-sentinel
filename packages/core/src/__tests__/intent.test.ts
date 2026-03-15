import { describe, it, expect } from 'vitest';
import { InMemoryKeyProvider } from '../key-provider.js';
import { createIdentity } from '../did.js';
import { createIntent, validateIntent, isActionInScope } from '../intent.js';

async function makeIdentity(name: string) {
  const kp = new InMemoryKeyProvider();
  const identity = await createIdentity(kp, name);
  return { kp, identity };
}

describe('createIntent / validateIntent', () => {
  it('creates and validates an intent successfully', async () => {
    const { kp, identity: agent } = await makeIdentity('agent');
    const { identity: principal } = await makeIdentity('principal');

    const intent = await createIntent(kp, {
      action: 'book_flight',
      scope: ['travel:book'],
      principalDid: principal.did,
      agentDid: agent.did,
      agentKeyId: agent.keyId,
      delegationChain: ['vc-123'],
      expiresInMs: 60_000,
    });

    expect(intent.version).toBe('1.0');
    expect(intent.action).toBe('book_flight');
    expect(intent.scope).toEqual(['travel:book']);
    expect(intent.principalDid).toBe(principal.did);
    expect(intent.agentDid).toBe(agent.did);
    expect(intent.nonce).toHaveLength(64); // 32 bytes = 64 hex chars
    expect(intent.signature).toBeTruthy();

    const seenNonces = new Set<string>();
    const result = await validateIntent(intent, seenNonces);
    expect(result.valid).toBe(true);
    expect(result.checks.signature).toBe(true);
    expect(result.checks.expiry).toBe(true);
    expect(result.checks.nonce).toBe(true);
    expect(result.checks.scopeValid).toBe(true);
  });

  it('detects replay (same nonce used twice)', async () => {
    const { kp, identity: agent } = await makeIdentity('agent');
    const { identity: principal } = await makeIdentity('principal');

    const intent = await createIntent(kp, {
      action: 'book_flight',
      scope: ['travel:book'],
      principalDid: principal.did,
      agentDid: agent.did,
      agentKeyId: agent.keyId,
      delegationChain: [],
      expiresInMs: 60_000,
    });

    const seenNonces = new Set<string>();
    const first = await validateIntent(intent, seenNonces);
    expect(first.valid).toBe(true);

    const second = await validateIntent(intent, seenNonces);
    expect(second.valid).toBe(false);
    expect(second.error).toBe('Replayed nonce detected');
  });

  it('rejects an expired intent', async () => {
    const { kp, identity: agent } = await makeIdentity('agent');
    const { identity: principal } = await makeIdentity('principal');

    const intent = await createIntent(kp, {
      action: 'book_flight',
      scope: ['travel:book'],
      principalDid: principal.did,
      agentDid: agent.did,
      agentKeyId: agent.keyId,
      delegationChain: [],
      expiresInMs: 1,
    });

    // Force expiry beyond clock tolerance
    intent.expiry = new Date(Date.now() - 60_000).toISOString();

    const result = await validateIntent(intent);
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Intent has expired');
  });

  it('rejects a tampered intent (invalid signature)', async () => {
    const { kp, identity: agent } = await makeIdentity('agent');
    const { identity: principal } = await makeIdentity('principal');

    const intent = await createIntent(kp, {
      action: 'book_flight',
      scope: ['travel:book'],
      principalDid: principal.did,
      agentDid: agent.did,
      agentKeyId: agent.keyId,
      delegationChain: [],
      expiresInMs: 60_000,
    });

    // Tamper with the action
    intent.action = 'delete_account';

    const result = await validateIntent(intent);
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Invalid signature');
  });

  it('rejects an intent with empty scope', async () => {
    const { kp, identity: agent } = await makeIdentity('agent');
    const { identity: principal } = await makeIdentity('principal');

    const intent = await createIntent(kp, {
      action: 'do_something',
      scope: ['placeholder'],
      principalDid: principal.did,
      agentDid: agent.did,
      agentKeyId: agent.keyId,
      delegationChain: [],
    });

    // Force empty scope
    intent.scope = [];

    const result = await validateIntent(intent);
    expect(result.valid).toBe(false);
    expect(result.error).toBe('Intent has no scope');
  });
});

describe('isActionInScope', () => {
  it('returns true for an action in scope', async () => {
    const { kp, identity: agent } = await makeIdentity('agent');
    const intent = await createIntent(kp, {
      action: 'book_flight',
      scope: ['travel:book', 'travel:search'],
      principalDid: 'did:key:zFakePrincipal',
      agentDid: agent.did,
      agentKeyId: agent.keyId,
      delegationChain: [],
    });

    expect(isActionInScope(intent, 'travel:book')).toBe(true);
    expect(isActionInScope(intent, 'travel:search')).toBe(true);
  });

  it('returns false for an action not in scope', async () => {
    const { kp, identity: agent } = await makeIdentity('agent');
    const intent = await createIntent(kp, {
      action: 'book_flight',
      scope: ['travel:book'],
      principalDid: 'did:key:zFakePrincipal',
      agentDid: agent.did,
      agentKeyId: agent.keyId,
      delegationChain: [],
    });

    expect(isActionInScope(intent, 'admin:delete')).toBe(false);
  });
});
