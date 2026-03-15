import { describe, it, expect, beforeEach } from 'vitest';
import {
  createHandshakeInit,
  processInitAndRespond,
  createVCExchange,
  verifyVCExchange,
  createSessionEstablished,
  HandshakeRateLimiter,
  HandshakeCircuitBreaker,
  type HandshakeConfig,
} from '../index.js';
import {
  InMemoryKeyProvider,
  createIdentity,
  createPassport,
  issueVC,
} from '@sentinel-atl/core';

async function makeAgent(name: string) {
  const kp = new InMemoryKeyProvider();
  const identity = await createIdentity(kp, name);
  const passport = createPassport({
    did: identity.did,
    name,
    offeredCredentials: ['AgentAuthorizationCredential'],
    requiredCredentials: ['AgentAuthorizationCredential'],
  });
  const config: HandshakeConfig = {
    selfDid: identity.did,
    selfKeyId: identity.keyId,
    passport,
    keyProvider: kp,
  };
  return { kp, identity, passport, config };
}

describe('Handshake Protocol', () => {
  it('completes a full 5-step handshake', async () => {
    const agentA = await makeAgent('agent-a');
    const agentB = await makeAgent('agent-b');

    // Step 1: Init
    const init = createHandshakeInit(agentA.config);
    expect(init.type).toBe('handshake_init');
    expect(init.protocolVersion).toBe('1.0');
    expect(init.initiatorDid).toBe(agentA.identity.did);

    // Step 2: Response
    const response = processInitAndRespond(init, agentB.config);
    expect(response.type).toBe('handshake_response');
    if (response.type !== 'handshake_response') throw new Error('Expected response');
    expect(response.responderDid).toBe(agentB.identity.did);

    // Issue VCs for exchange
    const vcA = await issueVC(agentA.kp, {
      type: 'AgentAuthorizationCredential',
      issuerDid: agentA.identity.did,
      issuerKeyId: agentA.identity.keyId,
      subjectDid: agentA.identity.did,
      scope: ['test:scope'],
      expiresInMs: 3600_000,
    });

    const vcB = await issueVC(agentB.kp, {
      type: 'AgentAuthorizationCredential',
      issuerDid: agentB.identity.did,
      issuerKeyId: agentB.identity.keyId,
      subjectDid: agentB.identity.did,
      scope: ['test:scope'],
      expiresInMs: 3600_000,
    });

    // Step 3: Agent A sends VCs
    const exchangeA = await createVCExchange(agentA.config, response.nonce, [vcA]);
    expect(exchangeA.type).toBe('vc_exchange');
    expect(exchangeA.credentials).toHaveLength(1);

    // Step 4: Verify A's exchange, then B sends
    const verifyA = await verifyVCExchange(exchangeA, response.nonce);
    expect(verifyA.valid).toBe(true);

    const exchangeB = await createVCExchange(agentB.config, init.nonce, [vcB]);
    const verifyB = await verifyVCExchange(exchangeB, init.nonce);
    expect(verifyB.valid).toBe(true);

    // Step 5: Session established
    const session = createSessionEstablished(agentA.identity.did, agentB.identity.did);
    expect(session.type).toBe('session_established');
    expect(session.sessionId).toHaveLength(32); // 16 bytes = 32 hex chars
    expect(session.initiatorDid).toBe(agentA.identity.did);
    expect(session.responderDid).toBe(agentB.identity.did);
  });

  it('rejects a handshake with clock skew', async () => {
    const agentA = await makeAgent('agent-a');
    const agentB = await makeAgent('agent-b');

    const init = createHandshakeInit(agentA.config);
    // Set timestamp to far in the past
    init.timestamp = new Date(Date.now() - 120_000).toISOString();

    const response = processInitAndRespond(init, agentB.config);
    expect(response.type).toBe('handshake_error');
    if (response.type === 'handshake_error') {
      expect(response.code).toBe('CLOCK_SKEW');
    }
  });

  it('rejects a handshake with wrong protocol version', async () => {
    const agentA = await makeAgent('agent-a');
    const agentB = await makeAgent('agent-b');

    const init = createHandshakeInit(agentA.config);
    init.protocolVersion = '99.0';

    const response = processInitAndRespond(init, agentB.config);
    expect(response.type).toBe('handshake_error');
    if (response.type === 'handshake_error') {
      expect(response.code).toBe('VERSION_MISMATCH');
    }
  });

  it('rejects VC exchange with wrong nonce (proof of liveness fails)', async () => {
    const agentA = await makeAgent('agent-a');

    const vc = await issueVC(agentA.kp, {
      type: 'AgentAuthorizationCredential',
      issuerDid: agentA.identity.did,
      issuerKeyId: agentA.identity.keyId,
      subjectDid: agentA.identity.did,
      expiresInMs: 3600_000,
    });

    const exchange = await createVCExchange(agentA.config, 'correct-nonce', [vc]);
    const result = await verifyVCExchange(exchange, 'wrong-nonce');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('liveness');
  });
});

describe('HandshakeRateLimiter', () => {
  it('allows requests within the limit', () => {
    const limiter = new HandshakeRateLimiter(5);
    for (let i = 0; i < 5; i++) {
      expect(limiter.check('did:key:z6MkTest').allowed).toBe(true);
    }
  });

  it('blocks requests over the limit', () => {
    const limiter = new HandshakeRateLimiter(3);
    limiter.check('did:key:z6MkTest');
    limiter.check('did:key:z6MkTest');
    limiter.check('did:key:z6MkTest');

    const result = limiter.check('did:key:z6MkTest');
    expect(result.allowed).toBe(false);
    expect(result.retryAfterMs).toBeGreaterThan(0);
  });

  it('tracks DIDs independently', () => {
    const limiter = new HandshakeRateLimiter(1);
    expect(limiter.check('did:key:z6Mk1').allowed).toBe(true);
    expect(limiter.check('did:key:z6Mk2').allowed).toBe(true);
    // First DID now blocked
    expect(limiter.check('did:key:z6Mk1').allowed).toBe(false);
  });
});

describe('HandshakeCircuitBreaker', () => {
  it('opens after threshold failures', () => {
    const breaker = new HandshakeCircuitBreaker(3, 60_000);

    breaker.recordFailure('did:key:z6MkTest');
    breaker.recordFailure('did:key:z6MkTest');
    expect(breaker.check('did:key:z6MkTest').allowed).toBe(true);

    breaker.recordFailure('did:key:z6MkTest');
    const result = breaker.check('did:key:z6MkTest');
    expect(result.allowed).toBe(false);
    expect(result.retryAfterMs).toBeGreaterThan(0);
  });

  it('resets on success', () => {
    const breaker = new HandshakeCircuitBreaker(2, 60_000);
    breaker.recordFailure('did:key:z6MkTest');
    breaker.recordSuccess('did:key:z6MkTest');

    // Should be clean now
    breaker.recordFailure('did:key:z6MkTest');
    expect(breaker.check('did:key:z6MkTest').allowed).toBe(true);
  });
});
