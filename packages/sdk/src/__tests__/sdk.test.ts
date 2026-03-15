import { describe, it, expect } from 'vitest';
import { createTrustedAgent, hashCode } from '../index.js';
import { join } from 'node:path';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';

async function makeAgent(name: string) {
  const dir = await mkdtemp(join(tmpdir(), `sentinel-sdk-test-${name}-`));
  return createTrustedAgent({
    name,
    capabilities: ['test'],
    auditLogPath: join(dir, 'audit.jsonl'),
  });
}

describe('@sentinel-atl/sdk', () => {
  it('creates a trusted agent with a DID', async () => {
    const agent = await makeAgent('test-agent');
    expect(agent.did).toMatch(/^did:key:z6Mk/);
    expect(agent.keyId).toBe('test-agent');
    expect(agent.passport.name).toBe('test-agent');
    expect(agent.passport.capabilities).toEqual(['test']);
  });

  it('issues and verifies a credential', async () => {
    const agent = await makeAgent('issuer');
    const peer = await makeAgent('peer');

    const vc = await agent.issueCredential({
      type: 'AgentAuthorizationCredential',
      subjectDid: peer.did,
      scope: ['read:email'],
      expiresInMs: 3600_000,
    });

    expect(vc.issuer).toBe(agent.did);
    expect(vc.credentialSubject.id).toBe(peer.did);

    const result = await peer.verifyCredential(vc);
    expect(result.valid).toBe(true);
  });

  it('creates and validates intents with replay protection', async () => {
    const agent = await makeAgent('agent');
    const validator = await makeAgent('validator');

    const intent = await agent.createIntent(
      'book_flight',
      ['travel:book'],
      'did:key:z6MkFakePrincipal'
    );

    expect(intent.action).toBe('book_flight');
    expect(intent.agentDid).toBe(agent.did);

    // First validation succeeds
    const r1 = await validator.validateIntent(intent);
    expect(r1.valid).toBe(true);

    // Replay fails
    const r2 = await validator.validateIntent(intent);
    expect(r2.valid).toBe(false);
    expect(r2.error).toContain('Replayed');
  });

  it('adds reputation vouches with rate limiting', async () => {
    const agent = await makeAgent('voucher');
    const peer = await makeAgent('subject');

    // First vouch succeeds
    const r1 = agent.vouch(peer.did, 'positive', 0.8);
    expect(r1.allowed).toBe(true);

    // Second vouch to same peer blocked (rate limit)
    const r2 = agent.vouch(peer.did, 'positive', 0.8);
    expect(r2.allowed).toBe(false);

    // Reputation increased
    const score = agent.getReputation(peer.did);
    expect(score.score).toBeGreaterThan(50);
    expect(score.positiveVouches).toBe(1);
  });

  it('self-vouch is rejected', async () => {
    const agent = await makeAgent('narcissist');
    const result = agent.vouch(agent.did, 'positive', 1.0);
    expect(result.allowed).toBe(false);
  });

  it('maintains audit log', async () => {
    const agent = await makeAgent('audited');

    await agent.issueCredential({
      type: 'ComplianceCredential',
      subjectDid: agent.did,
      expiresInMs: 3600_000,
    });

    const entries = await agent.getAuditLog().readAll();
    // At least: identity_created + vc_issued
    expect(entries.length).toBeGreaterThanOrEqual(2);
  });

  it('revokes a VC and checks trust', async () => {
    const agent = await makeAgent('revoker');
    const peer = await makeAgent('peer');

    const vc = await agent.issueCredential({
      type: 'AgentAuthorizationCredential',
      subjectDid: peer.did,
      scope: ['test:scope'],
      expiresInMs: 3600_000,
    });

    // Initially trusted
    expect(agent.isTrusted(peer.did, vc.id).trusted).toBe(true);

    // Revoke
    await agent.revokeCredential(vc.id, 'policy_violation');

    // Now VC is untrusted
    const result = agent.isTrusted(peer.did, vc.id);
    expect(result.trusted).toBe(false);
    expect(result.reason).toContain('VC revoked');
  });

  it('activates kill switch on a rogue agent', async () => {
    const admin = await makeAgent('admin');
    const rogue = await makeAgent('rogue');

    const event = await admin.killSwitch(
      rogue.did,
      'Producing harmful output'
    );

    expect(event.targetDid).toBe(rogue.did);
    expect(event.activatedBy).toBe(admin.did);
    expect(admin.isTrusted(rogue.did).trusted).toBe(false);
  });

  it('attests code and retrieves attestation', async () => {
    const agent = await makeAgent('attested');
    const codeHash = hashCode('my agent code v1.0');

    const attestation = await agent.attestCode(
      codeHash,
      ['main.ts', 'utils.ts'],
      { version: '1.0.0', commitHash: 'abc123' }
    );

    expect(attestation.agentDid).toBe(agent.did);
    expect(attestation.codeHash).toBe(codeHash);

    const retrieved = agent.getAttestation();
    expect(retrieved?.version).toBe('1.0.0');
  });
});
