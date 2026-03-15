import { describe, it, expect, beforeEach } from 'vitest';
import { SentinelGuard, createSentinelGuard } from '../index.js';
import {
  InMemoryKeyProvider,
  createIdentity,
  issueVC,
  createIntent,
  toBase64Url,
  textToBytes,
} from '@sentinel/core';
import { AuditLog } from '@sentinel/audit';
import { ReputationEngine } from '@sentinel/reputation';
import { join } from 'node:path';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';

let auditLog: AuditLog;
let serverKP: InMemoryKeyProvider;
let serverDid: string;

beforeEach(async () => {
  const dir = await mkdtemp(join(tmpdir(), 'sentinel-mcp-test-'));
  auditLog = new AuditLog({ logPath: join(dir, 'audit.jsonl') });

  serverKP = new InMemoryKeyProvider();
  const serverIdentity = await createIdentity(serverKP, 'mcp-server');
  serverDid = serverIdentity.did;
});

async function makeCaller(name: string) {
  const kp = new InMemoryKeyProvider();
  const identity = await createIdentity(kp, name);
  return { kp, identity };
}

describe('SentinelGuard', () => {
  it('allows a basic call with no requirements', async () => {
    const guard = createSentinelGuard({ auditLog, serverDid });
    const { identity: caller } = await makeCaller('caller');

    const result = await guard.verifyToolCall({
      toolName: 'echo',
      callerDid: caller.did,
    });

    expect(result.allowed).toBe(true);
    expect(result.checks.identity).toBe(true);
  });

  it('rejects an invalid DID', async () => {
    const guard = createSentinelGuard({ auditLog, serverDid });

    const result = await guard.verifyToolCall({
      toolName: 'echo',
      callerDid: 'not-a-did',
    });

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('Invalid caller DID');
  });

  it('verifies required credentials', async () => {
    const guard = createSentinelGuard({
      auditLog,
      serverDid,
      requiredCredentials: ['AgentAuthorizationCredential'],
    });

    const { kp, identity: caller } = await makeCaller('caller');

    // Call without credentials — should fail
    const noCredsResult = await guard.verifyToolCall({
      toolName: 'echo',
      callerDid: caller.did,
    });
    expect(noCredsResult.allowed).toBe(false);
    expect(noCredsResult.reason).toContain('Missing required credential');

    // Call with valid credential — should pass
    const vc = await issueVC(kp, {
      type: 'AgentAuthorizationCredential',
      issuerDid: caller.did,
      issuerKeyId: caller.keyId,
      subjectDid: caller.did,
      scope: ['test:scope'],
      expiresInMs: 3600_000,
    });

    const withCredsResult = await guard.verifyToolCall({
      toolName: 'echo',
      callerDid: caller.did,
      credentials: [vc],
    });
    expect(withCredsResult.allowed).toBe(true);
    expect(withCredsResult.checks.credentials).toBe(true);
  });

  it('rejects VC with subject mismatch', async () => {
    const guard = createSentinelGuard({
      auditLog,
      serverDid,
      requiredCredentials: ['AgentAuthorizationCredential'],
    });

    const { kp, identity: issuer } = await makeCaller('issuer');
    const { identity: caller } = await makeCaller('caller');

    // VC issued FOR issuer, not for caller
    const vc = await issueVC(kp, {
      type: 'AgentAuthorizationCredential',
      issuerDid: issuer.did,
      issuerKeyId: issuer.keyId,
      subjectDid: issuer.did, // Subject is issuer, not caller
      expiresInMs: 3600_000,
    });

    const result = await guard.verifyToolCall({
      toolName: 'echo',
      callerDid: caller.did,
      credentials: [vc],
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('subject does not match');
  });

  it('enforces tool-level scopes', async () => {
    const guard = createSentinelGuard({
      auditLog,
      serverDid,
      toolScopes: {
        send_email: ['email:send'],
        read_files: ['fs:read'],
      },
    });

    const { kp, identity: caller } = await makeCaller('caller');

    const vc = await issueVC(kp, {
      type: 'AgentAuthorizationCredential',
      issuerDid: caller.did,
      issuerKeyId: caller.keyId,
      subjectDid: caller.did,
      scope: ['email:send'], // Has email but NOT fs:read
      expiresInMs: 3600_000,
    });

    // Can send email
    const emailResult = await guard.verifyToolCall({
      toolName: 'send_email',
      callerDid: caller.did,
      credentials: [vc],
    });
    expect(emailResult.allowed).toBe(true);

    // Cannot read files
    const fsResult = await guard.verifyToolCall({
      toolName: 'read_files',
      callerDid: caller.did,
      credentials: [vc],
    });
    expect(fsResult.allowed).toBe(false);
    expect(fsResult.reason).toContain('fs:read');
  });

  it('enforces minimum reputation', async () => {
    const reputationEngine = new ReputationEngine();
    const guard = createSentinelGuard({
      auditLog,
      serverDid,
      minReputation: 60,
      reputationEngine,
    });

    const { identity: caller } = await makeCaller('caller');

    // New agent has score 50 (below 60)
    const result = await guard.verifyToolCall({
      toolName: 'echo',
      callerDid: caller.did,
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('below minimum');
  });

  it('rejects quarantined callers', async () => {
    const reputationEngine = new ReputationEngine();
    const guard = createSentinelGuard({
      auditLog,
      serverDid,
      reputationEngine,
    });

    const { identity: caller } = await makeCaller('bad-agent');

    // Quarantine the caller
    for (let i = 1; i <= 3; i++) {
      reputationEngine.addVouch({
        voucherDid: `did:key:z6MkVerifier${i}`,
        subjectDid: caller.did,
        polarity: 'negative',
        weight: 0.8,
        voucherVerified: true,
        timestamp: new Date().toISOString(),
      });
    }

    const result = await guard.verifyToolCall({
      toolName: 'echo',
      callerDid: caller.did,
    });
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('quarantined');
  });

  it('requires intent when configured', async () => {
    const guard = createSentinelGuard({
      auditLog,
      serverDid,
      requireIntent: true,
    });

    const { kp, identity: caller } = await makeCaller('caller');
    const { identity: principal } = await makeCaller('principal');

    // Without intent — rejected
    const noIntentResult = await guard.verifyToolCall({
      toolName: 'echo',
      callerDid: caller.did,
    });
    expect(noIntentResult.allowed).toBe(false);
    expect(noIntentResult.reason).toContain('Intent envelope required');

    // With valid intent — accepted
    const intent = await createIntent(kp, {
      action: 'echo',
      scope: ['test:scope'],
      principalDid: principal.did,
      agentDid: caller.did,
      agentKeyId: caller.keyId,
      delegationChain: [],
      expiresInMs: 60_000,
    });

    const withIntentResult = await guard.verifyToolCall({
      toolName: 'echo',
      callerDid: caller.did,
      intent,
    });
    expect(withIntentResult.allowed).toBe(true);
    expect(withIntentResult.checks.intent).toBe(true);
  });

  it('records results for audit trail', async () => {
    const guard = createSentinelGuard({ auditLog, serverDid });
    const { identity: caller } = await makeCaller('caller');

    await guard.verifyToolCall({
      toolName: 'echo',
      callerDid: caller.did,
    });

    await guard.recordResult(
      { toolName: 'echo', callerDid: caller.did },
      'success'
    );

    const entries = await auditLog.readAll();
    expect(entries.length).toBeGreaterThanOrEqual(2);
  });
});
