import { describe, it, expect, beforeEach } from 'vitest';
import { AuditLog } from '../index.js';
import { join } from 'node:path';
import { mkdtemp, readFile, appendFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';

let logPath: string;

beforeEach(async () => {
  const dir = await mkdtemp(join(tmpdir(), 'sentinel-audit-test-'));
  logPath = join(dir, 'audit.jsonl');
});

describe('AuditLog', () => {
  it('logs an event and reads it back', async () => {
    const log = new AuditLog({ logPath });

    const entry = await log.log({
      eventType: 'identity_created',
      actorDid: 'did:key:z6MkTest',
      result: 'success',
    });

    expect(entry.eventType).toBe('identity_created');
    expect(entry.actorDid).toBe('did:key:z6MkTest');
    expect(entry.result).toBe('success');
    expect(entry.entryHash).toBeTruthy();
    expect(entry.prevHash).toBe('0'.repeat(64)); // Genesis

    const entries = await log.readAll();
    expect(entries).toHaveLength(1);
    expect(entries[0].entryHash).toBe(entry.entryHash);
  });

  it('chains hashes: each entry links to the previous', async () => {
    const log = new AuditLog({ logPath });

    const e1 = await log.log({
      eventType: 'identity_created',
      actorDid: 'did:key:z6Mk1',
      result: 'success',
    });

    const e2 = await log.log({
      eventType: 'handshake_init',
      actorDid: 'did:key:z6Mk1',
      targetDid: 'did:key:z6Mk2',
      result: 'success',
    });

    const e3 = await log.log({
      eventType: 'handshake_complete',
      actorDid: 'did:key:z6Mk1',
      targetDid: 'did:key:z6Mk2',
      result: 'success',
    });

    expect(e1.prevHash).toBe('0'.repeat(64));
    expect(e2.prevHash).toBe(e1.entryHash);
    expect(e3.prevHash).toBe(e2.entryHash);
  });

  it('verifyIntegrity passes for a valid log', async () => {
    const log = new AuditLog({ logPath });

    await log.log({ eventType: 'identity_created', actorDid: 'did:key:z6Mk1', result: 'success' });
    await log.log({ eventType: 'vc_issued', actorDid: 'did:key:z6Mk1', result: 'success' });
    await log.log({ eventType: 'handshake_complete', actorDid: 'did:key:z6Mk1', result: 'success' });

    const result = await log.verifyIntegrity();
    expect(result.valid).toBe(true);
    expect(result.totalEntries).toBe(3);
  });

  it('verifyIntegrity detects tampering', async () => {
    const log = new AuditLog({ logPath });

    await log.log({ eventType: 'identity_created', actorDid: 'did:key:z6Mk1', result: 'success' });
    await log.log({ eventType: 'vc_issued', actorDid: 'did:key:z6Mk1', result: 'success' });

    // Tamper with the file: modify the first entry
    const content = await readFile(logPath, 'utf-8');
    const lines = content.trim().split('\n');
    const entry = JSON.parse(lines[0]);
    entry.actorDid = 'did:key:z6MkTampered';
    lines[0] = JSON.stringify(entry);

    const { writeFile } = await import('node:fs/promises');
    await writeFile(logPath, lines.join('\n') + '\n', 'utf-8');

    // Fresh log instance to force re-read
    const freshLog = new AuditLog({ logPath });
    const result = await freshLog.verifyIntegrity();
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(0);
  });

  it('verifyIntegrity detects chain break (deleted entry)', async () => {
    const log = new AuditLog({ logPath });

    await log.log({ eventType: 'identity_created', actorDid: 'did:key:z6Mk1', result: 'success' });
    await log.log({ eventType: 'vc_issued', actorDid: 'did:key:z6Mk1', result: 'success' });
    await log.log({ eventType: 'handshake_complete', actorDid: 'did:key:z6Mk1', result: 'success' });

    // Remove the middle entry
    const content = await readFile(logPath, 'utf-8');
    const lines = content.trim().split('\n');
    const tampered = [lines[0], lines[2]].join('\n') + '\n';

    const { writeFile } = await import('node:fs/promises');
    await writeFile(logPath, tampered, 'utf-8');

    const freshLog = new AuditLog({ logPath });
    const result = await freshLog.verifyIntegrity();
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(1);
  });

  it('returns valid for an empty/nonexistent log', async () => {
    const log = new AuditLog({ logPath: join(logPath, '..', 'nonexistent.jsonl') });
    const result = await log.verifyIntegrity();
    expect(result.valid).toBe(true);
    expect(result.totalEntries).toBe(0);
  });

  it('preserves metadata', async () => {
    const log = new AuditLog({ logPath });

    await log.log({
      eventType: 'vc_issued',
      actorDid: 'did:key:z6Mk1',
      targetDid: 'did:key:z6Mk2',
      result: 'success',
      metadata: { type: 'AgentAuthorizationCredential', scope: 'read:email' },
    });

    const entries = await log.readAll();
    expect(entries[0].metadata).toEqual({
      type: 'AgentAuthorizationCredential',
      scope: 'read:email',
    });
  });
});
