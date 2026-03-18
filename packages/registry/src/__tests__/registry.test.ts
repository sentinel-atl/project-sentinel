import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { CertificateStore, RegistryServer, gradeBadge, scoreBadge, verifiedBadge, notFoundBadge } from '../index.js';
import { InMemoryKeyProvider, publicKeyToDid } from '@sentinel-atl/core';
import { scan, issueSTC, type SentinelTrustCertificate } from '@sentinel-atl/scanner';
import { mkdtemp, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// ─── Helpers ──────────────────────────────────────────────────────────

async function createTempPackage(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'sentinel-reg-'));
  for (const [name, content] of Object.entries(files)) {
    const dirPath = join(dir, name.split('/').slice(0, -1).join('/'));
    if (name.includes('/')) await mkdir(dirPath, { recursive: true });
    await writeFile(join(dir, name), content, 'utf-8');
  }
  return dir;
}

let kp: InMemoryKeyProvider;
let identity: { keyId: string; did: string };

async function makeTestSTC(pkgName: string, version = '1.0.0'): Promise<SentinelTrustCertificate> {
  const dir = await createTempPackage({
    'package.json': JSON.stringify({ name: pkgName, version }),
    'src/index.ts': 'export function handler() { return "ok"; }\n',
  });
  const report = await scan({ packagePath: dir, skipDependencies: true });
  return issueSTC(kp, {
    scanReport: report,
    codeHash: `hash-${pkgName}-${version}`,
    issuerDid: identity.did,
    issuerKeyId: identity.keyId,
  });
}

beforeEach(async () => {
  kp = new InMemoryKeyProvider();
  await kp.generate('test-key');
  const pubKey = await kp.getPublicKey('test-key');
  identity = { keyId: 'test-key', did: publicKeyToDid(pubKey) };
});

// ─── Store Tests ──────────────────────────────────────────────────────

describe('CertificateStore', () => {
  it('registers and retrieves a certificate', async () => {
    const store = new CertificateStore();
    const stc = await makeTestSTC('@test/pkg-a');
    const entry = await store.register(stc);

    expect(entry.id).toBe(stc.id);
    expect(entry.verified).toBe(true);
    expect(entry.packageName).toBe('@test/pkg-a');

    const retrieved = store.get(stc.id);
    expect(retrieved).toBeDefined();
    expect(retrieved!.trustScore).toBe(stc.trustScore.overall);
  });

  it('gets latest for package', async () => {
    const store = new CertificateStore();
    const stc1 = await makeTestSTC('@test/pkg-b', '1.0.0');
    const stc2 = await makeTestSTC('@test/pkg-b', '2.0.0');

    await store.register(stc1);
    await store.register(stc2);

    const latest = store.getLatestForPackage('@test/pkg-b');
    expect(latest).toBeDefined();
    expect(latest!.packageVersion).toBe('2.0.0');
  });

  it('queries with filters', async () => {
    const store = new CertificateStore();
    await store.register(await makeTestSTC('@test/a'));
    await store.register(await makeTestSTC('@test/b'));

    const all = store.query({});
    expect(all.length).toBe(2);

    const filtered = store.query({ packageName: '@test/a' });
    expect(filtered.length).toBe(1);
    expect(filtered[0].packageName).toBe('@test/a');
  });

  it('removes a certificate', async () => {
    const store = new CertificateStore();
    const stc = await makeTestSTC('@test/removable');
    await store.register(stc);

    expect(store.count()).toBe(1);
    const removed = await store.remove(stc.id);
    expect(removed).toBe(true);
    expect(store.count()).toBe(0);
    expect(store.get(stc.id)).toBeUndefined();
  });

  it('provides stats', async () => {
    const store = new CertificateStore();
    await store.register(await makeTestSTC('@test/stats-a'));
    await store.register(await makeTestSTC('@test/stats-b'));

    const stats = store.getStats();
    expect(stats.totalCertificates).toBe(2);
    expect(stats.verifiedCertificates).toBe(2);
    expect(stats.uniquePackages).toBe(2);
    expect(stats.averageScore).toBeGreaterThan(0);
  });
});

// ─── Badge Tests ──────────────────────────────────────────────────────

describe('Badge SVG', () => {
  it('generates grade badge', () => {
    const svg = gradeBadge('A');
    expect(svg).toContain('<svg');
    expect(svg).toContain('Grade A');
    expect(svg).toContain('#4c1'); // green
  });

  it('generates score badge', () => {
    const svg = scoreBadge(87);
    expect(svg).toContain('87/100');
  });

  it('generates verified badge', () => {
    const svg = verifiedBadge(true);
    expect(svg).toContain('Verified');
  });

  it('generates not-found badge', () => {
    const svg = notFoundBadge();
    expect(svg).toContain('Not Found');
    expect(svg).toContain('#9f9f9f'); // gray
  });

  it('supports flat-square style', () => {
    const svg = gradeBadge('B', 'flat-square');
    expect(svg).toContain('rx="0"'); // no border radius
  });
});

// ─── Server Tests ─────────────────────────────────────────────────────

let nextPort = 18200;
function getPort() { return nextPort++; }

describe('RegistryServer', () => {
  let server: RegistryServer | null = null;

  afterEach(async () => {
    if (server) { await server.stop(); server = null; }
  });

  it('starts and responds to /health', async () => {
    const port = getPort();
    server = new RegistryServer({ port });
    await server.start();

    const res = await fetch(`http://localhost:${port}/health`);
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.status).toBe('ok');
  });

  it('registers and retrieves a certificate via API', async () => {
    const port = getPort();
    server = new RegistryServer({ port });
    await server.start();

    const stc = await makeTestSTC('@test/api-pkg');

    // Register
    const postRes = await fetch(`http://localhost:${port}/api/v1/certificates`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(stc),
    });
    expect(postRes.status).toBe(201);
    const postBody = await postRes.json() as any;
    expect(postBody.id).toBe(stc.id);
    expect(postBody.verified).toBe(true);

    // Get by ID
    const getRes = await fetch(`http://localhost:${port}/api/v1/certificates/${encodeURIComponent(stc.id)}`);
    expect(getRes.status).toBe(200);
    const getBody = await getRes.json() as any;
    expect(getBody.packageName).toBe('@test/api-pkg');
  });

  it('rejects duplicate registration', async () => {
    const port = getPort();
    server = new RegistryServer({ port });
    await server.start();

    const stc = await makeTestSTC('@test/dup-pkg');

    await fetch(`http://localhost:${port}/api/v1/certificates`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(stc),
    });

    const res2 = await fetch(`http://localhost:${port}/api/v1/certificates`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(stc),
    });
    expect(res2.status).toBe(409);
  });

  it('serves grade badge for a package', async () => {
    const port = getPort();
    server = new RegistryServer({ port });
    await server.start();

    const stc = await makeTestSTC('@test/badge-pkg');
    await fetch(`http://localhost:${port}/api/v1/certificates`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(stc),
    });

    const badgeRes = await fetch(`http://localhost:${port}/api/v1/packages/${encodeURIComponent('@test/badge-pkg')}/badge`);
    expect(badgeRes.status).toBe(200);
    expect(badgeRes.headers.get('content-type')).toBe('image/svg+xml');
    const svg = await badgeRes.text();
    expect(svg).toContain('<svg');
    expect(svg).toContain('Grade');
  });

  it('serves not-found badge for unknown package', async () => {
    const port = getPort();
    server = new RegistryServer({ port });
    await server.start();

    const badgeRes = await fetch(`http://localhost:${port}/api/v1/packages/${encodeURIComponent('@test/unknown')}/badge`);
    expect(badgeRes.status).toBe(200);
    const svg = await badgeRes.text();
    expect(svg).toContain('Not Found');
  });

  it('queries certificates with filters', async () => {
    const port = getPort();
    server = new RegistryServer({ port });
    await server.start();

    await fetch(`http://localhost:${port}/api/v1/certificates`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(await makeTestSTC('@test/q1')),
    });
    await fetch(`http://localhost:${port}/api/v1/certificates`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(await makeTestSTC('@test/q2')),
    });

    const res = await fetch(`http://localhost:${port}/api/v1/certificates?package=@test/q1`);
    const body = await res.json() as any;
    expect(body.count).toBe(1);
    expect(body.certificates[0].packageName).toBe('@test/q1');
  });

  it('deletes a certificate', async () => {
    const port = getPort();
    server = new RegistryServer({ port });
    await server.start();

    const stc = await makeTestSTC('@test/del-pkg');
    await fetch(`http://localhost:${port}/api/v1/certificates`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(stc),
    });

    const delRes = await fetch(`http://localhost:${port}/api/v1/certificates/${encodeURIComponent(stc.id)}`, {
      method: 'DELETE',
    });
    expect(delRes.status).toBe(200);

    const getRes = await fetch(`http://localhost:${port}/api/v1/certificates/${encodeURIComponent(stc.id)}`);
    expect(getRes.status).toBe(404);
  });

  it('returns stats', async () => {
    const port = getPort();
    server = new RegistryServer({ port });
    await server.start();

    await fetch(`http://localhost:${port}/api/v1/certificates`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(await makeTestSTC('@test/stats-pkg')),
    });

    const res = await fetch(`http://localhost:${port}/api/v1/stats`);
    const stats = await res.json() as any;
    expect(stats.totalCertificates).toBe(1);
    expect(stats.verifiedCertificates).toBe(1);
  });
});
