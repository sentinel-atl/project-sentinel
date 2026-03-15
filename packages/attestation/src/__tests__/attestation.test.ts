import { describe, it, expect, beforeEach } from 'vitest';
import { AttestationManager, hashCode, hashDirectory } from '../index.js';
import {
  InMemoryKeyProvider,
  publicKeyToDid,
} from '@sentinel-atl/core';
import { mkdtemp, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

async function makeIdentity(keyProvider: InMemoryKeyProvider, name: string) {
  await keyProvider.generate(name);
  const pubKey = await keyProvider.getPublicKey(name);
  const did = publicKeyToDid(pubKey);
  return { keyId: name, did };
}

describe('@sentinel-atl/attestation', () => {
  let keyProvider: InMemoryKeyProvider;
  let manager: AttestationManager;
  let agent: { keyId: string; did: string };

  beforeEach(async () => {
    keyProvider = new InMemoryKeyProvider();
    manager = new AttestationManager();
    agent = await makeIdentity(keyProvider, 'agent');
  });

  // ─── hashCode ──────────────────────────────────────────────────────

  describe('hashCode', () => {
    it('hashes a string deterministically', () => {
      const h1 = hashCode('console.log("hello")');
      const h2 = hashCode('console.log("hello")');
      expect(h1).toBe(h2);
      expect(h1).toHaveLength(64); // SHA-256 hex
    });

    it('produces different hashes for different code', () => {
      const h1 = hashCode('console.log("hello")');
      const h2 = hashCode('console.log("world")');
      expect(h1).not.toBe(h2);
    });
  });

  // ─── hashDirectory ────────────────────────────────────────────────

  describe('hashDirectory', () => {
    it('hashes a directory of files deterministically', async () => {
      const dir = await mkdtemp(join(tmpdir(), 'sentinel-attest-'));
      await writeFile(join(dir, 'main.ts'), 'export function agent() {}');
      await writeFile(join(dir, 'utils.ts'), 'export function helper() {}');

      const r1 = await hashDirectory(dir);
      const r2 = await hashDirectory(dir);

      expect(r1.codeHash).toBe(r2.codeHash);
      expect(r1.codeHash).toHaveLength(64);
      expect(r1.includedFiles).toEqual(['main.ts', 'utils.ts']);
    });

    it('changes hash when file content changes', async () => {
      const dir = await mkdtemp(join(tmpdir(), 'sentinel-attest-'));
      await writeFile(join(dir, 'main.ts'), 'version 1');
      const r1 = await hashDirectory(dir);

      await writeFile(join(dir, 'main.ts'), 'version 2');
      const r2 = await hashDirectory(dir);

      expect(r1.codeHash).not.toBe(r2.codeHash);
    });

    it('filters by extension', async () => {
      const dir = await mkdtemp(join(tmpdir(), 'sentinel-attest-'));
      await writeFile(join(dir, 'main.ts'), 'typescript');
      await writeFile(join(dir, 'readme.md'), 'markdown');

      const result = await hashDirectory(dir, { extensions: ['.ts'] });
      expect(result.includedFiles).toEqual(['main.ts']);
    });

    it('excludes directories', async () => {
      const dir = await mkdtemp(join(tmpdir(), 'sentinel-attest-'));
      await writeFile(join(dir, 'main.ts'), 'src');
      await mkdir(join(dir, 'node_modules'));
      await writeFile(join(dir, 'node_modules', 'dep.js'), 'dep');

      const result = await hashDirectory(dir, { exclude: ['node_modules'] });
      expect(result.includedFiles).toEqual(['main.ts']);
    });
  });

  // ─── Attestation signing and verification ──────────────────────────

  describe('attestation', () => {
    it('creates and verifies a code attestation', async () => {
      const codeHash = hashCode('my agent code');

      const attestation = await manager.attest(
        keyProvider, agent.keyId, agent.did,
        codeHash, ['main.ts'],
        { version: '1.0.0', commitHash: 'abc123' }
      );

      expect(attestation.agentDid).toBe(agent.did);
      expect(attestation.codeHash).toBe(codeHash);
      expect(attestation.version).toBe('1.0.0');
      expect(attestation.commitHash).toBe('abc123');
      expect(attestation.signature).toBeDefined();

      const result = await manager.verify(attestation);
      expect(result.valid).toBe(true);
      expect(result.codeHash).toBe(codeHash);
    });

    it('detects tampered attestation', async () => {
      const attestation = await manager.attest(
        keyProvider, agent.keyId, agent.did,
        hashCode('original'), ['main.ts']
      );

      // Tamper: change the code hash
      attestation.codeHash = hashCode('tampered');

      const result = await manager.verify(attestation);
      expect(result.valid).toBe(false);
    });

    it('verifies code hash match', async () => {
      const codeHash = hashCode('my agent code');

      await manager.attest(
        keyProvider, agent.keyId, agent.did,
        codeHash, ['main.ts']
      );

      const match = await manager.verifyCodeHash(agent.did, codeHash);
      expect(match.match).toBe(true);
    });

    it('detects code hash mismatch', async () => {
      await manager.attest(
        keyProvider, agent.keyId, agent.did,
        hashCode('version 1'), ['main.ts']
      );

      const result = await manager.verifyCodeHash(agent.did, hashCode('version 2'));
      expect(result.match).toBe(false);
      expect(result.error).toContain('Code hash mismatch');
    });

    it('returns error for unknown agent', async () => {
      const result = await manager.verifyCodeHash('did:key:z6MkUnknown', hashCode('x'));
      expect(result.match).toBe(false);
      expect(result.error).toContain('No attestation found');
    });

    it('stores and retrieves attestations', async () => {
      await manager.attest(
        keyProvider, agent.keyId, agent.did,
        hashCode('code'), ['main.ts']
      );

      expect(manager.getAttestation(agent.did)).toBeDefined();
      expect(manager.getAllAttestations()).toHaveLength(1);
    });

    it('updates attestation on re-attestation', async () => {
      await manager.attest(
        keyProvider, agent.keyId, agent.did,
        hashCode('v1'), ['main.ts'], { version: '1.0' }
      );
      await manager.attest(
        keyProvider, agent.keyId, agent.did,
        hashCode('v2'), ['main.ts'], { version: '2.0' }
      );

      const att = manager.getAttestation(agent.did);
      expect(att?.version).toBe('2.0');
      expect(manager.getAllAttestations()).toHaveLength(1);
    });
  });
});
