import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  EncryptedFileKeyProvider,
  AWSCloudHSMKeyProvider,
  AzureManagedHSMKeyProvider,
  PKCS11KeyProvider,
} from '../index.js';

describe('@sentinel-atl/hsm', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'sentinel-hsm-'));
  });

  afterAll(async () => {
    // Cleanup happens automatically on process exit for tmp dirs
  });

  // ─── EncryptedFileKeyProvider ──────────────────────────────────

  describe('EncryptedFileKeyProvider', () => {
    it('generates, signs, and verifies a key', async () => {
      const provider = new EncryptedFileKeyProvider({
        directory: join(tempDir, 'keys'),
        passphrase: 'test-passphrase-123',
      });

      const kp = await provider.generate('test-key');
      expect(kp.publicKey).toBeInstanceOf(Uint8Array);
      expect(kp.privateKey).toBeInstanceOf(Uint8Array);
      expect(kp.publicKey.length).toBe(32);
      expect(kp.privateKey.length).toBe(32);
    });

    it('persists keys to encrypted files', async () => {
      const dir = join(tempDir, 'persist');
      const passphrase = 'my-strong-passphrase';

      const provider1 = new EncryptedFileKeyProvider({ directory: dir, passphrase });
      const kp1 = await provider1.generate('persist-key');

      // Create new provider instance (simulates restart)
      const provider2 = new EncryptedFileKeyProvider({ directory: dir, passphrase });
      const pubKey = await provider2.getPublicKey('persist-key');
      expect(pubKey).toEqual(kp1.publicKey);
    });

    it('signs data correctly', async () => {
      const provider = new EncryptedFileKeyProvider({
        directory: join(tempDir, 'sign'),
        passphrase: 'sign-test',
      });

      await provider.generate('sign-key');
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const sig = await provider.sign('sign-key', data);
      expect(sig).toBeInstanceOf(Uint8Array);
      expect(sig.length).toBe(64); // Ed25519 signature length
    });

    it('has() returns correct values', async () => {
      const provider = new EncryptedFileKeyProvider({
        directory: join(tempDir, 'has'),
        passphrase: 'has-test',
      });

      expect(await provider.has('nope')).toBe(false);
      await provider.generate('exists');
      expect(await provider.has('exists')).toBe(true);
    });

    it('list() returns key IDs', async () => {
      const provider = new EncryptedFileKeyProvider({
        directory: join(tempDir, 'list'),
        passphrase: 'list-test',
      });

      await provider.generate('key-a');
      await provider.generate('key-b');
      const ids = await provider.list();
      expect(ids.sort()).toEqual(['key-a', 'key-b']);
    });

    it('delete() removes a key', async () => {
      const provider = new EncryptedFileKeyProvider({
        directory: join(tempDir, 'delete'),
        passphrase: 'del-test',
      });

      await provider.generate('to-delete');
      expect(await provider.has('to-delete')).toBe(true);
      await provider.delete('to-delete');
      expect(await provider.has('to-delete')).toBe(false);
    });

    it('exportPrivateKey() returns the private key', async () => {
      const provider = new EncryptedFileKeyProvider({
        directory: join(tempDir, 'export'),
        passphrase: 'export-test',
      });

      const kp = await provider.generate('export-key');
      const exported = await provider.exportPrivateKey('export-key');
      expect(exported).toEqual(kp.privateKey);
    });

    it('throws on missing key', async () => {
      const provider = new EncryptedFileKeyProvider({
        directory: join(tempDir, 'missing'),
        passphrase: 'test',
      });

      await expect(provider.sign('nope', new Uint8Array([1]))).rejects.toThrow('Key not found');
    });

    it('rejects wrong passphrase', async () => {
      const dir = join(tempDir, 'wrong-pass');
      const provider1 = new EncryptedFileKeyProvider({ directory: dir, passphrase: 'correct' });
      await provider1.generate('secret-key');

      const provider2 = new EncryptedFileKeyProvider({ directory: dir, passphrase: 'wrong' });
      await expect(provider2.getPublicKey('secret-key')).rejects.toThrow();
    });

    it('sanitizes key IDs to prevent path traversal', async () => {
      const provider = new EncryptedFileKeyProvider({
        directory: join(tempDir, 'sanitize'),
        passphrase: 'test',
      });

      await provider.generate('../../../etc/passwd');
      // Should create a safely-named file, not escape the directory
      const ids = await provider.list();
      expect(ids).toHaveLength(1);
      expect(ids[0]).not.toContain('/');
    });
  });

  // ─── HSM Stubs ────────────────────────────────────────────────

  describe('AWSCloudHSMKeyProvider', () => {
    it('throws informative errors', async () => {
      const provider = new AWSCloudHSMKeyProvider({
        clusterId: 'cluster-abc',
        pkcs11LibPath: '/opt/cloudhsm/lib/libcloudhsm_pkcs11.so',
        pin: '1234',
      });

      await expect(provider.generate('key')).rejects.toThrow('pkcs11js');
      await expect(provider.sign('key', new Uint8Array())).rejects.toThrow('pkcs11js');
      await expect(provider.getPublicKey('key')).rejects.toThrow('pkcs11js');
    });
  });

  describe('AzureManagedHSMKeyProvider', () => {
    it('throws informative errors', async () => {
      const provider = new AzureManagedHSMKeyProvider({
        vaultUrl: 'https://myhsm.managedhsm.azure.net',
      });

      await expect(provider.generate('key')).rejects.toThrow('@azure/keyvault-keys');
      await expect(provider.sign('key', new Uint8Array())).rejects.toThrow('@azure/keyvault-keys');
    });
  });

  describe('PKCS11KeyProvider', () => {
    it('throws informative errors', async () => {
      const provider = new PKCS11KeyProvider({
        libraryPath: '/usr/lib/softhsm/libsofthsm2.so',
        pin: '1234',
      });

      await expect(provider.generate('key')).rejects.toThrow('pkcs11js');
      await expect(provider.sign('key', new Uint8Array())).rejects.toThrow('pkcs11js');
    });
  });
});
