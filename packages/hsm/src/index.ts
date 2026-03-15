/**
 * @sentinel/hsm — HSM and secure KeyProvider backends.
 *
 * Provides production-grade KeyProvider implementations:
 * - EncryptedFileKeyProvider  — AES-256-GCM encrypted file storage (Node crypto)
 * - AWSCloudHSMKeyProvider    — AWS CloudHSM (stub, requires pkcs11js)
 * - AzureManagedHSMKeyProvider — Azure Managed HSM (stub, requires @azure/keyvault-keys)
 * - PKCS11KeyProvider         — Generic PKCS#11 interface (stub, requires pkcs11js)
 *
 * The EncryptedFileKeyProvider is fully functional with zero external deps.
 * HSM stubs provide the correct interface and throw clear "configure SDK" errors.
 */

import type { KeyProvider } from '@sentinel/core';
import { createHash, createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';

// ─── KeyPair type (matches @sentinel/core) ───────────────────────

interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

// ─── EncryptedFileKeyProvider ────────────────────────────────────

export interface EncryptedFileConfig {
  /** Directory to store encrypted key files */
  directory: string;
  /** Passphrase for key derivation (use a strong passphrase!) */
  passphrase: string;
  /** Optional: scrypt cost parameter (default: 2^14) */
  scryptN?: number;
}

/**
 * EncryptedFileKeyProvider — stores Ed25519 keys as AES-256-GCM encrypted files.
 *
 * Each key is stored as a separate .key file:
 *   {directory}/{id}.key → { salt, iv, tag, ciphertext } (JSON)
 *
 * Key derivation: scrypt(passphrase, salt) → 32-byte AES key
 * Encryption: AES-256-GCM with random IV per key
 */
export class EncryptedFileKeyProvider implements KeyProvider {
  private directory: string;
  private passphrase: string;
  private scryptN: number;
  private cache = new Map<string, KeyPair>();

  constructor(config: EncryptedFileConfig) {
    this.directory = config.directory;
    this.passphrase = config.passphrase;
    this.scryptN = config.scryptN ?? 16384; // 2^14
    if (!existsSync(this.directory)) {
      mkdirSync(this.directory, { recursive: true });
    }
  }

  async generate(id: string): Promise<KeyPair> {
    const ed = await import('@noble/ed25519');
    const privKey = randomBytes(32);
    const pubKey = await ed.getPublicKeyAsync(privKey);
    const kp: KeyPair = { publicKey: pubKey, privateKey: new Uint8Array(privKey) };
    this.encryptAndStore(id, kp);
    this.cache.set(id, kp);
    return kp;
  }

  async sign(id: string, data: Uint8Array): Promise<Uint8Array> {
    const kp = await this.loadKey(id);
    const ed = await import('@noble/ed25519');
    return ed.signAsync(data, kp.privateKey);
  }

  async getPublicKey(id: string): Promise<Uint8Array> {
    const kp = await this.loadKey(id);
    return kp.publicKey;
  }

  async has(id: string): Promise<boolean> {
    if (this.cache.has(id)) return true;
    return existsSync(this.keyPath(id));
  }

  async delete(id: string): Promise<void> {
    this.cache.delete(id);
    const path = this.keyPath(id);
    if (existsSync(path)) {
      const { unlinkSync } = await import('node:fs');
      unlinkSync(path);
    }
  }

  async list(): Promise<string[]> {
    const { readdirSync } = await import('node:fs');
    const files = readdirSync(this.directory);
    return files
      .filter(f => f.endsWith('.key'))
      .map(f => f.slice(0, -4));
  }

  async exportPrivateKey(id: string): Promise<Uint8Array> {
    const kp = await this.loadKey(id);
    return kp.privateKey;
  }

  // ─── Internal helpers ────────────────────────────────────────

  private keyPath(id: string): string {
    // Sanitize id to prevent path traversal
    const safeId = id.replace(/[^a-zA-Z0-9_-]/g, '_');
    return join(this.directory, `${safeId}.key`);
  }

  private deriveKey(salt: Buffer): Buffer {
    return scryptSync(this.passphrase, salt, 32, { N: this.scryptN, r: 8, p: 1 }) as Buffer;
  }

  private encryptAndStore(id: string, kp: KeyPair): void {
    const salt = randomBytes(16);
    const aesKey = this.deriveKey(salt);
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', aesKey, iv);

    // Concatenate pub + priv for storage
    const plaintext = Buffer.concat([
      Buffer.from(kp.publicKey),
      Buffer.from(kp.privateKey),
    ]);

    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    const stored = {
      salt: salt.toString('hex'),
      iv: iv.toString('hex'),
      tag: tag.toString('hex'),
      ciphertext: ciphertext.toString('hex'),
      pubKeyLen: kp.publicKey.length,
    };

    writeFileSync(this.keyPath(id), JSON.stringify(stored), 'utf-8');
  }

  private async loadKey(id: string): Promise<KeyPair> {
    if (this.cache.has(id)) return this.cache.get(id)!;

    const path = this.keyPath(id);
    if (!existsSync(path)) throw new Error(`Key not found: ${id}`);

    const raw = JSON.parse(readFileSync(path, 'utf-8'));
    const salt = Buffer.from(raw.salt, 'hex');
    const iv = Buffer.from(raw.iv, 'hex');
    const tag = Buffer.from(raw.tag, 'hex');
    const ciphertext = Buffer.from(raw.ciphertext, 'hex');

    const aesKey = this.deriveKey(salt);
    const decipher = createDecipheriv('aes-256-gcm', aesKey, iv);
    decipher.setAuthTag(tag);

    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const publicKey = new Uint8Array(plaintext.subarray(0, raw.pubKeyLen));
    const privateKey = new Uint8Array(plaintext.subarray(raw.pubKeyLen));

    const kp: KeyPair = { publicKey, privateKey };
    this.cache.set(id, kp);
    return kp;
  }
}

// ─── AWS CloudHSM KeyProvider (stub) ────────────────────────────

export interface AWSCloudHSMConfig {
  /** CloudHSM cluster ID */
  clusterId: string;
  /** PKCS#11 library path (e.g., /opt/cloudhsm/lib/libcloudhsm_pkcs11.so) */
  pkcs11LibPath: string;
  /** HSM user PIN */
  pin: string;
}

/**
 * AWSCloudHSMKeyProvider — interface for AWS CloudHSM.
 *
 * Requires the `pkcs11js` npm package and a configured CloudHSM cluster.
 * This stub provides the correct KeyProvider interface; actual HSM operations
 * require the PKCS#11 library to be installed and configured.
 */
export class AWSCloudHSMKeyProvider implements KeyProvider {
  private config: AWSCloudHSMConfig;

  constructor(config: AWSCloudHSMConfig) {
    this.config = config;
  }

  async generate(id: string): Promise<KeyPair> {
    throw new Error(
      `AWSCloudHSMKeyProvider.generate(): Requires pkcs11js package and CloudHSM cluster "${this.config.clusterId}". ` +
      'Install pkcs11js and configure your cluster to use this provider.'
    );
  }

  async sign(id: string, data: Uint8Array): Promise<Uint8Array> {
    throw new Error(
      'AWSCloudHSMKeyProvider.sign(): Requires pkcs11js. Keys never leave the HSM.'
    );
  }

  async getPublicKey(id: string): Promise<Uint8Array> {
    throw new Error(
      'AWSCloudHSMKeyProvider.getPublicKey(): Requires pkcs11js.'
    );
  }

  async has(id: string): Promise<boolean> {
    throw new Error('AWSCloudHSMKeyProvider.has(): Requires pkcs11js.');
  }

  async delete(id: string): Promise<void> {
    throw new Error('AWSCloudHSMKeyProvider.delete(): Requires pkcs11js.');
  }

  async list(): Promise<string[]> {
    throw new Error('AWSCloudHSMKeyProvider.list(): Requires pkcs11js.');
  }
}

// ─── Azure Managed HSM KeyProvider (stub) ────────────────────────

export interface AzureManagedHSMConfig {
  /** HSM vault URL (e.g., https://myhsm.managedhsm.azure.net) */
  vaultUrl: string;
  /** Optional: Azure credential (DefaultAzureCredential used if omitted) */
  credential?: unknown;
}

/**
 * AzureManagedHSMKeyProvider — interface for Azure Managed HSM.
 *
 * Requires @azure/keyvault-keys and @azure/identity packages.
 * Keys are stored in Azure Managed HSM; signing happens server-side.
 */
export class AzureManagedHSMKeyProvider implements KeyProvider {
  private config: AzureManagedHSMConfig;

  constructor(config: AzureManagedHSMConfig) {
    this.config = config;
  }

  async generate(id: string): Promise<KeyPair> {
    throw new Error(
      `AzureManagedHSMKeyProvider.generate(): Requires @azure/keyvault-keys. ` +
      `HSM URL: ${this.config.vaultUrl}`
    );
  }

  async sign(id: string, data: Uint8Array): Promise<Uint8Array> {
    throw new Error(
      'AzureManagedHSMKeyProvider.sign(): Requires @azure/keyvault-keys. Signing happens server-side.'
    );
  }

  async getPublicKey(id: string): Promise<Uint8Array> {
    throw new Error('AzureManagedHSMKeyProvider.getPublicKey(): Requires @azure/keyvault-keys.');
  }

  async has(id: string): Promise<boolean> {
    throw new Error('AzureManagedHSMKeyProvider.has(): Requires @azure/keyvault-keys.');
  }

  async delete(id: string): Promise<void> {
    throw new Error('AzureManagedHSMKeyProvider.delete(): Requires @azure/keyvault-keys.');
  }

  async list(): Promise<string[]> {
    throw new Error('AzureManagedHSMKeyProvider.list(): Requires @azure/keyvault-keys.');
  }
}

// ─── PKCS#11 KeyProvider (stub) ─────────────────────────────────

export interface PKCS11Config {
  /** Path to the PKCS#11 shared library */
  libraryPath: string;
  /** Slot index to use */
  slotIndex?: number;
  /** User PIN for authentication */
  pin: string;
}

/**
 * PKCS11KeyProvider — generic PKCS#11 interface for any HSM.
 *
 * Requires the `pkcs11js` npm package and a PKCS#11-compatible HSM.
 * Works with YubiKey, SoftHSM, Thales Luna, nCipher, etc.
 */
export class PKCS11KeyProvider implements KeyProvider {
  private config: PKCS11Config;

  constructor(config: PKCS11Config) {
    this.config = config;
  }

  async generate(id: string): Promise<KeyPair> {
    throw new Error(
      `PKCS11KeyProvider.generate(): Requires pkcs11js and library at "${this.config.libraryPath}".`
    );
  }

  async sign(id: string, data: Uint8Array): Promise<Uint8Array> {
    throw new Error('PKCS11KeyProvider.sign(): Requires pkcs11js.');
  }

  async getPublicKey(id: string): Promise<Uint8Array> {
    throw new Error('PKCS11KeyProvider.getPublicKey(): Requires pkcs11js.');
  }

  async has(id: string): Promise<boolean> {
    throw new Error('PKCS11KeyProvider.has(): Requires pkcs11js.');
  }

  async delete(id: string): Promise<void> {
    throw new Error('PKCS11KeyProvider.delete(): Requires pkcs11js.');
  }

  async list(): Promise<string[]> {
    throw new Error('PKCS11KeyProvider.list(): Requires pkcs11js.');
  }
}
