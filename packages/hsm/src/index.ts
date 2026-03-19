/**
 * @sentinel-atl/hsm — HSM and secure KeyProvider backends.
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

import type { KeyProvider } from '@sentinel-atl/core';
import { createHash, createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';

// ─── KeyPair type (matches @sentinel-atl/core) ───────────────────────

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
 * Uses PKCS#11 to perform Ed25519 key operations inside the HSM.
 * Keys never leave the HSM boundary; only public keys are exported.
 */
export class AWSCloudHSMKeyProvider implements KeyProvider {
  private config: AWSCloudHSMConfig;
  private pkcs11: any;
  private session: any;
  private handles = new Map<string, { privHandle: any; pubHandle: any }>();

  constructor(config: AWSCloudHSMConfig) {
    this.config = config;
  }

  private async ensureSession(): Promise<void> {
    if (this.session) return;
    let pkcs11js: any;
    try {
      pkcs11js = await import('pkcs11js');
    } catch {
      throw new Error(
        'AWSCloudHSMKeyProvider requires the "pkcs11js" package. Install it with: npm install pkcs11js'
      );
    }
    const PKCS11 = pkcs11js.PKCS11 ?? pkcs11js.default?.PKCS11 ?? pkcs11js;
    this.pkcs11 = new PKCS11();
    this.pkcs11.load(this.config.pkcs11LibPath);
    this.pkcs11.C_Initialize();
    const slots = this.pkcs11.C_GetSlotList(true);
    if (slots.length === 0) throw new Error('No PKCS#11 slots available on CloudHSM cluster');
    this.session = this.pkcs11.C_OpenSession(slots[0], 6 /* RW_SESSION | SERIAL_SESSION */);
    this.pkcs11.C_Login(this.session, 1 /* CKU_USER */, this.config.pin);
  }

  async generate(id: string): Promise<KeyPair> {
    await this.ensureSession();
    const pubTemplate = [
      { type: 0x0000_0003, value: true },   // CKA_TOKEN
      { type: 0x0000_0100, value: id },      // CKA_LABEL
      { type: 0x0000_0162, value: Buffer.from([0x13, 0x0c]) }, // CKA_EC_PARAMS (Ed25519 OID)
    ];
    const privTemplate = [
      { type: 0x0000_0003, value: true },   // CKA_TOKEN
      { type: 0x0000_0100, value: id },      // CKA_LABEL
      { type: 0x0000_0004, value: true },   // CKA_PRIVATE
      { type: 0x0000_0108, value: true },   // CKA_SIGN
      { type: 0x0000_0164, value: false },  // CKA_EXTRACTABLE
    ];
    const { hPublicKey, hPrivateKey } = this.pkcs11.C_GenerateKeyPair(
      this.session,
      { mechanism: 0x0000_1057 /* CKM_EC_EDWARDS_KEY_PAIR_GEN */ },
      pubTemplate,
      privTemplate,
    );
    this.handles.set(id, { privHandle: hPrivateKey, pubHandle: hPublicKey });
    const pubBytes = this.pkcs11.C_GetAttributeValue(this.session, hPublicKey, [
      { type: 0x0000_0161 /* CKA_EC_POINT */ },
    ]);
    const rawPub = pubBytes[0].value.slice(-32);
    return { publicKey: new Uint8Array(rawPub), privateKey: new Uint8Array(0) };
  }

  async sign(id: string, data: Uint8Array): Promise<Uint8Array> {
    await this.ensureSession();
    const handles = await this.findKey(id);
    this.pkcs11.C_SignInit(this.session, { mechanism: 0x0000_1057 }, handles.privHandle);
    const sig = this.pkcs11.C_Sign(this.session, Buffer.from(data), Buffer.alloc(64));
    return new Uint8Array(sig);
  }

  async getPublicKey(id: string): Promise<Uint8Array> {
    await this.ensureSession();
    const handles = await this.findKey(id);
    const attrs = this.pkcs11.C_GetAttributeValue(this.session, handles.pubHandle, [
      { type: 0x0000_0161 },
    ]);
    return new Uint8Array(attrs[0].value.slice(-32));
  }

  async has(id: string): Promise<boolean> {
    try {
      await this.findKey(id);
      return true;
    } catch {
      return false;
    }
  }

  async delete(id: string): Promise<void> {
    await this.ensureSession();
    const handles = await this.findKey(id);
    this.pkcs11.C_DestroyObject(this.session, handles.privHandle);
    this.pkcs11.C_DestroyObject(this.session, handles.pubHandle);
    this.handles.delete(id);
  }

  async list(): Promise<string[]> {
    await this.ensureSession();
    this.pkcs11.C_FindObjectsInit(this.session, [{ type: 0x0000_0003, value: true }]);
    const labels: string[] = [];
    let obj;
    while ((obj = this.pkcs11.C_FindObjects(this.session))) {
      const attrs = this.pkcs11.C_GetAttributeValue(this.session, obj, [{ type: 0x0000_0100 }]);
      labels.push(attrs[0].value.toString());
    }
    this.pkcs11.C_FindObjectsFinal(this.session);
    return labels;
  }

  private async findKey(id: string): Promise<{ privHandle: any; pubHandle: any }> {
    const cached = this.handles.get(id);
    if (cached) return cached;
    await this.ensureSession();
    // Find by label
    this.pkcs11.C_FindObjectsInit(this.session, [
      { type: 0x0000_0100, value: id },
    ]);
    const objs: any[] = [];
    let obj;
    while ((obj = this.pkcs11.C_FindObjects(this.session))) objs.push(obj);
    this.pkcs11.C_FindObjectsFinal(this.session);
    if (objs.length < 2) throw new Error(`Key not found in CloudHSM: ${id}`);
    this.handles.set(id, { privHandle: objs[0], pubHandle: objs[1] });
    return this.handles.get(id)!;
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
 * Keys are stored in Azure Managed HSM; signing happens server-side
 * via the Azure Key Vault Crypto Client. Keys never leave the HSM.
 */
export class AzureManagedHSMKeyProvider implements KeyProvider {
  private config: AzureManagedHSMConfig;
  private client: any;
  private cryptoClients = new Map<string, any>();

  constructor(config: AzureManagedHSMConfig) {
    this.config = config;
  }

  private async ensureClient(): Promise<void> {
    if (this.client) return;
    let kvKeys: any;
    let identity: any;
    try {
      kvKeys = await import('@azure/keyvault-keys');
    } catch {
      throw new Error(
        'AzureManagedHSMKeyProvider requires "@azure/keyvault-keys". Install it with: npm install @azure/keyvault-keys'
      );
    }
    try {
      identity = await import('@azure/identity');
    } catch {
      throw new Error(
        'AzureManagedHSMKeyProvider requires "@azure/identity". Install it with: npm install @azure/identity'
      );
    }
    const credential = this.config.credential ?? new identity.DefaultAzureCredential();
    this.client = new kvKeys.KeyClient(this.config.vaultUrl, credential);
  }

  private async getCryptoClient(id: string): Promise<any> {
    const cached = this.cryptoClients.get(id);
    if (cached) return cached;
    await this.ensureClient();
    const kvKeys = await import('@azure/keyvault-keys');
    const key = await this.client.getKey(id);
    const identity = await import('@azure/identity');
    const credential = this.config.credential ?? new identity.DefaultAzureCredential();
    const crypto = new kvKeys.CryptographyClient(key, credential);
    this.cryptoClients.set(id, crypto);
    return crypto;
  }

  async generate(id: string): Promise<KeyPair> {
    await this.ensureClient();
    const key = await this.client.createKey(id, 'EC', {
      curve: 'Ed25519',
      keyOps: ['sign', 'verify'],
      hsm: true,
    });
    // Extract the public key bytes from the JWK
    const xBytes = key.key?.x;
    const publicKey = xBytes ? new Uint8Array(Buffer.from(xBytes, 'base64url')) : new Uint8Array(32);
    // Private key never leaves HSM — return empty
    return { publicKey, privateKey: new Uint8Array(0) };
  }

  async sign(id: string, data: Uint8Array): Promise<Uint8Array> {
    const crypto = await this.getCryptoClient(id);
    const result = await crypto.sign('EdDSA', data);
    return new Uint8Array(result.result);
  }

  async getPublicKey(id: string): Promise<Uint8Array> {
    await this.ensureClient();
    const key = await this.client.getKey(id);
    const xBytes = key.key?.x;
    if (!xBytes) throw new Error(`No public key found for ${id}`);
    return new Uint8Array(Buffer.from(xBytes, 'base64url'));
  }

  async has(id: string): Promise<boolean> {
    try {
      await this.ensureClient();
      await this.client.getKey(id);
      return true;
    } catch {
      return false;
    }
  }

  async delete(id: string): Promise<void> {
    await this.ensureClient();
    const poller = await this.client.beginDeleteKey(id);
    await poller.pollUntilDone();
    this.cryptoClients.delete(id);
  }

  async list(): Promise<string[]> {
    await this.ensureClient();
    const keys: string[] = [];
    for await (const keyProperties of this.client.listPropertiesOfKeys()) {
      keys.push(keyProperties.name);
    }
    return keys;
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
  private pkcs11: any;
  private session: any;
  private handles = new Map<string, { privHandle: any; pubHandle: any }>();

  constructor(config: PKCS11Config) {
    this.config = config;
  }

  private async ensureSession(): Promise<void> {
    if (this.session) return;
    let pkcs11js: any;
    try {
      pkcs11js = await import('pkcs11js');
    } catch {
      throw new Error(
        'PKCS11KeyProvider requires the "pkcs11js" package. Install it with: npm install pkcs11js'
      );
    }
    const PKCS11 = pkcs11js.PKCS11 ?? pkcs11js.default?.PKCS11 ?? pkcs11js;
    this.pkcs11 = new PKCS11();
    this.pkcs11.load(this.config.libraryPath);
    this.pkcs11.C_Initialize();
    const slots = this.pkcs11.C_GetSlotList(true);
    const slotIdx = this.config.slotIndex ?? 0;
    if (slotIdx >= slots.length) throw new Error(`PKCS#11 slot ${slotIdx} not found`);
    this.session = this.pkcs11.C_OpenSession(slots[slotIdx], 6);
    this.pkcs11.C_Login(this.session, 1, this.config.pin);
  }

  async generate(id: string): Promise<KeyPair> {
    await this.ensureSession();
    const pubTemplate = [
      { type: 0x0000_0003, value: true },
      { type: 0x0000_0100, value: id },
      { type: 0x0000_0162, value: Buffer.from([0x13, 0x0c]) },
    ];
    const privTemplate = [
      { type: 0x0000_0003, value: true },
      { type: 0x0000_0100, value: id },
      { type: 0x0000_0004, value: true },
      { type: 0x0000_0108, value: true },
      { type: 0x0000_0164, value: false },
    ];
    const { hPublicKey, hPrivateKey } = this.pkcs11.C_GenerateKeyPair(
      this.session,
      { mechanism: 0x0000_1057 },
      pubTemplate,
      privTemplate,
    );
    this.handles.set(id, { privHandle: hPrivateKey, pubHandle: hPublicKey });
    const pubBytes = this.pkcs11.C_GetAttributeValue(this.session, hPublicKey, [
      { type: 0x0000_0161 },
    ]);
    return { publicKey: new Uint8Array(pubBytes[0].value.slice(-32)), privateKey: new Uint8Array(0) };
  }

  async sign(id: string, data: Uint8Array): Promise<Uint8Array> {
    await this.ensureSession();
    const handles = await this.findKey(id);
    this.pkcs11.C_SignInit(this.session, { mechanism: 0x0000_1057 }, handles.privHandle);
    const sig = this.pkcs11.C_Sign(this.session, Buffer.from(data), Buffer.alloc(64));
    return new Uint8Array(sig);
  }

  async getPublicKey(id: string): Promise<Uint8Array> {
    await this.ensureSession();
    const handles = await this.findKey(id);
    const attrs = this.pkcs11.C_GetAttributeValue(this.session, handles.pubHandle, [
      { type: 0x0000_0161 },
    ]);
    return new Uint8Array(attrs[0].value.slice(-32));
  }

  async has(id: string): Promise<boolean> {
    try {
      await this.findKey(id);
      return true;
    } catch {
      return false;
    }
  }

  async delete(id: string): Promise<void> {
    await this.ensureSession();
    const handles = await this.findKey(id);
    this.pkcs11.C_DestroyObject(this.session, handles.privHandle);
    this.pkcs11.C_DestroyObject(this.session, handles.pubHandle);
    this.handles.delete(id);
  }

  async list(): Promise<string[]> {
    await this.ensureSession();
    this.pkcs11.C_FindObjectsInit(this.session, [{ type: 0x0000_0003, value: true }]);
    const labels: string[] = [];
    let obj;
    while ((obj = this.pkcs11.C_FindObjects(this.session))) {
      const attrs = this.pkcs11.C_GetAttributeValue(this.session, obj, [{ type: 0x0000_0100 }]);
      labels.push(attrs[0].value.toString());
    }
    this.pkcs11.C_FindObjectsFinal(this.session);
    return labels;
  }

  private async findKey(id: string): Promise<{ privHandle: any; pubHandle: any }> {
    const cached = this.handles.get(id);
    if (cached) return cached;
    await this.ensureSession();
    this.pkcs11.C_FindObjectsInit(this.session, [{ type: 0x0000_0100, value: id }]);
    const objs: any[] = [];
    let obj;
    while ((obj = this.pkcs11.C_FindObjects(this.session))) objs.push(obj);
    this.pkcs11.C_FindObjectsFinal(this.session);
    if (objs.length < 2) throw new Error(`Key not found in PKCS#11 token: ${id}`);
    this.handles.set(id, { privHandle: objs[0], pubHandle: objs[1] });
    return this.handles.get(id)!;
  }
}
