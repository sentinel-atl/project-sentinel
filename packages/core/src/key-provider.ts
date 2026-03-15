/**
 * @sentinel/core — KeyProvider interface
 *
 * Abstracts key storage so backends are swappable:
 * - OS keychain (v0 default)
 * - Secure Enclave (macOS)
 * - HSM (AWS CloudHSM, Azure Managed HSM, PKCS#11)
 *
 * Protocol logic never touches raw keys directly — always goes through a provider.
 */

import type { KeyPair } from './crypto.js';

export interface KeyProvider {
  /** Generate a new keypair and store it under the given ID */
  generate(id: string): Promise<KeyPair>;

  /** Sign data using the private key for the given ID */
  sign(id: string, data: Uint8Array): Promise<Uint8Array>;

  /** Get the public key for the given ID */
  getPublicKey(id: string): Promise<Uint8Array>;

  /** Check if a key exists for the given ID */
  has(id: string): Promise<boolean>;

  /** Delete a key by ID */
  delete(id: string): Promise<void>;

  /** List all stored key IDs */
  list(): Promise<string[]>;

  /** Export the raw private key (only for backup — providers MAY refuse) */
  exportPrivateKey?(id: string): Promise<Uint8Array>;
}

/**
 * InMemoryKeyProvider — for testing and development.
 * Keys live in memory only and are lost when the process exits.
 */
export class InMemoryKeyProvider implements KeyProvider {
  private keys = new Map<string, KeyPair>();

  async generate(id: string): Promise<KeyPair> {
    const { generateKeyPair } = await import('./crypto.js');
    const kp = await generateKeyPair();
    this.keys.set(id, kp);
    return kp;
  }

  async sign(id: string, data: Uint8Array): Promise<Uint8Array> {
    const kp = this.keys.get(id);
    if (!kp) throw new Error(`Key not found: ${id}`);
    const { sign } = await import('./crypto.js');
    return sign(data, kp.privateKey);
  }

  async getPublicKey(id: string): Promise<Uint8Array> {
    const kp = this.keys.get(id);
    if (!kp) throw new Error(`Key not found: ${id}`);
    return kp.publicKey;
  }

  async has(id: string): Promise<boolean> {
    return this.keys.has(id);
  }

  async delete(id: string): Promise<void> {
    this.keys.delete(id);
  }

  async list(): Promise<string[]> {
    return Array.from(this.keys.keys());
  }

  async exportPrivateKey(id: string): Promise<Uint8Array> {
    const kp = this.keys.get(id);
    if (!kp) throw new Error(`Key not found: ${id}`);
    return kp.privateKey;
  }
}
