/**
 * Trust Store — manages loaded Sentinel Trust Certificates for runtime verification.
 * Supports optional persistent backend via SentinelStore.
 */

import { readFile } from 'node:fs/promises';
import { verifySTC, type SentinelTrustCertificate } from '@sentinel-atl/scanner';
import type { SentinelStore } from '@sentinel-atl/store';

export interface StoredCertificate {
  certificate: SentinelTrustCertificate;
  serverName: string;
  verified: boolean;
  loadedAt: string;
}

export interface TrustStoreOptions {
  /** Persistent backend — data survives restarts */
  backend?: SentinelStore;
  /** Key prefix for the backend (default: 'trust-store:') */
  prefix?: string;
}

const KEY_PREFIX_DEFAULT = 'trust-store:';

export class TrustStore {
  private certificates = new Map<string, StoredCertificate>();
  private backend?: SentinelStore;
  private prefix: string;

  constructor(options?: TrustStoreOptions) {
    this.backend = options?.backend;
    this.prefix = options?.prefix ?? KEY_PREFIX_DEFAULT;
  }

  /** Load all entries from the backend into the in-memory cache. Call once on startup. */
  async load(): Promise<void> {
    if (!this.backend) return;
    const keys = await this.backend.keys(this.prefix);
    const values = await this.backend.getMany(keys);
    for (const [, json] of values) {
      const stored: StoredCertificate = JSON.parse(json);
      this.certificates.set(stored.serverName, stored);
    }
  }

  /**
   * Load an STC from a file and verify its signature.
   */
  async loadCertificate(serverName: string, filePath: string): Promise<StoredCertificate> {
    const raw = await readFile(filePath, 'utf-8');
    const certificate: SentinelTrustCertificate = JSON.parse(raw);

    const result = await verifySTC(certificate);

    const stored: StoredCertificate = {
      certificate,
      serverName,
      verified: result.valid,
      loadedAt: new Date().toISOString(),
    };

    this.certificates.set(serverName, stored);

    if (this.backend) {
      await this.backend.set(`${this.prefix}${serverName}`, JSON.stringify(stored));
    }

    return stored;
  }

  /**
   * Register a pre-loaded certificate.
   */
  async addCertificate(serverName: string, certificate: SentinelTrustCertificate): Promise<StoredCertificate> {
    const result = await verifySTC(certificate);

    const stored: StoredCertificate = {
      certificate,
      serverName,
      verified: result.valid,
      loadedAt: new Date().toISOString(),
    };

    this.certificates.set(serverName, stored);

    if (this.backend) {
      await this.backend.set(`${this.prefix}${serverName}`, JSON.stringify(stored));
    }

    return stored;
  }

  /**
   * Get the certificate for a server.
   */
  getCertificate(serverName: string): StoredCertificate | undefined {
    return this.certificates.get(serverName);
  }

  /**
   * Check if a server has a valid, non-expired certificate.
   */
  isVerified(serverName: string): boolean {
    const stored = this.certificates.get(serverName);
    if (!stored || !stored.verified) return false;
    return new Date(stored.certificate.expiresAt) > new Date();
  }

  /**
   * Get all stored certificates.
   */
  getAll(): StoredCertificate[] {
    return Array.from(this.certificates.values());
  }

  /**
   * Remove a certificate.
   */
  async remove(serverName: string): Promise<boolean> {
    const existed = this.certificates.delete(serverName);
    if (existed && this.backend) {
      await this.backend.delete(`${this.prefix}${serverName}`);
    }
    return existed;
  }
}
