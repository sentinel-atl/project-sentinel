/**
 * Trust Store — manages loaded Sentinel Trust Certificates for runtime verification.
 */

import { readFile } from 'node:fs/promises';
import { verifySTC, type SentinelTrustCertificate } from '@sentinel-atl/scanner';

export interface StoredCertificate {
  certificate: SentinelTrustCertificate;
  serverName: string;
  verified: boolean;
  loadedAt: string;
}

export class TrustStore {
  private certificates = new Map<string, StoredCertificate>();

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
  remove(serverName: string): boolean {
    return this.certificates.delete(serverName);
  }
}
