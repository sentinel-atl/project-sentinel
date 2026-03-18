/**
 * Certificate Store — persistent storage for Sentinel Trust Certificates.
 *
 * Backed by SentinelStore interface — supports in-memory, Redis, Postgres, SQLite.
 * By default uses in-memory Map for zero-config development.
 */

import { verifySTC, type SentinelTrustCertificate, type STCVerifyResult } from '@sentinel-atl/scanner';
import type { SentinelStore } from '@sentinel-atl/store';

// ─── Types ───────────────────────────────────────────────────────────

export interface RegistryEntry {
  /** STC ID */
  id: string;
  /** Full certificate */
  certificate: SentinelTrustCertificate;
  /** Package name (for lookup) */
  packageName: string;
  /** Package version */
  packageVersion: string;
  /** Trust score */
  trustScore: number;
  /** Grade */
  grade: string;
  /** Whether signature is verified */
  verified: boolean;
  /** When the entry was registered */
  registeredAt: string;
  /** Issuer DID */
  issuerDid: string;
}

export interface RegistryQuery {
  /** Filter by package name */
  packageName?: string;
  /** Filter by minimum trust score */
  minScore?: number;
  /** Filter by minimum grade */
  minGrade?: string;
  /** Filter by verified status */
  verified?: boolean;
  /** Maximum results */
  limit?: number;
  /** Offset for pagination */
  offset?: number;
}

export interface RegistryStats {
  totalCertificates: number;
  verifiedCertificates: number;
  uniquePackages: number;
  averageScore: number;
  gradeDistribution: Record<string, number>;
}

// ─── Grade Helpers ───────────────────────────────────────────────────

const GRADE_ORDER: Record<string, number> = { A: 4, B: 3, C: 2, D: 1, F: 0 };

function gradeAtLeast(actual: string, required: string): boolean {
  return (GRADE_ORDER[actual] ?? 0) >= (GRADE_ORDER[required] ?? 0);
}

// ─── Store ───────────────────────────────────────────────────────────

/**
 * Options for creating a CertificateStore.
 * If `backend` is provided, certificates are persisted via SentinelStore.
 * Otherwise, an in-memory Map is used (development only).
 */
export interface CertificateStoreOptions {
  /** Persistent backend — data survives restarts */
  backend?: SentinelStore;
  /** Key prefix for the backend (default: 'registry:') */
  prefix?: string;
}

const KEY_PREFIX_DEFAULT = 'registry:';
const CERT_PREFIX = 'cert:';
const PKG_INDEX_PREFIX = 'pkg:';

export class CertificateStore {
  private cache = new Map<string, RegistryEntry>();
  /** Index: packageName → entry IDs (newest first) */
  private pkgIndex = new Map<string, string[]>();
  private backend?: SentinelStore;
  private prefix: string;
  private loaded = false;

  constructor(options?: CertificateStoreOptions) {
    this.backend = options?.backend;
    this.prefix = options?.prefix ?? KEY_PREFIX_DEFAULT;
  }

  /** Load all entries from the backend into the in-memory cache. Call once on startup. */
  async load(): Promise<void> {
    if (this.loaded || !this.backend) return;
    const keys = await this.backend.keys(`${this.prefix}${CERT_PREFIX}`);
    const values = await this.backend.getMany(keys);
    for (const [, json] of values) {
      const entry: RegistryEntry = JSON.parse(json);
      this.cache.set(entry.id, entry);
      const existing = this.pkgIndex.get(entry.packageName) ?? [];
      existing.push(entry.id);
      this.pkgIndex.set(entry.packageName, existing);
    }
    // Sort each package's IDs by registeredAt descending
    for (const [pkg, ids] of this.pkgIndex) {
      ids.sort((a, b) => {
        const ea = this.cache.get(a)!;
        const eb = this.cache.get(b)!;
        return eb.registeredAt.localeCompare(ea.registeredAt);
      });
    }
    this.loaded = true;
  }

  /**
   * Register a new certificate. Verifies signature before storing.
   */
  async register(certificate: SentinelTrustCertificate): Promise<RegistryEntry> {
    const result: STCVerifyResult = await verifySTC(certificate);

    const entry: RegistryEntry = {
      id: certificate.id,
      certificate,
      packageName: certificate.subject.packageName,
      packageVersion: certificate.subject.packageVersion,
      trustScore: certificate.trustScore.overall,
      grade: certificate.trustScore.grade,
      verified: result.valid,
      registeredAt: new Date().toISOString(),
      issuerDid: certificate.issuer.did,
    };

    this.cache.set(entry.id, entry);

    // Update package index
    const existing = this.pkgIndex.get(entry.packageName) ?? [];
    existing.unshift(entry.id); // newest first
    this.pkgIndex.set(entry.packageName, existing);

    // Persist to backend
    if (this.backend) {
      await this.backend.set(`${this.prefix}${CERT_PREFIX}${entry.id}`, JSON.stringify(entry));
      await this.backend.set(
        `${this.prefix}${PKG_INDEX_PREFIX}${entry.packageName}`,
        JSON.stringify(existing)
      );
    }

    return entry;
  }

  /**
   * Get a certificate by ID.
   */
  get(id: string): RegistryEntry | undefined {
    return this.cache.get(id);
  }

  /**
   * Get the latest certificate for a package.
   */
  getLatestForPackage(packageName: string): RegistryEntry | undefined {
    const ids = this.pkgIndex.get(packageName);
    if (!ids || ids.length === 0) return undefined;
    return this.cache.get(ids[0]);
  }

  /**
   * Get all certificates for a package.
   */
  getForPackage(packageName: string): RegistryEntry[] {
    const ids = this.pkgIndex.get(packageName) ?? [];
    return ids.map(id => this.cache.get(id)!).filter(Boolean);
  }

  /**
   * Query certificates with filters.
   */
  query(q: RegistryQuery): RegistryEntry[] {
    let results = Array.from(this.cache.values());

    if (q.packageName) {
      results = results.filter(e => e.packageName === q.packageName);
    }
    if (q.minScore !== undefined) {
      results = results.filter(e => e.trustScore >= q.minScore!);
    }
    if (q.minGrade) {
      results = results.filter(e => gradeAtLeast(e.grade, q.minGrade!));
    }
    if (q.verified !== undefined) {
      results = results.filter(e => e.verified === q.verified);
    }

    // Sort by registeredAt descending
    results.sort((a, b) => b.registeredAt.localeCompare(a.registeredAt));

    const offset = q.offset ?? 0;
    const limit = q.limit ?? 50;
    return results.slice(offset, offset + limit);
  }

  /**
   * Remove a certificate by ID.
   */
  async remove(id: string): Promise<boolean> {
    const entry = this.cache.get(id);
    if (!entry) return false;

    this.cache.delete(id);

    const ids = this.pkgIndex.get(entry.packageName);
    if (ids) {
      const idx = ids.indexOf(id);
      if (idx !== -1) ids.splice(idx, 1);
      if (ids.length === 0) this.pkgIndex.delete(entry.packageName);
    }

    // Persist deletion to backend
    if (this.backend) {
      await this.backend.delete(`${this.prefix}${CERT_PREFIX}${id}`);
      if (ids && ids.length > 0) {
        await this.backend.set(
          `${this.prefix}${PKG_INDEX_PREFIX}${entry.packageName}`,
          JSON.stringify(ids)
        );
      } else {
        await this.backend.delete(`${this.prefix}${PKG_INDEX_PREFIX}${entry.packageName}`);
      }
    }

    return true;
  }

  /**
   * Get registry statistics.
   */
  getStats(): RegistryStats {
    const all = Array.from(this.cache.values());
    const gradeDistribution: Record<string, number> = { A: 0, B: 0, C: 0, D: 0, F: 0 };

    let totalScore = 0;
    for (const entry of all) {
      totalScore += entry.trustScore;
      gradeDistribution[entry.grade] = (gradeDistribution[entry.grade] ?? 0) + 1;
    }

    return {
      totalCertificates: all.length,
      verifiedCertificates: all.filter(e => e.verified).length,
      uniquePackages: this.pkgIndex.size,
      averageScore: all.length > 0 ? Math.round(totalScore / all.length) : 0,
      gradeDistribution,
    };
  }

  /**
   * Get total count (for pagination).
   */
  count(): number {
    return this.cache.size;
  }
}
