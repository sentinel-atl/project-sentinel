/**
 * Sentinel Trust Certificate (STC) — A signed, verifiable scan result.
 *
 * An STC is a cryptographically signed certificate that attests to the
 * security posture of an MCP server package at a specific point in time.
 *
 * Think of it as:
 * - SSL certificate meets npm audit report
 * - A "nutrition label" for MCP servers
 * - Machine-readable trust evidence
 *
 * Format:
 * {
 *   "@context": "https://sentinel.trust/stc/v1",
 *   "type": "SentinelTrustCertificate",
 *   "id": "stc:<hash>",
 *   "issuedAt": ISO timestamp,
 *   "expiresAt": ISO timestamp,
 *   "issuer": { did, name },
 *   "subject": { packageName, packageVersion, codeHash },
 *   "trustScore": { overall, grade, breakdown },
 *   "findings": { critical, high, medium, low, info },
 *   "permissions": [...],
 *   "proof": { type: "Ed25519Signature2024", ... }
 * }
 */

import {
  type KeyProvider,
  sign,
  verify,
  toBase64Url,
  fromBase64Url,
  textToBytes,
  toHex,
  hash,
  didToPublicKey,
} from '@sentinel-atl/core';
import type { ScanReport, TrustScore } from './scanner.js';

// ─── Types ───────────────────────────────────────────────────────────

export interface STCIssuer {
  did: string;
  name?: string;
}

export interface STCSubject {
  packageName: string;
  packageVersion: string;
  codeHash: string;
}

export interface STCFindingSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface STCProof {
  type: 'Ed25519Signature2024';
  created: string;
  verificationMethod: string;
  signature: string;
}

export interface SentinelTrustCertificate {
  '@context': 'https://sentinel.trust/stc/v1';
  type: 'SentinelTrustCertificate';
  id: string;
  issuedAt: string;
  expiresAt: string;
  issuer: STCIssuer;
  subject: STCSubject;
  trustScore: TrustScore;
  findingSummary: STCFindingSummary;
  permissions: string[];
  scannerVersion: string;
  proof: STCProof;
}

export interface STCVerifyResult {
  valid: boolean;
  error?: string;
  certificate?: SentinelTrustCertificate;
}

export interface IssueSTCOptions {
  scanReport: ScanReport;
  codeHash: string;
  issuerDid: string;
  issuerKeyId: string;
  issuerName?: string;
  /** Certificate validity in hours (default: 720 = 30 days) */
  validityHours?: number;
}

// ─── STC Issuance ────────────────────────────────────────────────────

/**
 * Issue a Sentinel Trust Certificate from a scan report.
 */
export async function issueSTC(
  keyProvider: KeyProvider,
  options: IssueSTCOptions
): Promise<SentinelTrustCertificate> {
  const {
    scanReport,
    codeHash,
    issuerDid,
    issuerKeyId,
    issuerName,
    validityHours = 720,
  } = options;

  const now = new Date();
  const expiresAt = new Date(now.getTime() + validityHours * 3600_000);

  // Count findings by severity
  const findingSummary: STCFindingSummary = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0, total: scanReport.findings.length,
  };
  for (const f of scanReport.findings) {
    findingSummary[f.severity]++;
  }

  // Build unsigned certificate body
  const body = {
    '@context': 'https://sentinel.trust/stc/v1' as const,
    type: 'SentinelTrustCertificate' as const,
    id: '', // computed after hashing
    issuedAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    issuer: { did: issuerDid, name: issuerName },
    subject: {
      packageName: scanReport.packageName,
      packageVersion: scanReport.packageVersion,
      codeHash,
    },
    trustScore: scanReport.trustScore,
    findingSummary,
    permissions: scanReport.permissions.kinds,
    scannerVersion: scanReport.scannerVersion,
  };

  // Generate deterministic ID from body hash
  const bodyBytes = textToBytes(JSON.stringify(sortDeep(body)));
  const bodyHash = toHex(hash(bodyBytes));
  body.id = `stc:${bodyHash.slice(0, 16)}`;

  // Sign the canonical body
  const canonicalBytes = textToBytes(JSON.stringify(sortDeep(body)));
  const sig = await keyProvider.sign(issuerKeyId, canonicalBytes);

  const proof: STCProof = {
    type: 'Ed25519Signature2024',
    created: now.toISOString(),
    verificationMethod: `${issuerDid}#key-0`,
    signature: toBase64Url(sig),
  };

  return { ...body, proof };
}

// ─── STC Verification ────────────────────────────────────────────────

/**
 * Verify a Sentinel Trust Certificate's signature and validity.
 */
export async function verifySTC(
  certificate: SentinelTrustCertificate
): Promise<STCVerifyResult> {
  try {
    // Check expiry
    if (new Date(certificate.expiresAt) < new Date()) {
      return { valid: false, error: 'Certificate has expired' };
    }

    // Extract the body (everything except proof)
    const { proof, ...body } = certificate;

    // Reconstruct canonical form and verify signature
    const canonicalBytes = textToBytes(JSON.stringify(sortDeep(body)));
    const sigBytes = fromBase64Url(proof.signature);
    const publicKey = didToPublicKey(certificate.issuer.did);
    const isValid = await verify(sigBytes, canonicalBytes, publicKey);

    if (!isValid) {
      return { valid: false, error: 'Invalid certificate signature' };
    }

    return { valid: true, certificate };
  } catch (e) {
    return { valid: false, error: `Verification failed: ${(e as Error).message}` };
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────

function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value !== null && typeof value === 'object') {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortDeep((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}
