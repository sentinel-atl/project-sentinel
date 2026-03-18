/**
 * Core scanner — orchestrates all sub-scanners and produces a unified ScanReport.
 */

import { scanDependencies, type DependencyScanResult } from './dependency-scanner.js';
import { scanCodePatterns, type PatternScanResult } from './pattern-scanner.js';
import { scanPermissions, type PermissionScanResult } from './permission-scanner.js';
import { scanPublisher, type PublisherScanResult } from './publisher-scanner.js';
import { computeTrustScore, type ScoreBreakdown } from './trust-score.js';
import { readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';

// ─── Types ───────────────────────────────────────────────────────────

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingCategory =
  | 'vulnerability'
  | 'dangerous-pattern'
  | 'obfuscation'
  | 'permission'
  | 'exfiltration'
  | 'publisher';

export interface Finding {
  severity: FindingSeverity;
  category: FindingCategory;
  title: string;
  description: string;
  file?: string;
  line?: number;
  evidence?: string;
}

export interface TrustScore {
  /** Overall score 0-100 (100 = fully trusted) */
  overall: number;
  /** Per-category breakdown */
  breakdown: ScoreBreakdown;
  /** Human-readable grade: A, B, C, D, F */
  grade: string;
}

export interface ScanReport {
  /** Package name */
  packageName: string;
  /** Package version */
  packageVersion: string;
  /** When scan was performed */
  scannedAt: string;
  /** Scanner version */
  scannerVersion: string;
  /** Trust score */
  trustScore: TrustScore;
  /** All findings */
  findings: Finding[];
  /** Dependency scan results */
  dependencies: DependencyScanResult;
  /** Code pattern scan results */
  patterns: PatternScanResult;
  /** Permission scan results */
  permissions: PermissionScanResult;
  /** Publisher identity results */
  publisher?: PublisherScanResult;
  /** Scan duration in ms */
  durationMs: number;
}

export interface ScanOptions {
  /** Path to the package directory to scan */
  packagePath: string;
  /** Skip dependency scanning (useful when npm not available) */
  skipDependencies?: boolean;
  /** Additional file extensions to scan (default: .ts, .js, .mjs, .cjs) */
  extensions?: string[];
}

// ─── Main Scan Function ──────────────────────────────────────────────

const SCANNER_VERSION = '0.3.0';

export async function scan(options: ScanOptions): Promise<ScanReport> {
  const startTime = Date.now();
  const { packagePath, skipDependencies = false } = options;
  const extensions = options.extensions ?? ['.ts', '.js', '.mjs', '.cjs'];

  // Read package.json
  const pkgJsonPath = join(packagePath, 'package.json');
  let packageName = 'unknown';
  let packageVersion = '0.0.0';

  try {
    const pkgJson = JSON.parse(await readFile(pkgJsonPath, 'utf-8'));
    packageName = pkgJson.name ?? 'unknown';
    packageVersion = pkgJson.version ?? '0.0.0';
  } catch {
    // No package.json — we can still scan the code
  }

  // Run all sub-scanners
  const [dependencies, patterns, permissions, publisher] = await Promise.all([
    skipDependencies
      ? { vulnerabilities: [], totalDependencies: 0, findings: [] as Finding[] }
      : scanDependencies(packagePath),
    scanCodePatterns(packagePath, extensions),
    scanPermissions(packagePath, extensions),
    scanPublisher(packageName),
  ]);

  // Aggregate findings
  const findings: Finding[] = [
    ...dependencies.findings,
    ...patterns.findings,
    ...permissions.findings,
    ...publisher.findings,
  ];

  // Compute trust score
  const breakdown = computeTrustScore(findings, dependencies, patterns, permissions, publisher);
  const overall = Math.round(
    breakdown.dependencies * 0.25 +
    breakdown.codePatterns * 0.30 +
    breakdown.permissions * 0.25 +
    breakdown.publisher * 0.20
  );

  const grade = overall >= 90 ? 'A'
    : overall >= 75 ? 'B'
    : overall >= 60 ? 'C'
    : overall >= 40 ? 'D'
    : 'F';

  const trustScore: TrustScore = { overall, breakdown, grade };

  return {
    packageName,
    packageVersion,
    scannedAt: new Date().toISOString(),
    scannerVersion: SCANNER_VERSION,
    trustScore,
    findings,
    dependencies,
    patterns,
    permissions,
    publisher,
    durationMs: Date.now() - startTime,
  };
}
