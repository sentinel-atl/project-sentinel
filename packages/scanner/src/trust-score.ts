/**
 * Trust score computation — converts raw findings into a 0-100 score.
 *
 * Weights:
 * - Dependencies (25%): vulnerability count and severity
 * - Code-Patterns (30%): dangerous patterns and obfuscation
 * - Permissions (25%): scope of system access
 * - Publisher (20%): identity verification (placeholder for Phase 3)
 */

import type { Finding } from './scanner.js';
import type { DependencyScanResult } from './dependency-scanner.js';
import type { PatternScanResult } from './pattern-scanner.js';
import type { PermissionScanResult } from './permission-scanner.js';

export interface ScoreBreakdown {
  /** 0-100 score for dependency health */
  dependencies: number;
  /** 0-100 score for code patterns */
  codePatterns: number;
  /** 0-100 score for permission scope */
  permissions: number;
  /** 0-100 score for publisher identity (Phase 3 — default 50) */
  publisher: number;
}

const SEVERITY_PENALTIES: Record<string, number> = {
  critical: 30,
  high: 20,
  medium: 10,
  low: 5,
  info: 1,
};

export function computeTrustScore(
  findings: Finding[],
  deps: DependencyScanResult,
  patterns: PatternScanResult,
  permissions: PermissionScanResult
): ScoreBreakdown {
  return {
    dependencies: computeDependencyScore(deps),
    codePatterns: computePatternScore(patterns),
    permissions: computePermissionScore(permissions),
    publisher: 50, // Phase 3: npm registry identity check
  };
}

function computeDependencyScore(deps: DependencyScanResult): number {
  if (deps.vulnerabilities.length === 0) return 100;

  let penalty = 0;
  for (const vuln of deps.vulnerabilities) {
    const sev = vuln.severity === 'moderate' ? 'medium' : vuln.severity;
    penalty += SEVERITY_PENALTIES[sev] ?? 5;
  }

  return Math.max(0, 100 - penalty);
}

function computePatternScore(patterns: PatternScanResult): number {
  if (patterns.findings.length === 0) return 100;

  let penalty = 0;
  for (const finding of patterns.findings) {
    penalty += SEVERITY_PENALTIES[finding.severity] ?? 5;
  }

  return Math.max(0, 100 - penalty);
}

function computePermissionScore(permissions: PermissionScanResult): number {
  // Base score starts at 100, penalize for each permission kind + detections
  let penalty = 0;

  const kindPenalties: Record<string, number> = {
    process: 25,
    network: 15,
    native: 20,
    filesystem: 10,
    environment: 5,
    crypto: 0, // crypto is usually fine
  };

  for (const kind of permissions.kinds) {
    penalty += kindPenalties[kind] ?? 5;
  }

  // Additional penalty for high number of detections
  if (permissions.detections.length > 20) penalty += 10;
  if (permissions.detections.length > 50) penalty += 10;

  return Math.max(0, 100 - penalty);
}
