/**
 * Trust score computation — converts raw findings into a 0-100 score.
 *
 * Weights vary based on whether LLM semantic analysis is available:
 *
 * WITH semantic analysis (deep scan):
 * - Dependencies (15%): vulnerability count and severity
 * - Code-Patterns (15%): dangerous patterns and obfuscation
 * - Permissions (15%): scope of system access
 * - Publisher (15%): npm registry identity verification
 * - Semantic (30%): LLM-powered behavioral analysis
 * - Typosquat (10%): name similarity to known packages
 *
 * WITHOUT semantic analysis (fast scan):
 * - Dependencies (20%): vulnerability count and severity
 * - Code-Patterns (25%): dangerous patterns and obfuscation
 * - Permissions (20%): scope of system access
 * - Publisher (20%): npm registry identity verification
 * - Typosquat (15%): name similarity to known packages
 */

import type { Finding } from './scanner.js';
import type { DependencyScanResult } from './dependency-scanner.js';
import type { PatternScanResult } from './pattern-scanner.js';
import type { ASTScanResult } from './ast-scanner.js';
import type { PermissionScanResult } from './permission-scanner.js';
import type { PublisherScanResult } from './publisher-scanner.js';
import type { SemanticScanResult } from './semantic-scanner.js';
import type { TyposquatResult } from './typosquat-scanner.js';

export interface ScoreBreakdown {
  /** 0-100 score for dependency health */
  dependencies: number;
  /** 0-100 score for code patterns */
  codePatterns: number;
  /** 0-100 score for permission scope */
  permissions: number;
  /** 0-100 score for publisher identity */
  publisher: number;
  /** 0-100 score from LLM semantic analysis (-1 if not run) */
  semantic: number;
  /** 0-100 score for typosquat risk */
  typosquat: number;
}

export interface ScoreWeights {
  dependencies: number;
  codePatterns: number;
  permissions: number;
  publisher: number;
  semantic: number;
  typosquat: number;
}

/** Weights when semantic analysis is available */
export const DEEP_WEIGHTS: ScoreWeights = {
  dependencies: 0.15,
  codePatterns: 0.15,
  permissions: 0.15,
  publisher: 0.15,
  semantic: 0.30,
  typosquat: 0.10,
};

/** Weights when semantic analysis is not available */
export const FAST_WEIGHTS: ScoreWeights = {
  dependencies: 0.20,
  codePatterns: 0.25,
  permissions: 0.20,
  publisher: 0.20,
  semantic: 0,
  typosquat: 0.15,
};

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
  ast: ASTScanResult,
  permissions: PermissionScanResult,
  publisher?: PublisherScanResult,
  semantic?: SemanticScanResult,
  typosquat?: TyposquatResult,
): ScoreBreakdown {
  return {
    dependencies: computeDependencyScore(deps),
    codePatterns: computeCodeAnalysisScore(patterns, ast),
    permissions: computePermissionScore(permissions),
    publisher: publisher?.score ?? 50,
    semantic: semantic?.analyzed ? semantic.score : -1,
    typosquat: typosquat?.score ?? 100,
  };
}

/**
 * Compute the weighted overall score from a breakdown.
 * Automatically selects deep vs fast weights based on whether semantic ran.
 */
export function computeOverallScore(breakdown: ScoreBreakdown): number {
  const weights = breakdown.semantic >= 0 ? DEEP_WEIGHTS : FAST_WEIGHTS;

  let score = 0;
  score += breakdown.dependencies * weights.dependencies;
  score += breakdown.codePatterns * weights.codePatterns;
  score += breakdown.permissions * weights.permissions;
  score += breakdown.publisher * weights.publisher;
  score += breakdown.typosquat * weights.typosquat;

  if (breakdown.semantic >= 0) {
    score += breakdown.semantic * weights.semantic;
  }

  // Typosquat override: if it's a likely typosquat, cap the total score
  if (breakdown.typosquat <= 15) {
    score = Math.min(score, 25); // Likely typosquat — hard cap
  } else if (breakdown.typosquat <= 35) {
    score = Math.min(score, 45); // Possible typosquat — soft cap
  }

  return Math.round(score);
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

/**
 * Combined code analysis score from regex patterns + AST analysis.
 * AST findings carry higher penalty because they represent deeper understanding.
 * Deduplicate: if both regex and AST flag the same line in the same file,
 * count it once (using the higher penalty).
 */
function computeCodeAnalysisScore(patterns: PatternScanResult, ast: ASTScanResult): number {
  // Build a set of (file:line) already penalized by regex
  const regexHits = new Set<string>();
  let penalty = 0;

  for (const f of patterns.findings) {
    const key = `${f.file}:${f.line}`;
    regexHits.add(key);
    penalty += SEVERITY_PENALTIES[f.severity] ?? 5;
  }

  // AST findings that DON'T overlap with regex get an additional penalty
  for (const f of ast.findings) {
    const key = `${f.file}:${f.line}`;
    if (regexHits.has(key)) continue; // Already counted from regex
    penalty += SEVERITY_PENALTIES[f.severity] ?? 5;
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

// ─── Multi-Dimensional Scoring ───────────────────────────────────────

export interface TrustDimensions {
  integrity: number;
  behavior: number;
  provenance: number;
}

/**
 * Decompose the per-scanner breakdown into three human-meaningful dimensions.
 *
 * - integrity: supply chain risk (is this the real package?)
 *   → typosquat (50%) + dependencies (50%)
 *
 * - behavior: runtime risk (what does the code do?)
 *   → codePatterns (30%) + permissions (30%) + semantic (40%) [or codePatterns 45% + permissions 55% without semantic]
 *
 * - provenance: publisher risk (who published this?)
 *   → publisher (100%)
 */
export function computeDimensions(breakdown: ScoreBreakdown): TrustDimensions {
  // Integrity: is this the real package?
  const integrity = Math.round(
    breakdown.typosquat * 0.5 + breakdown.dependencies * 0.5
  );

  // Behavior: what does the code do?
  let behavior: number;
  if (breakdown.semantic >= 0) {
    behavior = Math.round(
      breakdown.codePatterns * 0.30 + breakdown.permissions * 0.30 + breakdown.semantic * 0.40
    );
  } else {
    behavior = Math.round(
      breakdown.codePatterns * 0.45 + breakdown.permissions * 0.55
    );
  }

  // Provenance: who published this?
  const provenance = breakdown.publisher;

  return { integrity, behavior, provenance };
}
