/**
 * Core scanner — orchestrates all sub-scanners and produces a unified ScanReport.
 *
 * Sub-scanners:
 * 1. Dependency scanner — npm audit for known CVEs
 * 2. Pattern scanner — regex-based dangerous code detection
 * 3. Permission scanner — system resource access profiling
 * 4. Publisher scanner — npm registry identity verification
 * 5. Semantic scanner — LLM-powered behavioral analysis (optional)
 * 6. Typosquat detector — supply chain name similarity check
 */

import { scanDependencies, type DependencyScanResult } from './dependency-scanner.js';
import { scanCodePatterns, type PatternScanResult } from './pattern-scanner.js';
import { scanAST, type ASTScanResult } from './ast-scanner.js';
import { scanPermissions, type PermissionScanResult } from './permission-scanner.js';
import { scanPublisher, type PublisherScanResult } from './publisher-scanner.js';
import { scanSemantic, type SemanticScanResult, type SemanticScanConfig } from './semantic-scanner.js';
import { detectTyposquat, type TyposquatResult } from './typosquat-scanner.js';
import { computeTrustScore, computeOverallScore, computeDimensions, type ScoreBreakdown, type TrustDimensions } from './trust-score.js';
import { readFile, readdir, stat } from 'node:fs/promises';
import { join, relative, extname } from 'node:path';
import { createHash } from 'node:crypto';

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
  /** Multi-dimensional risk profile — don't collapse security into one number */
  dimensions: TrustDimensions;
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
  /** Code pattern scan results (regex) */
  patterns: PatternScanResult;
  /** AST-based deep code analysis */
  ast: ASTScanResult;
  /** Permission scan results */
  permissions: PermissionScanResult;
  /** Publisher identity results */
  publisher?: PublisherScanResult;
  /** LLM semantic analysis results */
  semantic?: SemanticScanResult;
  /** Typosquat detection results */
  typosquat?: TyposquatResult;
  /** Scan duration in ms */
  durationMs: number;
  /** Scan depth: 'fast' (no LLM) or 'deep' (with LLM) */
  scanDepth: 'fast' | 'deep';
  /** SHA-256 hash of all source files (deterministic, content-addressable) */
  codeHash: string;
}

export interface ScanOptions {
  /** Path to the package directory to scan */
  packagePath: string;
  /** Skip dependency scanning (useful when npm not available) */
  skipDependencies?: boolean;
  /** Additional file extensions to scan (default: .ts, .js, .mjs, .cjs) */
  extensions?: string[];
  /** LLM configuration for semantic analysis. If not set, semantic scanning is skipped. */
  semanticConfig?: SemanticScanConfig;
  /** Package description from registry (used for scope-match analysis) */
  packageDescription?: string;
  /** Additional known packages for typosquat detection */
  knownPackages?: string[];
}

// ─── Main Scan Function ──────────────────────────────────────────────

const SCANNER_VERSION = '0.5.0';

// ─── Code Hashing ────────────────────────────────────────────────────

const HASH_SKIP_DIRS = new Set([
  'node_modules', 'dist', '.git', '.turbo', 'coverage',
  '__pycache__', '.next', 'build', '.cache',
]);

const HASH_EXTENSIONS = new Set([
  '.ts', '.js', '.mjs', '.cjs', '.jsx', '.tsx', '.py',
  '.json', '.yaml', '.yml', '.toml',
]);

/**
 * Compute a deterministic SHA-256 hash of all source files in a package.
 * Files are sorted by relative path so the hash is stable regardless
 * of filesystem ordering. This is the binding between a scan report
 * and the exact code that was scanned — callers should never provide
 * their own hash.
 */
export async function computeCodeHash(packagePath: string): Promise<string> {
  const h = createHash('sha256');
  const files = await collectHashableFiles(packagePath, packagePath);
  files.sort(); // deterministic ordering
  for (const filePath of files) {
    const relPath = relative(packagePath, filePath);
    const content = await readFile(filePath);
    // Include the path in the hash so renaming a file changes the hash
    h.update(relPath);
    h.update(content);
  }
  return h.digest('hex');
}

async function collectHashableFiles(dir: string, basePath: string): Promise<string[]> {
  const files: string[] = [];
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return files;
  }
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (HASH_SKIP_DIRS.has(entry.name)) continue;
      files.push(...await collectHashableFiles(fullPath, basePath));
    } else if (entry.isFile() && HASH_EXTENSIONS.has(extname(entry.name))) {
      files.push(fullPath);
    }
  }
  return files;
}

export async function scan(options: ScanOptions): Promise<ScanReport> {
  const startTime = Date.now();
  const { packagePath, skipDependencies = false } = options;
  const extensions = options.extensions ?? ['.ts', '.js', '.mjs', '.cjs'];

  // Read package.json
  const pkgJsonPath = join(packagePath, 'package.json');
  let packageName = 'unknown';
  let packageVersion = '0.0.0';
  let packageDescription = options.packageDescription;

  try {
    const pkgJson = JSON.parse(await readFile(pkgJsonPath, 'utf-8'));
    packageName = pkgJson.name ?? 'unknown';
    packageVersion = pkgJson.version ?? '0.0.0';
    if (!packageDescription) {
      packageDescription = pkgJson.description;
    }
  } catch {
    // No package.json — we can still scan the code
  }

  // Run static sub-scanners in parallel (fast, no external API needed)
  const [dependencies, patterns, ast, permissions, publisher] = await Promise.all([
    skipDependencies
      ? { vulnerabilities: [], totalDependencies: 0, findings: [] as Finding[] }
      : scanDependencies(packagePath),
    scanCodePatterns(packagePath, extensions),
    scanAST(packagePath, extensions),
    scanPermissions(packagePath, extensions),
    scanPublisher(packageName),
  ]);

  // Typosquat detection (synchronous, instant)
  const typosquat = detectTyposquat(packageName, options.knownPackages);

  // LLM semantic analysis (optional, runs only when configured)
  const semantic = await scanSemantic(packagePath, packageDescription, options.semanticConfig);

  // Aggregate findings from all scanners
  const findings: Finding[] = [
    ...dependencies.findings,
    ...patterns.findings,
    ...ast.findings,
    ...permissions.findings,
    ...publisher.findings,
    ...semantic.findings,
    ...typosquat.findings,
  ];

  // Compute trust score with all sub-scanner results
  const breakdown = computeTrustScore(
    findings, dependencies, patterns, ast, permissions,
    publisher, semantic, typosquat,
  );
  const overall = computeOverallScore(breakdown);

  const grade = overall >= 90 ? 'A'
    : overall >= 75 ? 'B'
    : overall >= 60 ? 'C'
    : overall >= 40 ? 'D'
    : 'F';

  const trustScore: TrustScore = { overall, breakdown, grade, dimensions: computeDimensions(breakdown) };

  // Compute content-addressable hash of all source files
  const codeHash = await computeCodeHash(packagePath);

  return {
    packageName,
    packageVersion,
    scannedAt: new Date().toISOString(),
    scannerVersion: SCANNER_VERSION,
    trustScore,
    findings,
    dependencies,
    patterns,
    ast,
    permissions,
    publisher,
    semantic,
    typosquat,
    durationMs: Date.now() - startTime,
    scanDepth: semantic.analyzed ? 'deep' : 'fast',
    codeHash,
  };
}
