/**
 * @sentinel-atl/scanner — MCP Server Security Scanner
 *
 * "npm audit for MCP servers."
 *
 * Static analysis engine that scans MCP server packages for:
 * 1. Dependency vulnerabilities (npm audit integration)
 * 2. Dangerous code patterns (eval, child_process, fs, net, exfiltration)
 * 3. Obfuscation detection (encoded payloads, minified code in src)
 * 4. Permission scope analysis (what system resources does it access?)
 * 5. Publisher identity verification (npm registry checks)
 *
 * Produces a TrustScore (0-100) and a ScanReport with detailed findings.
 */

export {
  scan,
  type ScanOptions,
  type ScanReport,
  type TrustScore,
  type Finding,
  type FindingSeverity,
  type FindingCategory,
} from './scanner.js';

export {
  scanDependencies,
  type DependencyScanResult,
  type VulnerablePackage,
} from './dependency-scanner.js';

export {
  scanCodePatterns,
  type PatternScanResult,
  type CodePattern,
  type PatternCategory,
} from './pattern-scanner.js';

export {
  scanPermissions,
  type PermissionScanResult,
  type DetectedPermission,
  type PermissionKind,
} from './permission-scanner.js';

export {
  computeTrustScore,
  type ScoreBreakdown,
} from './trust-score.js';

export {
  issueSTC,
  verifySTC,
  type SentinelTrustCertificate,
  type STCIssuer,
  type STCSubject,
  type STCFindingSummary,
  type STCProof,
  type STCVerifyResult,
  type IssueSTCOptions,
} from './stc.js';
