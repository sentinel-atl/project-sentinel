/**
 * @sentinel-atl/scanner — MCP Server Security Scanner
 *
 * "npm audit for MCP servers."
 *
 * Multi-layer analysis engine that scans MCP server packages for:
 * 1. Dependency vulnerabilities (npm audit integration)
 * 2. Dangerous code patterns (eval, child_process, fs, net, exfiltration)
 * 3. Obfuscation detection (encoded payloads, minified code in src)
 * 4. Permission scope analysis (what system resources does it access?)
 * 5. Publisher identity verification (npm registry checks)
 * 6. LLM semantic analysis (intent, data flow, scope mismatch — optional)
 * 7. Typosquat detection (supply chain name similarity attacks)
 *
 * Produces a TrustScore (0-100) and a ScanReport with detailed findings.
 * Supports two scan depths:
 * - **fast** (default): sub-scanners 1-5 + 7, regex-based, ~20s, free
 * - **deep**: all 7 sub-scanners including LLM analysis, ~60s, ~$0.11/scan
 */

export {
  scan,
  computeCodeHash,
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
  scanAST,
  type ASTScanResult,
} from './ast-scanner.js';

export {
  scanPermissions,
  type PermissionScanResult,
  type DetectedPermission,
  type PermissionKind,
} from './permission-scanner.js';

export {
  computeTrustScore,
  computeOverallScore,
  computeDimensions,
  DEEP_WEIGHTS,
  FAST_WEIGHTS,
  type ScoreBreakdown,
  type ScoreWeights,
  type TrustDimensions,
} from './trust-score.js';

export {
  scanSemantic,
  type SemanticScanResult,
  type SemanticScanConfig,
  type SemanticFinding,
  type FileAnalysis,
} from './semantic-scanner.js';

export {
  detectTyposquat,
  getKnownPackages,
  type TyposquatResult,
} from './typosquat-scanner.js';

export {
  issueSTC,
  verifySTC,
  revokeSTC,
  InMemoryRevocationStore,
  type SentinelTrustCertificate,
  type STCIssuer,
  type STCSubject,
  type STCFindingSummary,
  type STCProof,
  type STCVerifyResult,
  type IssueSTCOptions,
  type RevocationStore,
  type RevocationEntry,
} from './stc.js';

export {
  resolvePackage,
  cleanupPackage,
  type ResolvedPackage,
} from './package-resolver.js';

export {
  probeTools,
  type ToolProbeResult,
  type MCPTool,
  type ProbeOptions,
} from './tool-prober.js';

export {
  scanPublisher,
  type PublisherInfo,
  type PublisherScanResult,
} from './publisher-scanner.js';
