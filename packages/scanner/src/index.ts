/**
 * @sentinel-atl/scanner — MCP Server Security Scanner
 *
 * "npm audit for MCP servers."
 *
 * Multi-layer analysis engine that scans MCP server packages for:
 * 1. Dependency vulnerabilities (npm audit integration)
 * 2. Dangerous code patterns (eval, child_process, fs, net, exfiltration)
 * 3. AST-based deep structural analysis (alias tracking, obfuscation detection)
 * 4. Obfuscation detection (encoded payloads, minified code in src)
 * 5. Permission scope analysis (what system resources does it access?)
 * 6. Publisher identity verification (npm registry checks)
 * 7. Tool poisoning detection (hidden Unicode, prompt injection in tool descriptions)
 * 8. Tool shadowing detection (tools mimicking built-in names)
 * 9. Toxic flow analysis (cross-tool data paths: secrets→network, files→execute)
 * 10. LLM semantic analysis (intent, data flow, scope mismatch — optional)
 * 11. Typosquat detection (supply chain name similarity attacks)
 *
 * Also includes:
 * - Auto-discovery of MCP configs (Claude Desktop, Cursor, Windsurf, VS Code, Gemini CLI)
 * - Runtime MCP server probing with integrated poisoning/shadowing/flow analysis
 *
 * Produces a TrustScore (0-100) and a ScanReport with detailed findings.
 * Supports two scan depths:
 * - **fast** (default): static sub-scanners, regex-based, ~20s, free
 * - **deep**: all sub-scanners including LLM analysis, ~60s, ~$0.11/scan
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

export {
  discoverMCPConfigs,
  type DiscoveredServer,
  type DiscoveryResult,
  type MCPClientSource,
} from './config-discovery.js';

export {
  scanToolPoisoning,
  type PoisoningResult,
  type PoisonedTool,
  type PoisoningTechnique,
} from './poisoning-scanner.js';

export {
  scanToolShadowing,
  type ShadowingResult,
  type ShadowedTool,
  type ShadowingTechnique,
} from './shadowing-scanner.js';

export {
  analyzeFlows,
  type FlowAnalysisResult,
  type ToolCapability,
  type ToxicFlow,
  type ToxicFlowPattern,
  type DataCategory,
} from './flow-analyzer.js';
