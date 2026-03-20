/**
 * Toxic Flow Analyzer
 *
 * Analyzes cross-tool data flow patterns across MCP tools to detect
 * dangerous combinations that could compromise user security.
 *
 * A single tool may be harmless on its own, but the combination of tools
 * on a server can create toxic flows:
 *   - Tool A reads secrets → Tool B sends HTTP requests (exfiltration)
 *   - Tool A reads files → Tool B writes files → Tool C executes (RCE chain)
 *   - Tool A accesses database → Tool B posts to webhook (data leak)
 *
 * This is a static analysis based on tool descriptions and schemas — it
 * doesn't execute the tools, just reasons about what they claim to do.
 */

import type { Finding } from './scanner.js';
import type { MCPTool } from './tool-prober.js';

// ─── Types ───────────────────────────────────────────────────────────

export interface FlowAnalysisResult {
  /** Tools analyzed */
  toolsAnalyzed: number;
  /** Tool capabilities extracted */
  capabilities: ToolCapability[];
  /** Toxic flow patterns detected */
  toxicFlows: ToxicFlow[];
  /** Aggregated findings */
  findings: Finding[];
}

export interface ToolCapability {
  toolName: string;
  /** What data this tool can read/access */
  reads: DataCategory[];
  /** What data this tool can write/send */
  writes: DataCategory[];
  /** What this tool can execute */
  executes: boolean;
}

export type DataCategory =
  | 'files'
  | 'secrets'
  | 'database'
  | 'network'
  | 'environment'
  | 'clipboard'
  | 'browser'
  | 'email'
  | 'messages'
  | 'code'
  | 'system';

export interface ToxicFlow {
  /** Flow pattern name */
  pattern: ToxicFlowPattern;
  /** Source tool (reads data) */
  source: string;
  /** Sink tool (sends/writes data) */
  sink: string;
  /** What data flows between them */
  dataType: DataCategory;
  /** Severity assessment */
  severity: 'critical' | 'high' | 'medium';
  /** Human-readable description */
  description: string;
}

export type ToxicFlowPattern =
  | 'secret-exfiltration'     // reads secrets → sends to network
  | 'file-exfiltration'       // reads files → sends to network
  | 'data-leak'               // reads database → sends to network
  | 'rce-chain'               // reads/writes files → executes
  | 'credential-theft'        // reads env/secrets → sends email/message
  | 'clipboard-exfiltration'  // reads clipboard → sends to network
  | 'lateral-movement'        // executes → accesses other systems
  | 'persistence'             // writes code → executes code
  | 'data-destruction'        // reads → writes (overwrite) → no backup
  ;

// ─── Capability Detection ──────────────────────────────────────────────

/**
 * Keyword patterns to determine what a tool can read/write/execute
 * based on its name, description, and inputSchema.
 */
const READ_PATTERNS: Map<DataCategory, RegExp[]> = new Map([
  ['files', [/read[_\s]?file/i, /get[_\s]?file/i, /list[_\s]?(files?|dir)/i, /cat\b/i, /open[_\s]?file/i, /file[_\s]?content/i, /load[_\s]?file/i]],
  ['secrets', [/get[_\s]?(secret|key|token|password|credential)/i, /read[_\s]?(secret|key|token|password)/i, /vault/i, /keychain/i, /credential/i]],
  ['database', [/query/i, /select\b/i, /read[_\s]?db/i, /get[_\s]?record/i, /fetch[_\s]?data/i, /database/i, /sql/i, /mongo/i]],
  ['network', [/fetch/i, /download/i, /http[_\s]?get/i, /get[_\s]?url/i, /scrape/i, /crawl/i, /browse/i, /web[_\s]?search/i]],
  ['environment', [/get[_\s]?env/i, /environment/i, /process[_\s.]env/i, /config/i, /settings/i]],
  ['clipboard', [/clipboard/i, /paste/i, /get[_\s]?clipboard/i]],
  ['browser', [/browser/i, /cookie/i, /session/i, /local[_\s]?storage/i, /bookmark/i]],
  ['email', [/read[_\s]?(email|mail|inbox)/i, /get[_\s]?(email|mail)/i, /list[_\s]?(email|mail)/i]],
  ['messages', [/read[_\s]?(message|chat|dm|notification)/i, /get[_\s]?(message|conversation)/i, /list[_\s]?(message|chat)/i]],
  ['code', [/read[_\s]?source/i, /get[_\s]?code/i, /source[_\s]?code/i, /repository/i, /git/i]],
  ['system', [/system[_\s]?info/i, /process[_\s]?list/i, /who(?:ami)?/i, /hostname/i, /uname/i]],
]);

const WRITE_PATTERNS: Map<DataCategory, RegExp[]> = new Map([
  ['files', [/write[_\s]?file/i, /create[_\s]?file/i, /save[_\s]?file/i, /edit[_\s]?file/i, /modify[_\s]?file/i, /upload/i, /put[_\s]?file/i]],
  ['network', [/send[_\s]?request/i, /post\b/i, /http[_\s]?post/i, /webhook/i, /notify/i, /push[_\s]?notification/i, /send[_\s]?data/i, /upload/i, /api[_\s]?call/i]],
  ['database', [/insert/i, /update[_\s]?record/i, /write[_\s]?db/i, /create[_\s]?record/i, /delete[_\s]?record/i, /drop\b/i]],
  ['email', [/send[_\s]?(email|mail)/i, /compose[_\s]?(email|mail)/i, /reply/i, /forward/i]],
  ['messages', [/send[_\s]?(message|chat|dm|notification)/i, /post[_\s]?(message|comment)/i, /reply/i, /slack/i, /discord/i]],
  ['code', [/write[_\s]?(code|script|program)/i, /create[_\s]?(script|function)/i, /generate[_\s]?code/i, /modify[_\s]?code/i]],
  ['system', [/kill[_\s]?process/i, /shutdown/i, /restart/i, /reboot/i]],
]);

const EXECUTE_PATTERNS = [
  /exec(ute)?/i, /run[_\s]?(command|script|code|shell|bash|program)/i,
  /shell/i, /bash/i, /terminal/i, /subprocess/i, /spawn/i,
  /eval(uate)?/i, /interpret/i, /compile[_\s]?and[_\s]?run/i,
];

/**
 * Extract capabilities from a tool's name, description, and inputSchema.
 */
function extractCapabilities(tool: MCPTool): ToolCapability {
  const text = `${tool.name} ${tool.description ?? ''} ${extractSchemaText(tool.inputSchema)}`;
  const reads: Set<DataCategory> = new Set();
  const writes: Set<DataCategory> = new Set();
  let executes = false;

  for (const [category, patterns] of READ_PATTERNS) {
    if (patterns.some(p => p.test(text))) reads.add(category);
  }

  for (const [category, patterns] of WRITE_PATTERNS) {
    if (patterns.some(p => p.test(text))) writes.add(category);
  }

  if (EXECUTE_PATTERNS.some(p => p.test(text))) executes = true;

  return {
    toolName: tool.name,
    reads: [...reads],
    writes: [...writes],
    executes,
  };
}

function extractSchemaText(schema?: Record<string, unknown>): string {
  if (!schema) return '';
  const parts: string[] = [];
  const props = schema.properties as Record<string, Record<string, unknown>> | undefined;
  if (props && typeof props === 'object') {
    for (const [name, def] of Object.entries(props)) {
      if (!def || typeof def !== 'object') continue;
      parts.push(name);
      if (typeof def.description === 'string') parts.push(def.description);
    }
  }
  return parts.join(' ');
}

// ─── Flow Rules ────────────────────────────────────────────────────────

interface FlowRule {
  pattern: ToxicFlowPattern;
  /** Source reads this data type */
  sourceReads: DataCategory;
  /** Sink writes this data type OR executes */
  sinkWrites?: DataCategory;
  sinkExecutes?: boolean;
  severity: 'critical' | 'high' | 'medium';
  description: (source: string, sink: string) => string;
}

const FLOW_RULES: FlowRule[] = [
  {
    pattern: 'secret-exfiltration',
    sourceReads: 'secrets',
    sinkWrites: 'network',
    severity: 'critical',
    description: (s, k) => `"${s}" can read secrets and "${k}" can send to network — secrets could be exfiltrated`,
  },
  {
    pattern: 'file-exfiltration',
    sourceReads: 'files',
    sinkWrites: 'network',
    severity: 'high',
    description: (s, k) => `"${s}" can read files and "${k}" can send to network — local files could be exfiltrated`,
  },
  {
    pattern: 'data-leak',
    sourceReads: 'database',
    sinkWrites: 'network',
    severity: 'critical',
    description: (s, k) => `"${s}" can query databases and "${k}" can send to network — database records could be leaked`,
  },
  {
    pattern: 'credential-theft',
    sourceReads: 'secrets',
    sinkWrites: 'email',
    severity: 'critical',
    description: (s, k) => `"${s}" can read secrets and "${k}" can send email — credentials could be emailed to attacker`,
  },
  {
    pattern: 'credential-theft',
    sourceReads: 'secrets',
    sinkWrites: 'messages',
    severity: 'critical',
    description: (s, k) => `"${s}" can read secrets and "${k}" can send messages — credentials could be sent to attacker`,
  },
  {
    pattern: 'credential-theft',
    sourceReads: 'environment',
    sinkWrites: 'network',
    severity: 'high',
    description: (s, k) => `"${s}" can read environment variables and "${k}" can send to network — env vars (API keys, tokens) could be exfiltrated`,
  },
  {
    pattern: 'clipboard-exfiltration',
    sourceReads: 'clipboard',
    sinkWrites: 'network',
    severity: 'high',
    description: (s, k) => `"${s}" can read clipboard and "${k}" can send to network — clipboard contents (passwords, etc.) could be exfiltrated`,
  },
  {
    pattern: 'rce-chain',
    sourceReads: 'files',
    sinkExecutes: true,
    severity: 'critical',
    description: (s, k) => `"${s}" can read/write files and "${k}" can execute code — remote code execution chain possible`,
  },
  {
    pattern: 'rce-chain',
    sourceReads: 'code',
    sinkExecutes: true,
    severity: 'critical',
    description: (s, k) => `"${s}" can access code and "${k}" can execute — arbitrary code execution possible`,
  },
  {
    pattern: 'persistence',
    sourceReads: 'code',
    sinkWrites: 'files',
    severity: 'high',
    description: (s, k) => `"${s}" accesses code and "${k}" writes files — could persist malicious code`,
  },
  {
    pattern: 'lateral-movement',
    sourceReads: 'system',
    sinkWrites: 'network',
    severity: 'high',
    description: (s, k) => `"${s}" gathers system info and "${k}" sends to network — reconnaissance data could be exfiltrated for lateral movement`,
  },
  {
    pattern: 'data-leak',
    sourceReads: 'browser',
    sinkWrites: 'network',
    severity: 'high',
    description: (s, k) => `"${s}" accesses browser data and "${k}" sends to network — cookies and sessions could be stolen`,
  },
];

// ─── Core Analyzer ──────────────────────────────────────────────────────

/**
 * Analyze cross-tool data flows for toxic patterns.
 *
 * Examines all pairs of tools to find dangerous source→sink combinations
 * where one tool can read sensitive data and another can send it out.
 */
export function analyzeFlows(tools: MCPTool[]): FlowAnalysisResult {
  const capabilities = tools.map(extractCapabilities);
  const toxicFlows: ToxicFlow[] = [];
  const findings: Finding[] = [];

  // Check all pairs (source → sink)
  for (const source of capabilities) {
    for (const sink of capabilities) {
      if (source.toolName === sink.toolName) continue;

      for (const rule of FLOW_RULES) {
        const sourceMatches = source.reads.includes(rule.sourceReads);

        let sinkMatches = false;
        if (rule.sinkWrites) {
          sinkMatches = sink.writes.includes(rule.sinkWrites);
        }
        if (rule.sinkExecutes) {
          sinkMatches = sinkMatches || sink.executes;
        }

        if (sourceMatches && sinkMatches) {
          // Avoid duplicate flows for the same pattern + pair
          const exists = toxicFlows.some(
            f => f.source === source.toolName && f.sink === sink.toolName && f.pattern === rule.pattern,
          );
          if (exists) continue;

          const desc = rule.description(source.toolName, sink.toolName);
          toxicFlows.push({
            pattern: rule.pattern,
            source: source.toolName,
            sink: sink.toolName,
            dataType: rule.sourceReads,
            severity: rule.severity,
            description: desc,
          });
          findings.push({
            severity: rule.severity,
            category: 'exfiltration',
            title: `Toxic flow: ${rule.pattern}`,
            description: desc,
            evidence: `${source.toolName} → ${sink.toolName}`,
          });
        }
      }
    }
  }

  // Also flag any single tool that both reads secrets and writes to network
  for (const cap of capabilities) {
    const readsSensitive = cap.reads.some(r => ['secrets', 'database', 'environment'].includes(r));
    const writesNetwork = cap.writes.includes('network');
    if (readsSensitive && writesNetwork) {
      findings.push({
        severity: 'critical',
        category: 'exfiltration',
        title: `Single tool exfiltration risk: "${cap.toolName}"`,
        description: `Tool "${cap.toolName}" can both read sensitive data (${cap.reads.join(', ')}) and send to network — single tool can exfiltrate data without any cross-tool flow`,
        evidence: cap.toolName,
      });
    }
  }

  return {
    toolsAnalyzed: tools.length,
    capabilities,
    toxicFlows,
    findings,
  };
}
