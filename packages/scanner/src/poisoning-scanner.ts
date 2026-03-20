/**
 * Tool Poisoning Scanner
 *
 * Detects hidden injection patterns in MCP tool descriptions.
 * Malicious MCP servers can embed invisible instructions in tool descriptions
 * that manipulate the LLM's behavior — a form of indirect prompt injection.
 *
 * Detection techniques:
 * 1. Invisible Unicode characters (zero-width spaces, RTL overrides, etc.)
 * 2. Excessive whitespace hiding instructions
 * 3. Instruction injection patterns ("ignore previous", "you must", etc.)
 * 4. Data exfiltration instructions in descriptions
 * 5. Cross-tool manipulation ("before calling X, first call Y")
 */

import type { Finding } from './scanner.js';
import type { MCPTool } from './tool-prober.js';

// ─── Types ───────────────────────────────────────────────────────────

export interface PoisoningResult {
  /** Tools analyzed */
  toolsAnalyzed: number;
  /** Tools flagged as potentially poisoned */
  poisonedTools: PoisonedTool[];
  /** Aggregated findings */
  findings: Finding[];
}

export interface PoisonedTool {
  /** Tool name */
  toolName: string;
  /** Type of poisoning detected */
  techniques: PoisoningTechnique[];
  /** The suspicious content found */
  evidence: string;
}

export type PoisoningTechnique =
  | 'invisible-unicode'
  | 'hidden-whitespace'
  | 'instruction-injection'
  | 'exfiltration-instruction'
  | 'cross-tool-manipulation'
  | 'description-mismatch';

// ─── Detection Patterns ───────────────────────────────────────────────

/**
 * Unicode characters that are invisible but can carry instructions.
 * These can be hidden in tool descriptions and only seen by the LLM tokenizer.
 */
const INVISIBLE_UNICODE = [
  '\u200B', // Zero-width space
  '\u200C', // Zero-width non-joiner
  '\u200D', // Zero-width joiner
  '\u200E', // Left-to-right mark
  '\u200F', // Right-to-left mark
  '\u202A', // Left-to-right embedding
  '\u202B', // Right-to-left embedding
  '\u202C', // Pop directional formatting
  '\u202D', // Left-to-right override
  '\u202E', // Right-to-left override
  '\u2060', // Word joiner
  '\u2061', // Function application
  '\u2062', // Invisible times
  '\u2063', // Invisible separator
  '\u2064', // Invisible plus
  '\uFEFF', // Zero-width no-break space (BOM)
  '\u00AD', // Soft hyphen
  '\u034F', // Combining grapheme joiner
  '\u061C', // Arabic letter mark
  '\u115F', // Hangul choseong filler
  '\u1160', // Hangul jungseong filler
  '\u17B4', // Khmer vowel inherent aq
  '\u17B5', // Khmer vowel inherent aa
  '\u180E', // Mongolian vowel separator
];

const INVISIBLE_REGEX = new RegExp(`[${INVISIBLE_UNICODE.join('')}]`, 'g');

/**
 * Patterns indicating instruction injection in tool descriptions.
 * These try to manipulate the LLM into doing something beyond the tool's stated purpose.
 */
const INJECTION_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /ignore\s+(all\s+)?previous\s+(instructions?|context|rules)/i, label: 'Overrides previous instructions' },
  { pattern: /you\s+(must|should|have\s+to|need\s+to)\s+(always|never|first)/i, label: 'Forceful behavioral directive' },
  { pattern: /do\s+not\s+(tell|inform|reveal|show|mention)/i, label: 'Secrecy instruction' },
  { pattern: /before\s+(respond|answer|call|us)ing/i, label: 'Pre-action manipulation' },
  { pattern: /system\s*prompt/i, label: 'References system prompt' },
  { pattern: /act\s+as\s+(if|though|a)/i, label: 'Role manipulation' },
  { pattern: /pretend\s+(you|to\s+be|that)/i, label: 'Role manipulation' },
  { pattern: /override\s+(your|the|any)/i, label: 'Override instruction' },
  { pattern: /\bIMPORTANT\s*:/i, label: 'Emphasis marker for injection' },
  { pattern: /\bCRITICAL\s*:/i, label: 'Emphasis marker for injection' },
  { pattern: /\[SYSTEM\]/i, label: 'Fake system message marker' },
  { pattern: /<<\s*SYS\s*>>/i, label: 'Fake system message delimiter' },
  { pattern: /\buser_?password\b|\bapi_?key\b|\baccess_?token\b/i, label: 'References credentials' },
];

/**
 * Patterns indicating data exfiltration instructions.
 */
const EXFILTRATION_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /send\s+(to|data|the|all|user|information)\b.*\b(url|http|endpoint|server|webhook)/i, label: 'Data sending instruction' },
  { pattern: /include\s+(the\s+)?(conversation|chat|context|history|previous)/i, label: 'Conversation exfiltration' },
  { pattern: /append\s+(to\s+)?(the\s+)?(url|request|query|param)/i, label: 'Data appended to requests' },
  { pattern: /encode\s+(the\s+)?(response|data|content|conversation)\s+(in|as|to)\s+(base64|hex|url)/i, label: 'Data encoding for exfiltration' },
  { pattern: /https?:\/\/[^\s]+/i, label: 'Embedded URL in description' },
];

/**
 * Cross-tool manipulation — instructions that reference other tools.
 */
const CROSS_TOOL_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /before\s+(calling|using|invoking)\s+(this|the|any)\s+tool/i, label: 'Pre-call instruction' },
  { pattern: /after\s+(calling|using|invoking)\s+(this|the|any)\s+tool/i, label: 'Post-call instruction' },
  { pattern: /also\s+(call|invoke|use|run)\s+/i, label: 'Chained tool instruction' },
  { pattern: /instead\s+of\s+(calling|using|invoking)/i, label: 'Tool substitution instruction' },
  { pattern: /redirect\s+(to|the|output|result)/i, label: 'Output redirection instruction' },
  { pattern: /pipe\s+(the\s+)?(output|result|data)\s+(to|into)/i, label: 'Data piping instruction' },
];

// ─── Core Scanner ──────────────────────────────────────────────────────

/**
 * Scan MCP tool declarations for poisoning patterns.
 */
export function scanToolPoisoning(tools: MCPTool[]): PoisoningResult {
  const findings: Finding[] = [];
  const poisonedTools: PoisonedTool[] = [];

  for (const tool of tools) {
    const techniques: PoisoningTechnique[] = [];
    const evidenceParts: string[] = [];

    // Check both name and description
    const desc = tool.description ?? '';
    const nameAndDesc = `${tool.name} ${desc}`;

    // 1. Invisible Unicode detection
    const invisibleMatches = desc.match(INVISIBLE_REGEX);
    if (invisibleMatches && invisibleMatches.length > 0) {
      techniques.push('invisible-unicode');
      evidenceParts.push(`${invisibleMatches.length} invisible Unicode character(s) found`);
      findings.push({
        severity: 'critical',
        category: 'dangerous-pattern',
        title: `Hidden Unicode in tool "${tool.name}"`,
        description: `Tool description contains ${invisibleMatches.length} invisible Unicode character(s) that may hide injected instructions`,
        evidence: `Characters: ${invisibleMatches.map(c => `U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}`).join(', ')}`,
      });
    }

    // 2. Hidden whitespace detection — excessive line breaks, tabs, or trailing spaces
    const lines = desc.split('\n');
    const suspiciousWhitespace = lines.some(line => {
      const trailing = line.length - line.trimEnd().length;
      return trailing > 20; // 20+ trailing spaces is suspicious
    });
    const excessiveNewlines = (desc.match(/\n{5,}/g) ?? []).length > 0;

    if (suspiciousWhitespace || excessiveNewlines) {
      techniques.push('hidden-whitespace');
      evidenceParts.push('Excessive whitespace may hide instructions');
      findings.push({
        severity: 'high',
        category: 'dangerous-pattern',
        title: `Suspicious whitespace in tool "${tool.name}"`,
        description: 'Tool description contains excessive whitespace that may hide instructions after apparent end of text',
        evidence: `Description length: ${desc.length} chars, ${lines.length} lines`,
      });
    }

    // 3. Instruction injection patterns
    for (const { pattern, label } of INJECTION_PATTERNS) {
      if (pattern.test(desc)) {
        if (!techniques.includes('instruction-injection')) {
          techniques.push('instruction-injection');
        }
        evidenceParts.push(label);
        findings.push({
          severity: 'critical',
          category: 'dangerous-pattern',
          title: `Prompt injection in tool "${tool.name}": ${label}`,
          description: `Tool description contains an instruction injection pattern: "${desc.match(pattern)?.[0]}"`,
          evidence: desc.slice(0, 120),
        });
      }
    }

    // 4. Exfiltration instructions
    for (const { pattern, label } of EXFILTRATION_PATTERNS) {
      if (pattern.test(desc)) {
        if (!techniques.includes('exfiltration-instruction')) {
          techniques.push('exfiltration-instruction');
        }
        evidenceParts.push(label);
        findings.push({
          severity: 'critical',
          category: 'exfiltration',
          title: `Data exfiltration instruction in tool "${tool.name}": ${label}`,
          description: `Tool description contains instructions that could exfiltrate user data`,
          evidence: desc.slice(0, 120),
        });
      }
    }

    // 5. Cross-tool manipulation
    for (const { pattern, label } of CROSS_TOOL_PATTERNS) {
      if (pattern.test(desc)) {
        if (!techniques.includes('cross-tool-manipulation')) {
          techniques.push('cross-tool-manipulation');
        }
        evidenceParts.push(label);
        findings.push({
          severity: 'high',
          category: 'dangerous-pattern',
          title: `Cross-tool manipulation in "${tool.name}": ${label}`,
          description: `Tool description tries to influence how other tools are called`,
          evidence: desc.slice(0, 120),
        });
      }
    }

    // 6. Description length anomaly — very long descriptions are suspicious
    if (desc.length > 2000) {
      techniques.push('description-mismatch');
      evidenceParts.push(`Unusually long description (${desc.length} chars)`);
      findings.push({
        severity: 'medium',
        category: 'dangerous-pattern',
        title: `Unusually long description for tool "${tool.name}"`,
        description: `Tool description is ${desc.length} characters — may contain hidden instructions buried in verbosity`,
        evidence: desc.slice(0, 120),
      });
    }

    // Check inputSchema descriptions too
    if (tool.inputSchema) {
      checkSchemaForPoisoning(tool.name, tool.inputSchema, findings, techniques, evidenceParts);
    }

    if (techniques.length > 0) {
      poisonedTools.push({
        toolName: tool.name,
        techniques,
        evidence: evidenceParts.join('; '),
      });
    }
  }

  return {
    toolsAnalyzed: tools.length,
    poisonedTools,
    findings,
  };
}

/**
 * Recursively check inputSchema property descriptions for injection patterns.
 */
function checkSchemaForPoisoning(
  toolName: string,
  schema: Record<string, unknown>,
  findings: Finding[],
  techniques: PoisoningTechnique[],
  evidenceParts: string[],
): void {
  const properties = schema.properties as Record<string, Record<string, unknown>> | undefined;
  if (!properties || typeof properties !== 'object') return;

  for (const [propName, propDef] of Object.entries(properties)) {
    if (!propDef || typeof propDef !== 'object') continue;
    const desc = typeof propDef.description === 'string' ? propDef.description : '';

    // Check for invisible unicode
    const invisibleMatches = desc.match(INVISIBLE_REGEX);
    if (invisibleMatches && invisibleMatches.length > 0) {
      if (!techniques.includes('invisible-unicode')) techniques.push('invisible-unicode');
      evidenceParts.push(`Hidden Unicode in param "${propName}"`);
      findings.push({
        severity: 'critical',
        category: 'dangerous-pattern',
        title: `Hidden Unicode in "${toolName}.${propName}" schema`,
        description: `Input parameter description contains invisible Unicode characters`,
        evidence: `${invisibleMatches.length} hidden character(s)`,
      });
    }

    // Check for injection patterns
    for (const { pattern, label } of INJECTION_PATTERNS) {
      if (pattern.test(desc)) {
        if (!techniques.includes('instruction-injection')) techniques.push('instruction-injection');
        evidenceParts.push(`Injection in param "${propName}": ${label}`);
        findings.push({
          severity: 'critical',
          category: 'dangerous-pattern',
          title: `Injection in "${toolName}.${propName}": ${label}`,
          description: `Input parameter description contains injection pattern`,
          evidence: desc.slice(0, 120),
        });
      }
    }
  }
}
