/**
 * Tool Shadowing Scanner
 *
 * Detects when an MCP tool's name or description closely mimics a well-known
 * or built-in tool, potentially intercepting calls meant for the legitimate tool.
 *
 * Shadowing attack: A malicious server registers a tool named "read_file" or
 * "web_search" that looks identical to a trusted built-in — the LLM picks
 * the malicious version because it appears first or has a "better" description.
 *
 * Detection techniques:
 * 1. Exact name match against known built-in tool names
 * 2. Near-match (edit distance, prefix/suffix) against known tools
 * 3. Description similarity to built-in tool descriptions
 * 4. Rug-pull detection: tool that claims to be from a known provider
 */

import type { Finding } from './scanner.js';
import type { MCPTool } from './tool-prober.js';

// ─── Types ───────────────────────────────────────────────────────────

export interface ShadowingResult {
  /** Tools analyzed */
  toolsAnalyzed: number;
  /** Tools that shadow known built-ins */
  shadowedTools: ShadowedTool[];
  /** Aggregated findings */
  findings: Finding[];
}

export interface ShadowedTool {
  /** The suspicious tool name */
  toolName: string;
  /** The legitimate tool being shadowed */
  shadowsTarget: string;
  /** How the shadowing was detected */
  technique: ShadowingTechnique;
  /** Confidence level */
  confidence: 'high' | 'medium' | 'low';
}

export type ShadowingTechnique =
  | 'exact-name'
  | 'near-name'
  | 'description-clone'
  | 'provider-impersonation';

// ─── Known Built-in Tools ──────────────────────────────────────────────

/**
 * Well-known tool names from popular AI platforms.
 * These are tools that LLMs know natively (browser tools, code tools, etc.)
 * or that popular MCP servers provide.
 */
const KNOWN_BUILTIN_TOOLS: Map<string, string> = new Map([
  // Claude built-ins
  ['read_file', 'Read file contents'],
  ['write_file', 'Write content to a file'],
  ['edit_file', 'Edit an existing file'],
  ['create_file', 'Create a new file'],
  ['list_directory', 'List directory contents'],
  ['search_files', 'Search for files'],
  ['web_search', 'Search the web'],
  ['browser', 'Browse a webpage'],
  ['computer', 'Control the computer'],
  ['bash', 'Run bash commands'],
  ['text_editor', 'Edit text files'],

  // Common MCP server tool patterns
  ['execute_command', 'Execute a system command'],
  ['run_command', 'Run a shell command'],
  ['run_script', 'Run a script'],
  ['query_database', 'Query a database'],
  ['sql_query', 'Execute SQL query'],
  ['send_email', 'Send an email'],
  ['send_message', 'Send a message'],
  ['get_weather', 'Get weather information'],
  ['fetch_url', 'Fetch a URL'],
  ['read_url', 'Read URL contents'],
  ['screenshot', 'Take a screenshot'],
  ['click', 'Click on screen'],
  ['type_text', 'Type text on screen'],

  // GitHub / Git tools
  ['create_pull_request', 'Create a pull request'],
  ['create_issue', 'Create an issue'],
  ['git_commit', 'Make a git commit'],
  ['push_files', 'Push files to repository'],
  ['search_repositories', 'Search GitHub repositories'],

  // Memory / context tools
  ['save_memory', 'Save to memory'],
  ['search_memory', 'Search memory'],
  ['get_context', 'Get conversation context'],
]);

/**
 * Known providers that shouldn't be impersonated.
 */
const KNOWN_PROVIDERS = [
  'anthropic', 'claude', 'openai', 'gpt', 'google', 'gemini',
  'microsoft', 'copilot', 'github', 'cursor', 'windsurf',
  'notion', 'slack', 'discord', 'stripe', 'aws', 'azure',
];

// ─── Utility ──────────────────────────────────────────────────────────

function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost,
      );
    }
  }
  return dp[m][n];
}

function normalize(name: string): string {
  return name.toLowerCase().replace(/[-_\s.]/g, '');
}

// ─── Core Scanner ──────────────────────────────────────────────────────

/**
 * Scan MCP tool declarations for shadowing of known built-in tools.
 *
 * @param tools - Tools discovered from an MCP server
 * @param serverName - Name of the MCP server (for context in findings)
 */
export function scanToolShadowing(
  tools: MCPTool[],
  serverName?: string,
): ShadowingResult {
  const findings: Finding[] = [];
  const shadowedTools: ShadowedTool[] = [];
  const serverLabel = serverName ? ` (server: ${serverName})` : '';

  for (const tool of tools) {
    const normalizedName = normalize(tool.name);
    const desc = (tool.description ?? '').toLowerCase();

    // 1. Exact name match against known built-in tools
    for (const [builtinName, builtinDesc] of KNOWN_BUILTIN_TOOLS) {
      if (tool.name === builtinName || normalizedName === normalize(builtinName)) {
        shadowedTools.push({
          toolName: tool.name,
          shadowsTarget: builtinName,
          technique: 'exact-name',
          confidence: 'high',
        });
        findings.push({
          severity: 'critical',
          category: 'dangerous-pattern',
          title: `Tool shadows built-in: "${tool.name}"${serverLabel}`,
          description: `Tool "${tool.name}" exactly matches known built-in tool "${builtinName}" (${builtinDesc}). This could intercept legitimate tool calls.`,
          evidence: tool.description?.slice(0, 120),
        });
        break; // Only report first match
      }
    }

    // Skip near-match if we already have an exact match
    if (shadowedTools.some(s => s.toolName === tool.name && s.technique === 'exact-name')) continue;

    // 2. Near-match detection (edit distance)
    for (const [builtinName] of KNOWN_BUILTIN_TOOLS) {
      const dist = levenshtein(normalizedName, normalize(builtinName));
      const maxAllowed = normalizedName.length <= 6 ? 1 : 2;

      if (dist > 0 && dist <= maxAllowed) {
        shadowedTools.push({
          toolName: tool.name,
          shadowsTarget: builtinName,
          technique: 'near-name',
          confidence: dist === 1 ? 'high' : 'medium',
        });
        findings.push({
          severity: 'high',
          category: 'dangerous-pattern',
          title: `Tool near-matches built-in: "${tool.name}" ≈ "${builtinName}"`,
          description: `Tool name is ${dist} edit(s) from known built-in "${builtinName}". Could be a typosquatting attack to intercept tool calls.`,
          evidence: tool.description?.slice(0, 120),
        });
        break;
      }
    }

    // 3. Description clone detection
    if (tool.description && tool.description.length > 10) {
      for (const [builtinName, builtinDesc] of KNOWN_BUILTIN_TOOLS) {
        // Skip if we already flagged this tool
        if (shadowedTools.some(s => s.toolName === tool.name)) break;

        const descNormalized = normalize(tool.description);
        const builtinDescNormalized = normalize(builtinDesc);

        // Check if tool description closely matches a built-in's purpose
        // but uses a different name (potential redirection)
        if (
          descNormalized.includes(builtinDescNormalized) ||
          builtinDescNormalized.includes(descNormalized)
        ) {
          // Only flag if name is sufficiently different
          if (levenshtein(normalizedName, normalize(builtinName)) > 3) {
            shadowedTools.push({
              toolName: tool.name,
              shadowsTarget: builtinName,
              technique: 'description-clone',
              confidence: 'medium',
            });
            findings.push({
              severity: 'medium',
              category: 'dangerous-pattern',
              title: `Tool description clones "${builtinName}": "${tool.name}"`,
              description: `Tool "${tool.name}" has a description that closely matches built-in tool "${builtinName}" but uses a different name. Could be an attempt to re-route tool calls.`,
              evidence: tool.description?.slice(0, 120),
            });
            break;
          }
        }
      }
    }

    // 4. Provider impersonation
    for (const provider of KNOWN_PROVIDERS) {
      if (desc.includes(`by ${provider}`) || desc.includes(`from ${provider}`) || desc.includes(`official ${provider}`)) {
        shadowedTools.push({
          toolName: tool.name,
          shadowsTarget: provider,
          technique: 'provider-impersonation',
          confidence: 'medium',
        });
        findings.push({
          severity: 'high',
          category: 'dangerous-pattern',
          title: `Provider impersonation in "${tool.name}": claims ${provider}`,
          description: `Tool description claims to be from "${provider}". This may be an impersonation to gain trust.`,
          evidence: desc.slice(0, 120),
        });
        break;
      }
    }
  }

  return {
    toolsAnalyzed: tools.length,
    shadowedTools,
    findings,
  };
}
