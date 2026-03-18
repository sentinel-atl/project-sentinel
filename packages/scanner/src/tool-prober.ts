/**
 * MCP Tool Prober — connects to an MCP server and discovers its tool declarations.
 *
 * Starts the server in a sandboxed subprocess and calls `tools/list`
 * to enumerate what tools the server exposes. This is runtime analysis
 * that complements the static code scanning.
 */

import { spawn, type ChildProcess } from 'node:child_process';
import { createInterface } from 'node:readline';
import { randomUUID } from 'node:crypto';
import type { Finding } from './scanner.js';

// ─── Types ───────────────────────────────────────────────────────────

export interface MCPTool {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export interface ToolProbeResult {
  /** Whether the probe succeeded */
  success: boolean;
  /** Error message if probe failed */
  error?: string;
  /** Server name from initialize response */
  serverName?: string;
  /** Server version from initialize response */
  serverVersion?: string;
  /** Discovered tools */
  tools: MCPTool[];
  /** Findings from tool analysis */
  findings: Finding[];
  /** Probe duration in ms */
  durationMs: number;
}

export interface ProbeOptions {
  /** Command to start the MCP server (e.g., "node dist/index.js") */
  command: string;
  /** Arguments to pass to the command */
  args?: string[];
  /** Working directory */
  cwd?: string;
  /** Timeout for the entire probe in ms (default: 15000) */
  timeoutMs?: number;
  /** Environment variables to set */
  env?: Record<string, string>;
}

// ─── Suspicious tool patterns ─────────────────────────────────────────

const SUSPICIOUS_TOOL_NAMES = [
  /exec/i, /shell/i, /command/i, /run_code/i, /system/i,
  /eval/i, /upload/i, /download/i, /delete_all/i, /drop/i,
  /admin/i, /root/i, /sudo/i, /install/i, /uninstall/i,
];

const DANGEROUS_TOOL_DESCRIPTIONS = [
  /execut(?:e|ing)\s+(?:arbitrary|any|shell|system)/i,
  /run\s+(?:any|arbitrary|shell)/i,
  /delete\s+(?:all|everything|any)/i,
  /access\s+(?:all|any)\s+files/i,
  /modify\s+system/i,
];

// ─── Prober ───────────────────────────────────────────────────────────

/**
 * Probe an MCP server to discover its tools.
 */
export async function probeTools(options: ProbeOptions): Promise<ToolProbeResult> {
  const start = Date.now();
  const timeoutMs = options.timeoutMs ?? 15_000;
  const findings: Finding[] = [];

  let child: ChildProcess | null = null;

  try {
    // Start the server process
    child = spawn(options.command, options.args ?? [], {
      cwd: options.cwd,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, ...options.env },
      timeout: timeoutMs,
    });

    const reader = createInterface({ input: child.stdout! });

    // Helper: send JSON-RPC message and wait for response
    const sendRequest = (method: string, params?: Record<string, unknown>): Promise<any> => {
      return new Promise((resolve, reject) => {
        const id = randomUUID();
        const msg = JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n';

        const timeout = setTimeout(() => {
          cleanup();
          reject(new Error(`Request timed out: ${method}`));
        }, Math.min(timeoutMs, 10_000));

        const onLine = (line: string) => {
          try {
            const resp = JSON.parse(line);
            if (resp.id === id) {
              cleanup();
              if (resp.error) {
                reject(new Error(resp.error.message ?? 'RPC error'));
              } else {
                resolve(resp.result);
              }
            }
          } catch {
            // Not our response
          }
        };

        const cleanup = () => {
          clearTimeout(timeout);
          reader.removeListener('line', onLine);
        };

        reader.on('line', onLine);
        child!.stdin!.write(msg);
      });
    };

    // Step 1: Initialize
    const initResult = await sendRequest('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: { name: 'sentinel-prober', version: '0.3.0' },
    });

    const serverName = initResult?.serverInfo?.name;
    const serverVersion = initResult?.serverInfo?.version;

    // Send initialized notification
    child.stdin!.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');

    // Step 2: List tools
    const toolsResult = await sendRequest('tools/list', {});
    const tools: MCPTool[] = (toolsResult?.tools ?? []).map((t: any) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
    }));

    // Step 3: Analyze tool declarations for suspicious patterns
    for (const tool of tools) {
      for (const pattern of SUSPICIOUS_TOOL_NAMES) {
        if (pattern.test(tool.name)) {
          findings.push({
            severity: 'high',
            category: 'dangerous-pattern',
            title: `Suspicious tool name: "${tool.name}"`,
            description: `Tool "${tool.name}" has a name matching a dangerous pattern (${pattern.source})`,
          });
          break;
        }
      }

      if (tool.description) {
        for (const pattern of DANGEROUS_TOOL_DESCRIPTIONS) {
          if (pattern.test(tool.description)) {
            findings.push({
              severity: 'high',
              category: 'dangerous-pattern',
              title: `Dangerous tool description: "${tool.name}"`,
              description: `Tool "${tool.name}" description suggests dangerous capabilities: ${tool.description.slice(0, 100)}`,
            });
            break;
          }
        }
      }
    }

    // Many tools is itself a code smell
    if (tools.length > 50) {
      findings.push({
        severity: 'medium',
        category: 'dangerous-pattern',
        title: `Excessive tool count: ${tools.length} tools`,
        description: 'Servers with many tools may have an overly broad attack surface',
      });
    }

    return {
      success: true,
      serverName,
      serverVersion,
      tools,
      findings,
      durationMs: Date.now() - start,
    };
  } catch (err) {
    return {
      success: false,
      error: (err as Error).message,
      tools: [],
      findings,
      durationMs: Date.now() - start,
    };
  } finally {
    if (child && !child.killed) {
      child.kill('SIGTERM');
      // Force kill after 2s
      setTimeout(() => {
        if (child && !child.killed) child.kill('SIGKILL');
      }, 2000);
    }
  }
}
