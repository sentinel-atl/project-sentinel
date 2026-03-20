/**
 * MCP Config Auto-Discovery
 *
 * Automatically detects MCP server configurations from popular AI clients:
 * - Claude Desktop (macOS, Windows, Linux)
 * - Cursor IDE
 * - Windsurf IDE
 * - VS Code (Copilot MCP config)
 * - Gemini CLI
 *
 * Reads their config files, extracts MCP server entries, and returns
 * structured data for scanning.
 */

import { readFile, access } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir, platform } from 'node:os';

// ─── Types ───────────────────────────────────────────────────────────

export interface DiscoveredServer {
  /** Human-readable name of the MCP server (from config key) */
  name: string;
  /** Command to start the server */
  command: string;
  /** Arguments passed to the command */
  args: string[];
  /** Environment variables configured for this server */
  env?: Record<string, string>;
  /** Which client configuration this was found in */
  source: MCPClientSource;
  /** Path to the config file where this was found */
  configPath: string;
}

export type MCPClientSource =
  | 'claude-desktop'
  | 'cursor'
  | 'windsurf'
  | 'vscode'
  | 'gemini-cli';

export interface DiscoveryResult {
  /** All discovered MCP server configurations */
  servers: DiscoveredServer[];
  /** Config files that were found and parsed */
  configsFound: string[];
  /** Config paths that were checked but not found */
  configsMissing: string[];
  /** Errors encountered during discovery */
  errors: Array<{ path: string; error: string }>;
}

// ─── Config Path Definitions ──────────────────────────────────────────

interface ConfigLocation {
  source: MCPClientSource;
  /** Function that returns the config file path for the current platform */
  getPath: () => string | null;
}

function getConfigLocations(): ConfigLocation[] {
  const home = homedir();
  const os = platform();

  return [
    // Claude Desktop
    {
      source: 'claude-desktop',
      getPath: () => {
        if (os === 'darwin') return join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
        if (os === 'win32') return join(home, 'AppData', 'Roaming', 'Claude', 'claude_desktop_config.json');
        if (os === 'linux') return join(home, '.config', 'claude', 'claude_desktop_config.json');
        return null;
      },
    },
    // Cursor IDE
    {
      source: 'cursor',
      getPath: () => {
        if (os === 'darwin') return join(home, '.cursor', 'mcp.json');
        if (os === 'win32') return join(home, '.cursor', 'mcp.json');
        if (os === 'linux') return join(home, '.cursor', 'mcp.json');
        return null;
      },
    },
    // Windsurf IDE
    {
      source: 'windsurf',
      getPath: () => {
        if (os === 'darwin') return join(home, '.codeium', 'windsurf', 'mcp_config.json');
        if (os === 'win32') return join(home, '.codeium', 'windsurf', 'mcp_config.json');
        if (os === 'linux') return join(home, '.codeium', 'windsurf', 'mcp_config.json');
        return null;
      },
    },
    // VS Code (Copilot MCP settings)
    {
      source: 'vscode',
      getPath: () => {
        if (os === 'darwin') return join(home, 'Library', 'Application Support', 'Code', 'User', 'settings.json');
        if (os === 'win32') return join(home, 'AppData', 'Roaming', 'Code', 'User', 'settings.json');
        if (os === 'linux') return join(home, '.config', 'Code', 'User', 'settings.json');
        return null;
      },
    },
    // Gemini CLI
    {
      source: 'gemini-cli',
      getPath: () => join(home, '.gemini', 'settings.json'),
    },
  ];
}

// ─── Config Parsers ───────────────────────────────────────────────────

/**
 * Parse Claude Desktop / Cursor / Windsurf config format.
 * These share a common format:
 * ```json
 * { "mcpServers": { "name": { "command": "...", "args": [...], "env": {...} } } }
 * ```
 */
function parseMcpServersBlock(
  data: Record<string, unknown>,
  source: MCPClientSource,
  configPath: string,
): DiscoveredServer[] {
  const servers: DiscoveredServer[] = [];
  const mcpServers = data.mcpServers as Record<string, unknown> | undefined;
  if (!mcpServers || typeof mcpServers !== 'object') return servers;

  for (const [name, config] of Object.entries(mcpServers)) {
    if (!config || typeof config !== 'object') continue;
    const entry = config as Record<string, unknown>;
    const command = typeof entry.command === 'string' ? entry.command : '';
    if (!command) continue;

    const args = Array.isArray(entry.args)
      ? entry.args.filter((a): a is string => typeof a === 'string')
      : [];
    const env = entry.env && typeof entry.env === 'object'
      ? Object.fromEntries(
          Object.entries(entry.env as Record<string, unknown>)
            .filter(([, v]) => typeof v === 'string') as [string, string][]
        )
      : undefined;

    servers.push({ name, command, args, env, source, configPath });
  }
  return servers;
}

/**
 * Parse VS Code settings.json — MCP servers are under `mcp.servers`.
 * Format:
 * ```json
 * { "mcp": { "servers": { "name": { "command": "...", "args": [...] } } } }
 * ```
 */
function parseVSCodeSettings(
  data: Record<string, unknown>,
  configPath: string,
): DiscoveredServer[] {
  const servers: DiscoveredServer[] = [];
  const mcp = data.mcp as Record<string, unknown> | undefined;
  if (!mcp || typeof mcp !== 'object') return servers;

  const mcpServers = mcp.servers as Record<string, unknown> | undefined;
  if (!mcpServers || typeof mcpServers !== 'object') return servers;

  for (const [name, config] of Object.entries(mcpServers)) {
    if (!config || typeof config !== 'object') continue;
    const entry = config as Record<string, unknown>;
    const command = typeof entry.command === 'string' ? entry.command : '';
    if (!command) continue;

    const args = Array.isArray(entry.args)
      ? entry.args.filter((a): a is string => typeof a === 'string')
      : [];
    const env = entry.env && typeof entry.env === 'object'
      ? Object.fromEntries(
          Object.entries(entry.env as Record<string, unknown>)
            .filter(([, v]) => typeof v === 'string') as [string, string][]
        )
      : undefined;

    servers.push({ name, command, args, env, source: 'vscode', configPath });
  }
  return servers;
}

/**
 * Parse Gemini CLI settings.json — MCP servers under `mcpServers`.
 */
function parseGeminiSettings(
  data: Record<string, unknown>,
  configPath: string,
): DiscoveredServer[] {
  return parseMcpServersBlock(data, 'gemini-cli', configPath);
}

// ─── Main Discovery Function ─────────────────────────────────────────

/**
 * Discover all MCP server configurations on the local machine.
 *
 * Scans known config file locations for Claude Desktop, Cursor, Windsurf,
 * VS Code, and Gemini CLI. Returns structured data about every MCP server
 * found across all clients.
 */
export async function discoverMCPConfigs(): Promise<DiscoveryResult> {
  const locations = getConfigLocations();
  const result: DiscoveryResult = {
    servers: [],
    configsFound: [],
    configsMissing: [],
    errors: [],
  };

  for (const loc of locations) {
    const configPath = loc.getPath();
    if (!configPath) continue;

    try {
      await access(configPath);
    } catch {
      result.configsMissing.push(configPath);
      continue;
    }

    try {
      const content = await readFile(configPath, 'utf-8');
      const data = JSON.parse(content) as Record<string, unknown>;

      let servers: DiscoveredServer[];
      if (loc.source === 'vscode') {
        servers = parseVSCodeSettings(data, configPath);
      } else if (loc.source === 'gemini-cli') {
        servers = parseGeminiSettings(data, configPath);
      } else {
        servers = parseMcpServersBlock(data, loc.source, configPath);
      }

      result.servers.push(...servers);
      result.configsFound.push(configPath);
    } catch (err) {
      result.errors.push({
        path: configPath,
        error: (err as Error).message,
      });
    }
  }

  return result;
}
