/**
 * YAML configuration loader and validator for the trust gateway.
 *
 * Example sentinel.yaml:
 *
 * gateway:
 *   name: my-trust-gateway
 *   port: 3100
 *   mode: strict           # strict = reject unverified, permissive = warn only
 *   minTrustScore: 60      # global minimum trust score (0-100)
 *   minGrade: C            # global minimum grade (A-F)
 *   logPath: ./audit.jsonl
 *
 * servers:
 *   - name: filesystem
 *     upstream: stdio://node server.js
 *     trust:
 *       minScore: 75
 *       minGrade: B
 *       requireCertificate: true
 *       maxFindingsCritical: 0
 *       maxFindingsHigh: 2
 *       allowedPermissions: [filesystem]
 *     rateLimit: 100/min
 *     blockedTools: [delete_file, write_file]
 *
 *   - name: web-search
 *     upstream: http://localhost:4000/sse
 *     trust:
 *       minScore: 50
 *       allowedPermissions: [network]
 */

import { readFile } from 'node:fs/promises';
import { parse as parseYaml } from 'yaml';

// ─── Types ───────────────────────────────────────────────────────────

export interface TrustRequirements {
  /** Minimum trust score (0-100) */
  minScore?: number;
  /** Minimum grade (A-F) */
  minGrade?: string;
  /** Whether a valid STC is required */
  requireCertificate?: boolean;
  /** Maximum allowed critical findings */
  maxFindingsCritical?: number;
  /** Maximum allowed high findings */
  maxFindingsHigh?: number;
  /** Allowed permission kinds (whitelist) */
  allowedPermissions?: string[];
  /** Blocked permission kinds (blacklist) */
  blockedPermissions?: string[];
}

export interface ServerPolicy {
  /** Server name */
  name: string;
  /** Upstream MCP server connection (stdio:// or http://) */
  upstream: string;
  /** Trust requirements for this server */
  trust?: TrustRequirements;
  /** Rate limit (e.g., "100/min", "1000/hour") */
  rateLimit?: string;
  /** Blocked tool names */
  blockedTools?: string[];
  /** Allowed tool names (whitelist — if set, only these tools are allowed) */
  allowedTools?: string[];
  /** Path to the server's STC file */
  certificatePath?: string;
}

export interface GatewayConfig {
  gateway: {
    name: string;
    port: number;
    mode: 'strict' | 'permissive';
    minTrustScore?: number;
    minGrade?: string;
    logPath?: string;
    /** API keys for authentication (comma-separated in YAML, or use env SENTINEL_API_KEYS) */
    apiKeys?: string[];
    /** Allowed CORS origins (comma-separated in YAML, or use env SENTINEL_CORS_ORIGINS) */
    corsOrigins?: string[];
    /** Path to TLS certificate file */
    tlsCert?: string;
    /** Path to TLS key file */
    tlsKey?: string;
    /** Global rate limit (e.g. "1000/min") */
    rateLimit?: string;
  };
  servers: ServerPolicy[];
}

// ─── Validators ──────────────────────────────────────────────────────

const VALID_GRADES = ['A', 'B', 'C', 'D', 'F'];
const VALID_PERMISSIONS = ['filesystem', 'network', 'process', 'crypto', 'environment', 'native'];

export interface ConfigError {
  path: string;
  message: string;
}

export function validateConfig(config: GatewayConfig): ConfigError[] {
  const errors: ConfigError[] = [];

  if (!config.gateway) {
    errors.push({ path: 'gateway', message: 'Missing gateway configuration' });
    return errors;
  }

  if (!config.gateway.name) {
    errors.push({ path: 'gateway.name', message: 'Gateway name is required' });
  }

  if (!config.gateway.port || config.gateway.port < 1 || config.gateway.port > 65535) {
    errors.push({ path: 'gateway.port', message: 'Port must be between 1 and 65535' });
  }

  if (!['strict', 'permissive'].includes(config.gateway.mode)) {
    errors.push({ path: 'gateway.mode', message: 'Mode must be "strict" or "permissive"' });
  }

  if (config.gateway.minTrustScore !== undefined &&
      (config.gateway.minTrustScore < 0 || config.gateway.minTrustScore > 100)) {
    errors.push({ path: 'gateway.minTrustScore', message: 'Score must be 0-100' });
  }

  if (config.gateway.minGrade !== undefined && !VALID_GRADES.includes(config.gateway.minGrade)) {
    errors.push({ path: 'gateway.minGrade', message: `Grade must be one of: ${VALID_GRADES.join(', ')}` });
  }

  if (!Array.isArray(config.servers)) {
    errors.push({ path: 'servers', message: 'Servers must be an array' });
    return errors;
  }

  for (let i = 0; i < config.servers.length; i++) {
    const server = config.servers[i];
    const prefix = `servers[${i}]`;

    if (!server.name) {
      errors.push({ path: `${prefix}.name`, message: 'Server name is required' });
    }

    if (!server.upstream) {
      errors.push({ path: `${prefix}.upstream`, message: 'Upstream is required' });
    } else if (!server.upstream.startsWith('stdio://') &&
               !server.upstream.startsWith('http://') &&
               !server.upstream.startsWith('https://')) {
      errors.push({ path: `${prefix}.upstream`, message: 'Upstream must start with stdio://, http://, or https://' });
    }

    if (server.trust?.minGrade && !VALID_GRADES.includes(server.trust.minGrade)) {
      errors.push({ path: `${prefix}.trust.minGrade`, message: `Grade must be one of: ${VALID_GRADES.join(', ')}` });
    }

    if (server.trust?.allowedPermissions) {
      for (const perm of server.trust.allowedPermissions) {
        if (!VALID_PERMISSIONS.includes(perm)) {
          errors.push({ path: `${prefix}.trust.allowedPermissions`, message: `Unknown permission: ${perm}` });
        }
      }
    }

    if (server.rateLimit) {
      if (!/^\d+\/(min|hour|day)$/.test(server.rateLimit)) {
        errors.push({ path: `${prefix}.rateLimit`, message: 'Rate limit must be in format "N/min", "N/hour", or "N/day"' });
      }
    }
  }

  return errors;
}

// ─── Loader ──────────────────────────────────────────────────────────

/**
 * Load and validate a sentinel.yaml configuration file.
 */
export async function loadConfig(configPath: string): Promise<GatewayConfig> {
  const raw = await readFile(configPath, 'utf-8');
  const config = parseYaml(raw) as GatewayConfig;

  const errors = validateConfig(config);
  if (errors.length > 0) {
    const messages = errors.map(e => `  ${e.path}: ${e.message}`).join('\n');
    throw new Error(`Invalid configuration:\n${messages}`);
  }

  return config;
}
