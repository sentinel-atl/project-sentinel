/**
 * Environment variable schema validation — fail fast on misconfiguration.
 *
 * Validates required env vars exist and optional ones have correct formats
 * at startup, before the server begins accepting connections.
 */

// ─── Types ───────────────────────────────────────────────────────────

export interface EnvVarDef {
  /** Environment variable name */
  name: string;
  /** Whether this variable is required */
  required?: boolean;
  /** Default value if not set */
  default?: string;
  /** Validation: 'string' | 'number' | 'boolean' | 'url' | 'port' */
  type?: 'string' | 'number' | 'boolean' | 'url' | 'port';
  /** Human-readable description (for error messages) */
  description?: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  resolved: Record<string, string>;
}

// ─── Validator ───────────────────────────────────────────────────────

/**
 * Validate and resolve environment variables from a schema definition.
 * Returns resolved values (with defaults applied) or throws on error.
 */
export function validateEnv(schema: EnvVarDef[]): ValidationResult {
  const errors: string[] = [];
  const resolved: Record<string, string> = {};

  for (const def of schema) {
    const raw = process.env[def.name];
    const value = raw ?? def.default;

    if (def.required && !value) {
      errors.push(`Missing required env var: ${def.name}${def.description ? ` (${def.description})` : ''}`);
      continue;
    }

    if (!value) continue;

    // Type validation
    switch (def.type) {
      case 'number': {
        const num = Number(value);
        if (isNaN(num)) {
          errors.push(`${def.name}: expected a number, got "${value}"`);
          continue;
        }
        break;
      }
      case 'port': {
        const port = Number(value);
        if (isNaN(port) || port < 1 || port > 65535) {
          errors.push(`${def.name}: expected a port (1-65535), got "${value}"`);
          continue;
        }
        break;
      }
      case 'boolean': {
        if (!['true', 'false', '1', '0'].includes(value.toLowerCase())) {
          errors.push(`${def.name}: expected true/false, got "${value}"`);
          continue;
        }
        break;
      }
      case 'url': {
        try {
          new URL(value);
        } catch {
          errors.push(`${def.name}: expected a valid URL, got "${value}"`);
          continue;
        }
        break;
      }
    }

    resolved[def.name] = value;
  }

  return { valid: errors.length === 0, errors, resolved };
}

/**
 * Validate and throw if any errors — call at server startup.
 */
export function requireValidEnv(schema: EnvVarDef[]): Record<string, string> {
  const result = validateEnv(schema);
  if (!result.valid) {
    const msg = `Configuration errors:\n  ${result.errors.join('\n  ')}`;
    throw new Error(msg);
  }
  return result.resolved;
}

/**
 * Standard Sentinel env vars for the STP server.
 */
export const SENTINEL_ENV_SCHEMA: EnvVarDef[] = [
  { name: 'SENTINEL_PORT', type: 'port', default: '3000', description: 'HTTP port' },
  { name: 'SENTINEL_HOST', type: 'string', default: '0.0.0.0', description: 'Bind address' },
  { name: 'SENTINEL_DATA_DIR', type: 'string', default: './data', description: 'Data directory' },
  { name: 'SENTINEL_API_KEYS', type: 'string', description: 'API keys (key1:scope1,scope2;key2:admin)' },
  { name: 'SENTINEL_CORS_ORIGINS', type: 'string', description: 'Comma-separated allowed origins' },
  { name: 'SENTINEL_TLS_CERT', type: 'string', description: 'TLS certificate path' },
  { name: 'SENTINEL_TLS_KEY', type: 'string', description: 'TLS private key path' },
  { name: 'REDIS_URL', type: 'url', description: 'Redis connection URL' },
  { name: 'NODE_ENV', type: 'string', default: 'production' },
];
