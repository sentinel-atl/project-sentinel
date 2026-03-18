/**
 * Permission scanner — detects what system resources an MCP server accesses.
 *
 * Analyzes imports and API usage to determine permission scope:
 * - filesystem: fs, path operations
 * - network: http, https, net, tls, dns, fetch
 * - process: child_process, exec, spawn
 * - crypto: crypto operations (generally safe, but noted)
 * - environment: process.env access
 */

import { readFile, readdir } from 'node:fs/promises';
import { join, relative } from 'node:path';
import type { Finding } from './scanner.js';

export type PermissionKind =
  | 'filesystem'
  | 'network'
  | 'process'
  | 'crypto'
  | 'environment'
  | 'native';

export interface DetectedPermission {
  kind: PermissionKind;
  source: string;
  file: string;
  line: number;
  evidence: string;
}

export interface PermissionScanResult {
  /** Unique permission kinds detected */
  kinds: PermissionKind[];
  /** All detected permission usages */
  detections: DetectedPermission[];
  findings: Finding[];
}

// ─── Permission Rules ─────────────────────────────────────────────────

interface PermissionRule {
  kind: PermissionKind;
  pattern: RegExp;
  source: string;
  severity: Finding['severity'];
}

const PERMISSION_RULES: PermissionRule[] = [
  // Filesystem
  { kind: 'filesystem', pattern: /(?:from|require\s*\()\s*['"](?:node:)?fs(?:\/promises)?['"]/g, source: 'fs module', severity: 'medium' },
  { kind: 'filesystem', pattern: /(?:readFile|writeFile|readdir|mkdir|rmdir|unlink|rename|copyFile|stat|access)\s*\(/g, source: 'fs operation', severity: 'medium' },
  { kind: 'filesystem', pattern: /(?:createReadStream|createWriteStream)\s*\(/g, source: 'fs stream', severity: 'medium' },

  // Network
  { kind: 'network', pattern: /(?:from|require\s*\()\s*['"](?:node:)?(?:http|https|net|tls|dgram)['"]/g, source: 'network module', severity: 'high' },
  { kind: 'network', pattern: /(?:from|require\s*\()\s*['"](?:node-fetch|axios|got|undici)['"]/g, source: 'http client library', severity: 'high' },
  { kind: 'network', pattern: /\bfetch\s*\(/g, source: 'global fetch', severity: 'medium' },

  // Process/Shell
  { kind: 'process', pattern: /(?:from|require\s*\()\s*['"](?:node:)?child_process['"]/g, source: 'child_process module', severity: 'critical' },
  { kind: 'process', pattern: /(?:exec|execFile|execSync|spawn|spawnSync|fork)\s*\(/g, source: 'process execution', severity: 'critical' },
  { kind: 'process', pattern: /process\.(?:kill|exit|abort)\s*\(/g, source: 'process control', severity: 'high' },

  // Crypto (generally safe but noted)
  { kind: 'crypto', pattern: /(?:from|require\s*\()\s*['"](?:node:)?crypto['"]/g, source: 'crypto module', severity: 'info' },

  // Environment
  { kind: 'environment', pattern: /process\.env(?:\.|(?:\[))/g, source: 'environment variable', severity: 'low' },

  // Native modules
  { kind: 'native', pattern: /(?:from|require\s*\()\s*['"].*\.node['"]/g, source: 'native addon', severity: 'high' },
  { kind: 'native', pattern: /(?:from|require\s*\()\s*['"](?:node:)?(?:v8|vm|worker_threads)['"]/g, source: 'low-level module', severity: 'high' },
];

// ─── Scanner ─────────────────────────────────────────────────────────

export async function scanPermissions(
  packagePath: string,
  extensions: string[]
): Promise<PermissionScanResult> {
  const files = await collectSourceFiles(packagePath, extensions);
  const detections: DetectedPermission[] = [];
  const findings: Finding[] = [];

  for (const filePath of files) {
    const content = await readFile(filePath, 'utf-8');
    const lines = content.split('\n');
    const relPath = relative(packagePath, filePath);

    for (const rule of PERMISSION_RULES) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        rule.pattern.lastIndex = 0;
        if (rule.pattern.test(line)) {
          const trimmed = line.trim();
          if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) {
            continue;
          }

          detections.push({
            kind: rule.kind,
            source: rule.source,
            file: relPath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
          });

          findings.push({
            severity: rule.severity,
            category: 'permission',
            title: `${rule.kind}: ${rule.source} in ${relPath}:${i + 1}`,
            description: `Detected ${rule.kind} access via ${rule.source}`,
            file: relPath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
          });
        }
      }
    }
  }

  const kinds = [...new Set(detections.map(d => d.kind))];

  return { kinds, detections, findings };
}

// ─── File Collection ─────────────────────────────────────────────────

async function collectSourceFiles(
  dir: string,
  extensions: string[],
  basePath?: string
): Promise<string[]> {
  basePath ??= dir;
  const files: string[] = [];

  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return files;
  }

  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const fullPath = join(dir, entry.name);

    if (entry.isDirectory()) {
      if (['node_modules', 'dist', '.git', '.turbo', 'coverage', '__pycache__'].includes(entry.name)) {
        continue;
      }
      files.push(...await collectSourceFiles(fullPath, extensions, basePath));
    } else if (entry.isFile() && extensions.some(ext => entry.name.endsWith(ext))) {
      files.push(fullPath);
    }
  }

  return files;
}
