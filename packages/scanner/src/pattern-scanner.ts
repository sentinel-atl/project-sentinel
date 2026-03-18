/**
 * Code pattern scanner — detects dangerous patterns via regex-based static analysis.
 *
 * Categories:
 * - dangerous-pattern: eval(), new Function(), dynamic require
 * - obfuscation: hex-encoded strings, base64 payloads, packed code
 * - exfiltration: HTTP calls to external domains, DNS lookups, socket connections
 */

import { readFile, readdir, stat } from 'node:fs/promises';
import { join, relative, extname } from 'node:path';
import type { Finding } from './scanner.js';

export type PatternCategory = 'dangerous-pattern' | 'obfuscation' | 'exfiltration';

export interface CodePattern {
  name: string;
  category: PatternCategory;
  severity: Finding['severity'];
  pattern: RegExp;
  description: string;
}

export interface PatternScanResult {
  totalFiles: number;
  totalLines: number;
  matchedPatterns: Array<{
    pattern: string;
    file: string;
    line: number;
    evidence: string;
  }>;
  findings: Finding[];
}

// ─── Pattern Definitions ─────────────────────────────────────────────

const PATTERNS: CodePattern[] = [
  // Dangerous execution patterns
  {
    name: 'eval-usage',
    category: 'dangerous-pattern',
    severity: 'critical',
    pattern: /\beval\s*\(/g,
    description: 'eval() can execute arbitrary code — a major security risk',
  },
  {
    name: 'new-function',
    category: 'dangerous-pattern',
    severity: 'critical',
    pattern: /new\s+Function\s*\(/g,
    description: 'new Function() is equivalent to eval()',
  },
  {
    name: 'dynamic-import-variable',
    category: 'dangerous-pattern',
    severity: 'high',
    pattern: /import\s*\(\s*[^'"]/g,
    description: 'Dynamic import with variable — could load arbitrary modules',
  },
  {
    name: 'child-process-exec',
    category: 'dangerous-pattern',
    severity: 'high',
    pattern: /(?:exec|execSync|spawn|spawnSync|fork)\s*\(/g,
    description: 'Shell command execution detected',
  },
  {
    name: 'process-env-access',
    category: 'dangerous-pattern',
    severity: 'medium',
    pattern: /process\.env\[/g,
    description: 'Dynamic environment variable access',
  },

  // Obfuscation patterns
  {
    name: 'hex-string-long',
    category: 'obfuscation',
    severity: 'high',
    pattern: /["']\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){7,}["']/g,
    description: 'Long hex-encoded string — possible obfuscated payload',
  },
  {
    name: 'base64-long-literal',
    category: 'obfuscation',
    severity: 'medium',
    pattern: /atob\s*\(\s*["'][A-Za-z0-9+/=]{50,}["']\s*\)/g,
    description: 'Base64 decode of a long literal — possible hidden payload',
  },
  {
    name: 'char-code-array',
    category: 'obfuscation',
    severity: 'medium',
    pattern: /String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){5,}/g,
    description: 'String.fromCharCode with many values — possible obfuscation',
  },

  // Exfiltration patterns
  {
    name: 'fetch-external',
    category: 'exfiltration',
    severity: 'high',
    pattern: /(?:fetch|axios|got|node-fetch|request)\s*\(\s*[`"']https?:\/\//g,
    description: 'HTTP request to external URL',
  },
  {
    name: 'dns-lookup',
    category: 'exfiltration',
    severity: 'medium',
    pattern: /dns\.(?:lookup|resolve|resolve4|resolve6)\s*\(/g,
    description: 'DNS lookup — could be used for DNS exfiltration',
  },
  {
    name: 'websocket-connection',
    category: 'exfiltration',
    severity: 'medium',
    pattern: /new\s+WebSocket\s*\(/g,
    description: 'WebSocket connection — could be used for data exfiltration',
  },
  {
    name: 'net-socket',
    category: 'exfiltration',
    severity: 'high',
    pattern: /(?:net|tls)\.(?:createConnection|connect|createServer)\s*\(/g,
    description: 'Low-level network socket — could send data anywhere',
  },
];

// ─── Scanner ─────────────────────────────────────────────────────────

export async function scanCodePatterns(
  packagePath: string,
  extensions: string[]
): Promise<PatternScanResult> {
  const files = await collectSourceFiles(packagePath, extensions);
  const findings: Finding[] = [];
  const matchedPatterns: PatternScanResult['matchedPatterns'] = [];
  let totalLines = 0;

  for (const filePath of files) {
    const content = await readFile(filePath, 'utf-8');
    const lines = content.split('\n');
    totalLines += lines.length;
    const relPath = relative(packagePath, filePath);

    for (const pattern of PATTERNS) {
      // Reset regex state
      pattern.pattern.lastIndex = 0;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // Reset for each line
        pattern.pattern.lastIndex = 0;
        if (pattern.pattern.test(line)) {
          const trimmed = line.trim();
          // Skip matches in comments
          if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) {
            continue;
          }

          matchedPatterns.push({
            pattern: pattern.name,
            file: relPath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
          });

          findings.push({
            severity: pattern.severity,
            category: pattern.category,
            title: `${pattern.name} in ${relPath}:${i + 1}`,
            description: pattern.description,
            file: relPath,
            line: i + 1,
            evidence: trimmed.slice(0, 120),
          });
        }
      }
    }
  }

  return {
    totalFiles: files.length,
    totalLines,
    matchedPatterns,
    findings,
  };
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
    const relPath = relative(basePath, fullPath);

    // Skip common non-source directories
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
