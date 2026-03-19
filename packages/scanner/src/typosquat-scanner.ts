/**
 * Typosquat detector — catches supply chain attacks via name similarity.
 *
 * Compares a package name against a curated list of popular/official MCP servers
 * using edit distance (Levenshtein) and common typosquatting techniques:
 * - Character swaps: notion → notiom
 * - Missing characters: notion → noton
 * - Extra characters: notion → notionn
 * - Homoglyphs: notion → noti0n (0 vs o)
 * - Scope confusion: @notionhq/server → @notion-hq/server
 */

import type { Finding } from './scanner.js';

// ─── Types ───────────────────────────────────────────────────────────

export interface TyposquatResult {
  /** Whether this package name looks like a typosquat */
  isSuspicious: boolean;
  /** The legitimate package it might be impersonating */
  similarTo?: string;
  /** Edit distance to the closest match */
  editDistance?: number;
  /** Specific technique detected */
  technique?: string;
  /** All findings */
  findings: Finding[];
  /** Typosquat risk score 0-100 (100 = safe, 0 = definitely typosquat) */
  score: number;
}

// ─── Known Popular MCP Servers ────────────────────────────────────────

/**
 * Curated list of known legitimate MCP server packages.
 * This list should grow as we crawl the ecosystem.
 * High-download, verified, or official packages go here.
 */
const KNOWN_PACKAGES: string[] = [
  // Official / Anthropic
  '@modelcontextprotocol/server-filesystem',
  '@modelcontextprotocol/server-github',
  '@modelcontextprotocol/server-postgres',
  '@modelcontextprotocol/server-sqlite',
  '@modelcontextprotocol/server-memory',
  '@modelcontextprotocol/server-puppeteer',
  '@modelcontextprotocol/server-brave-search',
  '@modelcontextprotocol/server-google-maps',
  '@modelcontextprotocol/server-slack',
  '@modelcontextprotocol/server-sequential-thinking',
  '@modelcontextprotocol/server-everything',
  '@modelcontextprotocol/sdk',

  // High-profile third-party
  '@notionhq/notion-mcp-server',
  '@smithery/sdk',
  '@playwright/mcp',
  '@cloudflare/mcp-server-cloudflare',
  '@stripe/mcp',
  'mcp-server-sqlite',
  'mcp-server-fetch',
  'firecrawl-mcp',
  'mcp-server-git',
  'mcp-server-github',
  'mcp-server-filesystem',
  'mcp-server-postgres',
  'mcp-server-puppeteer',
  'mcp-server-brave-search',
  'mcp-server-memory',
  'mcp-server-slack',
  'mcp-server-time',
  'mcp-server-weather',

  // Sentinel
  '@sentinel-atl/scanner',
  '@sentinel-atl/gateway',
  '@sentinel-atl/audit',
  '@sentinel-atl/registry',
  '@sentinel-atl/core',
  '@sentinel-atl/sdk',
  '@sentinel-atl/mcp-proxy',
  '@sentinel-atl/mcp-plugin',
];

// ─── Homoglyph Map ────────────────────────────────────────────────────

const HOMOGLYPHS: Record<string, string[]> = {
  'o': ['0'],
  '0': ['o'],
  'l': ['1', 'i'],
  '1': ['l', 'i'],
  'i': ['1', 'l'],
  's': ['5'],
  '5': ['s'],
  'a': ['4'],
  '4': ['a'],
  'e': ['3'],
  '3': ['e'],
  'g': ['9'],
  '9': ['g'],
  'b': ['6'],
  '6': ['b'],
  't': ['7'],
  '7': ['t'],
};

// ─── Edit Distance ─────────────────────────────────────────────────────

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
        dp[i - 1][j] + 1,      // deletion
        dp[i][j - 1] + 1,      // insertion
        dp[i - 1][j - 1] + cost // substitution
      );
    }
  }

  return dp[m][n];
}

// ─── Normalization ─────────────────────────────────────────────────────

/**
 * Strip scope and normalize for comparison.
 * "@notionhq/notion-mcp-server" → "notion-mcp-server"
 * "@model-context-protocol/server-github" → "server-github"
 */
function stripScope(name: string): string {
  return name.includes('/') ? name.split('/').pop()! : name;
}

/**
 * Normalize hyphens, underscores, dots for fuzzy comparison.
 */
function normalizeChars(name: string): string {
  return name.toLowerCase().replace(/[-_.]/g, '');
}

// ─── Detection ──────────────────────────────────────────────────────

function detectHomoglyph(name: string, knownName: string): boolean {
  if (name === knownName) return false;
  if (name.length !== knownName.length) return false;

  let diffCount = 0;
  let hasHomoglyph = false;

  for (let i = 0; i < name.length; i++) {
    if (name[i] !== knownName[i]) {
      diffCount++;
      if (diffCount > 2) return false;
      const possibleHomoglyphs = HOMOGLYPHS[knownName[i]];
      if (possibleHomoglyphs?.includes(name[i])) {
        hasHomoglyph = true;
      }
    }
  }

  return hasHomoglyph && diffCount <= 2;
}

function detectScopeConfusion(name: string, knownName: string): boolean {
  // Only check if both are scoped
  if (!name.startsWith('@') || !knownName.startsWith('@')) return false;
  if (name === knownName) return false;

  const [nameScope, namePkg] = name.slice(1).split('/');
  const [knownScope, knownPkg] = knownName.slice(1).split('/');

  if (!namePkg || !knownPkg) return false;

  // Same package name, different scope (e.g. @notion/server vs @notionhq/server)
  if (namePkg === knownPkg && nameScope !== knownScope) {
    const scopeDistance = levenshtein(nameScope, knownScope);
    return scopeDistance <= 2;
  }

  return false;
}

// ─── Scanner ──────────────────────────────────────────────────────────

/**
 * Check if a package name is a potential typosquat of a known MCP server.
 */
export function detectTyposquat(
  packageName: string,
  additionalKnownPackages?: string[],
): TyposquatResult {
  const findings: Finding[] = [];

  if (!packageName || packageName === 'unknown') {
    return { isSuspicious: false, findings, score: 100 };
  }

  const allKnown = additionalKnownPackages
    ? [...KNOWN_PACKAGES, ...additionalKnownPackages]
    : KNOWN_PACKAGES;

  // Skip if the package itself is in the known list
  if (allKnown.includes(packageName)) {
    return { isSuspicious: false, findings, score: 100 };
  }

  const strippedName = stripScope(packageName);
  const normalizedName = normalizeChars(strippedName);

  let closestMatch: string | undefined;
  let closestDistance = Infinity;
  let detectedTechnique: string | undefined;

  for (const known of allKnown) {
    const strippedKnown = stripScope(known);
    const normalizedKnown = normalizeChars(strippedKnown);

    // Check exact stripped match (scope confusion)
    if (detectScopeConfusion(packageName, known)) {
      closestMatch = known;
      closestDistance = 0;
      detectedTechnique = 'scope-confusion';
      break;
    }

    // Check homoglyphs
    if (detectHomoglyph(normalizedName, normalizedKnown)) {
      closestMatch = known;
      closestDistance = 1;
      detectedTechnique = 'homoglyph';
      break;
    }

    // Edit distance on the normalized unscoped name
    const distance = levenshtein(normalizedName, normalizedKnown);

    // Threshold: edit distance of 1-2 for short names, up to 3 for longer names
    const threshold = normalizedKnown.length >= 15 ? 3 : 2;

    if (distance > 0 && distance <= threshold && distance < closestDistance) {
      closestDistance = distance;
      closestMatch = known;
      detectedTechnique = distance === 1 ? 'single-char-edit' : 'multi-char-edit';
    }
  }

  if (closestMatch && closestDistance <= 3) {
    const severity = closestDistance <= 1 ? 'critical' : 'high';

    findings.push({
      severity,
      category: 'dangerous-pattern',
      title: `Possible typosquat of "${closestMatch}"`,
      description: `Package "${packageName}" is suspiciously similar to known package "${closestMatch}" `
        + `(edit distance: ${closestDistance}, technique: ${detectedTechnique}). `
        + `This could be a supply chain attack attempting to impersonate a legitimate package.`,
    });

    const score = closestDistance === 0 ? 5
      : closestDistance === 1 ? 15
      : closestDistance === 2 ? 35
      : 50;

    return {
      isSuspicious: true,
      similarTo: closestMatch,
      editDistance: closestDistance,
      technique: detectedTechnique,
      findings,
      score,
    };
  }

  return { isSuspicious: false, findings, score: 100 };
}

/**
 * Get the list of known packages for external use (e.g., adding crawled packages).
 */
export function getKnownPackages(): readonly string[] {
  return KNOWN_PACKAGES;
}
