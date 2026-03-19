/**
 * Official MCP registry crawler — parse the curated server list from
 * https://github.com/modelcontextprotocol/servers
 *
 * Also handles awesome-mcp-servers (community-curated).
 * These targets get highest trust weight because they're vetted.
 */

import type { CrawlTarget, CrawlResult, CrawlOptions } from './types.js';

const OFFICIAL_README = 'https://raw.githubusercontent.com/modelcontextprotocol/servers/main/README.md';
const AWESOME_README = 'https://raw.githubusercontent.com/punkpeye/awesome-mcp-servers/main/README.md';

export async function crawlOfficial(options: CrawlOptions = {}): Promise<CrawlResult> {
  const startedAt = new Date().toISOString();
  const targets: CrawlTarget[] = [];

  try {
    options.onProgress?.('Official: fetching curated list...', 0);

    const [officialMd, awesomeMd] = await Promise.all([
      fetchMarkdown(OFFICIAL_README, options.signal),
      fetchMarkdown(AWESOME_README, options.signal),
    ]);

    if (officialMd) {
      targets.push(...parseMarkdownLinks(officialMd, 'official'));
    }
    if (awesomeMd) {
      targets.push(...parseMarkdownLinks(awesomeMd, 'awesome'));
    }

    options.onProgress?.('Official: done', targets.length);
  } catch (err) {
    return {
      source: 'official',
      targets,
      startedAt,
      finishedAt: new Date().toISOString(),
      error: (err as Error).message,
    };
  }

  return {
    source: 'official',
    targets,
    startedAt,
    finishedAt: new Date().toISOString(),
  };
}

async function fetchMarkdown(url: string, signal?: AbortSignal): Promise<string | null> {
  try {
    const resp = await fetch(url, {
      headers: { 'User-Agent': 'sentinel-crawler/0.1.0' },
      signal,
    });
    if (!resp.ok) return null;
    return resp.text();
  } catch {
    return null;
  }
}

/**
 * Extract GitHub repo URLs and npm package names from markdown.
 * Looks for patterns like:
 *   - [Name](https://github.com/org/repo) — Description
 *   - `npm install @scope/package`
 *   - Links to npmjs.com/package/...
 */
function parseMarkdownLinks(md: string, source: 'official' | 'awesome'): CrawlTarget[] {
  const targets: CrawlTarget[] = [];
  const seen = new Set<string>();

  // Match markdown links to GitHub repos
  const linkRegex = /\[([^\]]+)\]\((https:\/\/github\.com\/[^)]+)\)/g;
  let match;

  while ((match = linkRegex.exec(md)) !== null) {
    const name = match[1].trim();
    let repoUrl = match[2].trim();

    // Skip non-repo links (issues, pulls, etc.)
    if (/\/(issues|pulls|discussions|wiki|actions|releases)/.test(repoUrl)) continue;
    // Skip the main MCP org links that aren't individual servers
    if (repoUrl === 'https://github.com/modelcontextprotocol/servers') continue;

    // Normalize — remove tree/branch paths for monorepo links
    repoUrl = repoUrl.replace(/\/tree\/[^/]+\/.*$/, '');
    if (repoUrl.endsWith('/')) repoUrl = repoUrl.slice(0, -1);

    if (seen.has(repoUrl)) continue;
    seen.add(repoUrl);

    // Try to extract npm package from surrounding text
    const npmPackage = extractNpmFromContext(md, match.index);

    targets.push({
      repoUrl,
      name,
      npmPackage,
      source,
      categories: ['curated'],
    });
  }

  return targets;
}

/** Look for an npm package reference near a markdown link. */
function extractNpmFromContext(md: string, linkIndex: number): string | undefined {
  // Check ~500 chars after the link for npm references
  const context = md.substring(linkIndex, linkIndex + 500);
  const npmMatch = context.match(/`npm\s+(?:install|i)\s+([^`\s]+)`/) ??
    context.match(/npmjs\.com\/package\/([^)\s]+)/) ??
    context.match(/`(@[a-z0-9-]+\/[a-z0-9-]+)`/);
  return npmMatch?.[1];
}
