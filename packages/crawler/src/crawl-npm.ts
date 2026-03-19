/**
 * npm registry crawler — discover MCP packages from npm.
 *
 * Endpoint: GET https://registry.npmjs.org/-/v1/search
 * Pagination: offset-based (from/size)
 * Rate limit: undocumented, self-limit to 2 req/s
 */

import type { CrawlTarget, CrawlResult, CrawlOptions } from './types.js';

const NPM_SEARCH = 'https://registry.npmjs.org/-/v1/search';
const PAGE_SIZE = 250;
const DELAY_MS = 500;

/** Search queries that cover the MCP ecosystem. */
const SEARCH_QUERIES = [
  'keywords:mcp-server',
  'keywords:mcp-tool',
  'keywords:model-context-protocol',
  'keywords:mcp scope:modelcontextprotocol',
];

interface NpmSearchResult {
  objects: Array<{
    package: {
      name: string;
      version: string;
      description?: string;
      keywords?: string[];
      publisher?: { username: string };
      maintainers?: Array<{ username: string }>;
      links?: { repository?: string; homepage?: string };
    };
  }>;
  total: number;
}

export async function crawlNpm(options: CrawlOptions = {}): Promise<CrawlResult> {
  const startedAt = new Date().toISOString();
  const seen = new Set<string>(); // dedup by package name
  const targets: CrawlTarget[] = [];

  try {
    for (const query of SEARCH_QUERIES) {
      if (options.signal?.aborted) break;

      let offset = 0;
      while (true) {
        if (options.signal?.aborted) break;

        const url = new URL(NPM_SEARCH);
        url.searchParams.set('text', query);
        url.searchParams.set('size', String(PAGE_SIZE));
        url.searchParams.set('from', String(offset));

        const response = await fetch(url.toString(), {
          headers: { 'Accept': 'application/json', 'User-Agent': 'sentinel-crawler/0.1.0' },
          signal: options.signal,
        });

        if (!response.ok) {
          throw new Error(`npm search returned ${response.status}: ${await response.text()}`);
        }

        const data = await response.json() as NpmSearchResult;

        for (const obj of data.objects) {
          const pkg = obj.package;
          if (seen.has(pkg.name)) continue;
          seen.add(pkg.name);

          targets.push({
            npmPackage: pkg.name,
            name: pkg.name,
            description: pkg.description,
            repoUrl: normalizeRepoUrl(pkg.links?.repository),
            categories: pkg.keywords ?? [],
            publisherName: pkg.publisher?.username ?? pkg.maintainers?.[0]?.username,
            language: 'typescript', // npm packages assumed TS/JS
            source: 'npm',
          });
        }

        options.onProgress?.(`npm [${query}] offset=${offset}`, targets.length, data.total);

        offset += PAGE_SIZE;
        if (offset >= data.total || data.objects.length === 0) break;
        await sleep(DELAY_MS);
      }
    }
  } catch (err) {
    return {
      source: 'npm',
      targets,
      startedAt,
      finishedAt: new Date().toISOString(),
      error: (err as Error).message,
    };
  }

  return {
    source: 'npm',
    targets,
    startedAt,
    finishedAt: new Date().toISOString(),
  };
}

function normalizeRepoUrl(url?: string): string | undefined {
  if (!url) return undefined;
  let normalized = url.trim();
  if (normalized.endsWith('.git')) normalized = normalized.slice(0, -4);
  if (normalized.endsWith('/')) normalized = normalized.slice(0, -1);
  normalized = normalized.replace(/^git:\/\/github\.com/, 'https://github.com');
  normalized = normalized.replace(/^git@github\.com:/, 'https://github.com/');
  // npm sometimes returns "git+https://..." — strip the "git+" prefix
  normalized = normalized.replace(/^git\+/, '');
  return normalized || undefined;
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
