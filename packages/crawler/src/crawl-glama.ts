/**
 * Glama crawler — discover MCP servers from Glama's API.
 *
 * Endpoint: GET https://glama.ai/api/mcp/v1/servers
 * Pagination: cursor-based (after/first)
 * Rate limit: none documented, we self-limit to 1 req/s
 */

import type { CrawlTarget, CrawlResult, CrawlOptions } from './types.js';

const GLAMA_API = 'https://glama.ai/api/mcp/v1/servers';
const PAGE_SIZE = 100;
const DELAY_MS = 1000; // polite rate limiting

interface GlamaServer {
  id: string;
  name: string;
  namespace?: string;
  slug?: string;
  description?: string;
  repository?: { url?: string };
  spdxLicense?: string;
  attributes?: string[];
  tools?: Array<{ name: string }>;
  npmPackage?: string;
}

interface GlamaResponse {
  servers: GlamaServer[];
  pageInfo: {
    endCursor: string | null;
    hasNextPage: boolean;
  };
}

export async function crawlGlama(options: CrawlOptions = {}): Promise<CrawlResult> {
  const startedAt = new Date().toISOString();
  const targets: CrawlTarget[] = [];
  let cursor: string | null = null;
  let page = 0;

  try {
    while (true) {
      if (options.signal?.aborted) break;

      const url = new URL(GLAMA_API);
      url.searchParams.set('first', String(PAGE_SIZE));
      if (cursor) url.searchParams.set('after', cursor);

      const response = await fetch(url.toString(), {
        headers: { 'Accept': 'application/json', 'User-Agent': 'sentinel-crawler/0.1.0' },
        signal: options.signal,
      });

      if (!response.ok) {
        throw new Error(`Glama API returned ${response.status}: ${await response.text()}`);
      }

      const data = await response.json() as GlamaResponse;

      for (const server of data.servers) {
        const repoUrl = normalizeRepoUrl(server.repository?.url);
        targets.push({
          glamaId: server.id,
          name: server.name || server.slug || server.id,
          description: server.description,
          repoUrl,
          npmPackage: server.npmPackage ?? extractNpmFromRepo(repoUrl),
          license: server.spdxLicense,
          categories: server.attributes ?? [],
          source: 'glama',
        });
      }

      page++;
      options.onProgress?.(`Glama page ${page}`, targets.length);

      if (!data.pageInfo.hasNextPage) break;
      cursor = data.pageInfo.endCursor;

      await sleep(DELAY_MS);
    }
  } catch (err) {
    return {
      source: 'glama',
      targets,
      startedAt,
      finishedAt: new Date().toISOString(),
      error: (err as Error).message,
    };
  }

  return {
    source: 'glama',
    targets,
    startedAt,
    finishedAt: new Date().toISOString(),
  };
}

/** Normalize GitHub URLs to a standard form. */
function normalizeRepoUrl(url?: string): string | undefined {
  if (!url) return undefined;
  let normalized = url.trim();
  // Remove .git suffix
  if (normalized.endsWith('.git')) normalized = normalized.slice(0, -4);
  // Remove trailing slash
  if (normalized.endsWith('/')) normalized = normalized.slice(0, -1);
  // Convert git:// and ssh to https
  normalized = normalized.replace(/^git:\/\/github\.com/, 'https://github.com');
  normalized = normalized.replace(/^git@github\.com:/, 'https://github.com/');
  return normalized || undefined;
}

/** Try to infer npm package name from a well-known repo structure. */
function extractNpmFromRepo(_repoUrl?: string): string | undefined {
  // Can't reliably infer npm package from repo URL without checking package.json
  return undefined;
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
