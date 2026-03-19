/**
 * PyPI crawler — discover MCP packages from the Python Package Index.
 *
 * Strategy: Fetch the simple index, grep for "mcp" names,
 * then fetch per-package JSON metadata.
 *
 * Rate limit: undocumented, self-limit to 5 req/s
 */

import type { CrawlTarget, CrawlResult, CrawlOptions } from './types.js';

const PYPI_SIMPLE = 'https://pypi.org/simple/';
const PYPI_JSON = 'https://pypi.org/pypi'; // /pypi/{name}/json
const DELAY_MS = 200;
const BATCH_SIZE = 20;

/** Patterns that suggest an MCP server. */
const MCP_NAME_PATTERNS = [/\bmcp\b/i, /model.context.protocol/i];

export async function crawlPypi(options: CrawlOptions = {}): Promise<CrawlResult> {
  const startedAt = new Date().toISOString();
  const targets: CrawlTarget[] = [];

  try {
    // 1. Fetch the full simple index (~5MB HTML)
    options.onProgress?.('PyPI: fetching simple index...', 0);
    const indexResp = await fetch(PYPI_SIMPLE, {
      headers: { 'Accept': 'text/html', 'User-Agent': 'sentinel-crawler/0.1.0' },
      signal: options.signal,
    });
    if (!indexResp.ok) throw new Error(`PyPI simple index returned ${indexResp.status}`);
    const indexHtml = await indexResp.text();

    // 2. Extract package names (HTML format: <a href="/simple/name/">name</a>)
    const nameRegex = /<a[^>]*>([^<]+)<\/a>/g;
    const allNames: string[] = [];
    let match;
    while ((match = nameRegex.exec(indexHtml)) !== null) {
      allNames.push(match[1]);
    }

    // 3. Filter to MCP-related names
    const mcpNames = allNames.filter(name =>
      MCP_NAME_PATTERNS.some(p => p.test(name))
    );

    options.onProgress?.(`PyPI: found ${mcpNames.length} MCP candidate packages`, 0, mcpNames.length);

    // 4. Fetch metadata for each in batches
    for (let i = 0; i < mcpNames.length; i += BATCH_SIZE) {
      if (options.signal?.aborted) break;

      const batch = mcpNames.slice(i, i + BATCH_SIZE);
      const results = await Promise.allSettled(
        batch.map(name => fetchPypiMetadata(name, options.signal))
      );

      for (const result of results) {
        if (result.status === 'fulfilled' && result.value) {
          targets.push(result.value);
        }
      }

      options.onProgress?.(`PyPI: fetching metadata`, targets.length, mcpNames.length);
      await sleep(DELAY_MS);
    }
  } catch (err) {
    return {
      source: 'pypi',
      targets,
      startedAt,
      finishedAt: new Date().toISOString(),
      error: (err as Error).message,
    };
  }

  return {
    source: 'pypi',
    targets,
    startedAt,
    finishedAt: new Date().toISOString(),
  };
}

async function fetchPypiMetadata(name: string, signal?: AbortSignal): Promise<CrawlTarget | null> {
  const url = `${PYPI_JSON}/${encodeURIComponent(name)}/json`;
  const resp = await fetch(url, {
    headers: { 'Accept': 'application/json', 'User-Agent': 'sentinel-crawler/0.1.0' },
    signal,
  });
  if (!resp.ok) return null;

  const data = await resp.json() as {
    info: {
      name: string;
      summary?: string;
      author?: string;
      license?: string;
      project_urls?: Record<string, string>;
      classifiers?: string[];
      keywords?: string;
      home_page?: string;
    };
  };

  const info = data.info;
  const repoUrl = info.project_urls?.['Source'] ??
    info.project_urls?.['Repository'] ??
    info.project_urls?.['GitHub'] ??
    info.home_page;

  return {
    pypiPackage: info.name,
    name: info.name,
    description: info.summary,
    repoUrl: normalizeRepoUrl(repoUrl),
    language: 'python',
    license: info.license,
    publisherName: info.author,
    categories: parseClassifiers(info.classifiers),
    source: 'pypi',
  };
}

function parseClassifiers(classifiers?: string[]): string[] {
  if (!classifiers) return [];
  // Extract topic categories from PyPI classifiers
  return classifiers
    .filter(c => c.startsWith('Topic ::'))
    .map(c => c.split(' :: ').pop()!)
    .filter(Boolean);
}

function normalizeRepoUrl(url?: string | null): string | undefined {
  if (!url) return undefined;
  let normalized = url.trim();
  if (normalized.endsWith('.git')) normalized = normalized.slice(0, -4);
  if (normalized.endsWith('/')) normalized = normalized.slice(0, -1);
  return normalized || undefined;
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
