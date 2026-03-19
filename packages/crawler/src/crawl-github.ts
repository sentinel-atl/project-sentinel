/**
 * GitHub crawler — discover MCP server repos via GitHub Search API.
 *
 * Rate limit: 10 req/min (authenticated), 10 req/min (unauthenticated)
 * Max results: 1000 per query (GitHub API limit)
 * Strategy: multiple refined queries to maximize coverage.
 */

import type { CrawlTarget, CrawlResult, CrawlOptions } from './types.js';

const GITHUB_SEARCH = 'https://api.github.com/search/repositories';
const PER_PAGE = 100;
const DELAY_MS = 6500; // ~10 req/min → 6s between requests

/** Multiple queries to maximize coverage within GitHub's 1000-result limit per query. */
const SEARCH_QUERIES = [
  'topic:mcp-server',
  'topic:mcp language:typescript',
  'topic:mcp language:python',
  '"model context protocol" server',
  '"mcp server" in:readme language:typescript',
  '"mcp server" in:readme language:python',
];

interface GitHubSearchResult {
  total_count: number;
  items: Array<{
    full_name: string;
    html_url: string;
    description?: string;
    language?: string;
    license?: { spdx_id?: string };
    topics?: string[];
    stargazers_count: number;
    updated_at: string;
    owner: { login: string };
  }>;
}

export interface GitHubCrawlOptions extends CrawlOptions {
  /** GitHub personal access token for higher rate limits. */
  token?: string;
}

export async function crawlGithub(options: GitHubCrawlOptions = {}): Promise<CrawlResult> {
  const startedAt = new Date().toISOString();
  const seen = new Set<string>(); // dedup by repo full_name
  const targets: CrawlTarget[] = [];

  const headers: Record<string, string> = {
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'sentinel-crawler/0.1.0',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (options.token) {
    headers['Authorization'] = `Bearer ${options.token}`;
  }

  try {
    for (const query of SEARCH_QUERIES) {
      if (options.signal?.aborted) break;

      let page = 1;
      while (page <= 10) { // max 1000 results = 10 pages
        if (options.signal?.aborted) break;

        const url = new URL(GITHUB_SEARCH);
        url.searchParams.set('q', query);
        url.searchParams.set('per_page', String(PER_PAGE));
        url.searchParams.set('page', String(page));
        url.searchParams.set('sort', 'updated');

        const response = await fetch(url.toString(), { headers, signal: options.signal });

        if (response.status === 403 || response.status === 429) {
          // Rate limited — wait and retry
          const retryAfter = parseInt(response.headers.get('retry-after') ?? '60', 10);
          options.onProgress?.(`GitHub: rate limited, waiting ${retryAfter}s`, targets.length);
          await sleep(retryAfter * 1000);
          continue;
        }

        if (!response.ok) {
          throw new Error(`GitHub search returned ${response.status}: ${await response.text()}`);
        }

        const data = await response.json() as GitHubSearchResult;

        for (const repo of data.items) {
          if (seen.has(repo.full_name)) continue;
          seen.add(repo.full_name);

          targets.push({
            repoUrl: repo.html_url,
            name: repo.full_name,
            description: repo.description ?? undefined,
            language: repo.language?.toLowerCase(),
            license: repo.license?.spdx_id,
            categories: repo.topics ?? [],
            publisherName: repo.owner.login,
            source: 'github',
          });
        }

        options.onProgress?.(`GitHub [${query}] page ${page}`, targets.length, data.total_count);

        if (data.items.length < PER_PAGE) break;
        page++;
        await sleep(DELAY_MS);
      }
    }
  } catch (err) {
    return {
      source: 'github',
      targets,
      startedAt,
      finishedAt: new Date().toISOString(),
      error: (err as Error).message,
    };
  }

  return {
    source: 'github',
    targets,
    startedAt,
    finishedAt: new Date().toISOString(),
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
