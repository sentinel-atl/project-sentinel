/**
 * @sentinel-atl/crawler — MCP Server Discovery Engine
 *
 * Crawl every major MCP server directory and produce a
 * deduplicated list of targets for the scanning pipeline.
 *
 * Sources: Glama, npm, PyPI, GitHub, Official MCP list, Awesome MCP Servers
 */

export { crawlGlama } from './crawl-glama.js';
export { crawlNpm } from './crawl-npm.js';
export { crawlPypi } from './crawl-pypi.js';
export { crawlGithub, type GitHubCrawlOptions } from './crawl-github.js';
export { crawlOfficial } from './crawl-official.js';
export { deduplicateTargets } from './dedup.js';

export type {
  CrawlTarget,
  CrawlSource,
  CrawlResult,
  MergedTarget,
  CrawlProgressFn,
  CrawlOptions,
} from './types.js';

import { crawlGlama } from './crawl-glama.js';
import { crawlNpm } from './crawl-npm.js';
import { crawlPypi } from './crawl-pypi.js';
import { crawlGithub, type GitHubCrawlOptions } from './crawl-github.js';
import { crawlOfficial } from './crawl-official.js';
import { deduplicateTargets } from './dedup.js';
import type { CrawlResult, CrawlOptions, CrawlProgressFn, MergedTarget } from './types.js';

export interface FullCrawlOptions extends CrawlOptions {
  /** GitHub token for higher rate limits */
  githubToken?: string;
  /** Which sources to crawl (default: all) */
  sources?: Array<'glama' | 'npm' | 'pypi' | 'github' | 'official'>;
}

export interface FullCrawlResult {
  /** Deduplicated merged targets */
  targets: MergedTarget[];
  /** Per-source crawl results */
  results: CrawlResult[];
  /** Total time in ms */
  durationMs: number;
  /** Summary stats */
  stats: {
    totalRaw: number;
    totalDeduped: number;
    bySource: Record<string, number>;
  };
}

/**
 * Run a full crawl across all configured sources and return deduplicated targets.
 */
export async function crawlAll(options: FullCrawlOptions = {}): Promise<FullCrawlResult> {
  const start = Date.now();
  const enabledSources = options.sources ?? ['glama', 'npm', 'pypi', 'github', 'official'];
  const results: CrawlResult[] = [];

  const progress: CrawlProgressFn = options.onProgress ?? (() => {});

  // Run crawlers (some can run in parallel, but respect rate limits)
  // Glama + npm + official can run together, they're different APIs
  const parallelBatch = await Promise.allSettled([
    enabledSources.includes('glama')
      ? crawlGlama({ ...options, onProgress: (m, c, t) => progress(`[glama] ${m}`, c, t) })
      : null,
    enabledSources.includes('npm')
      ? crawlNpm({ ...options, onProgress: (m, c, t) => progress(`[npm] ${m}`, c, t) })
      : null,
    enabledSources.includes('official')
      ? crawlOfficial({ ...options, onProgress: (m, c, t) => progress(`[official] ${m}`, c, t) })
      : null,
  ]);

  for (const result of parallelBatch) {
    if (result.status === 'fulfilled' && result.value) {
      results.push(result.value);
    }
  }

  // PyPI and GitHub are slower/rate-limited, run sequentially
  if (enabledSources.includes('pypi')) {
    results.push(await crawlPypi({
      ...options,
      onProgress: (m, c, t) => progress(`[pypi] ${m}`, c, t),
    }));
  }

  if (enabledSources.includes('github')) {
    const ghOpts: GitHubCrawlOptions = {
      ...options,
      token: options.githubToken,
      onProgress: (m, c, t) => progress(`[github] ${m}`, c, t),
    };
    results.push(await crawlGithub(ghOpts));
  }

  // Combine all raw targets
  const allRawTargets = results.flatMap(r => r.targets);

  // Deduplicate
  const deduped = deduplicateTargets(allRawTargets);

  // Stats
  const bySource: Record<string, number> = {};
  for (const r of results) {
    bySource[r.source] = r.targets.length;
  }

  return {
    targets: deduped,
    results,
    durationMs: Date.now() - start,
    stats: {
      totalRaw: allRawTargets.length,
      totalDeduped: deduped.length,
      bySource,
    },
  };
}
