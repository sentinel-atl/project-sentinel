/**
 * Crawler types — shared across all source crawlers.
 */

/** A discovered MCP server/package target. */
export interface CrawlTarget {
  /** npm package name (if known) */
  npmPackage?: string;
  /** PyPI package name (if known) */
  pypiPackage?: string;
  /** GitHub repository URL (normalized) */
  repoUrl?: string;
  /** Glama ID */
  glamaId?: string;
  /** Human-readable name */
  name: string;
  /** Description */
  description?: string;
  /** Primary language */
  language?: string;
  /** License */
  license?: string;
  /** Categories/tags */
  categories?: string[];
  /** Publisher name (npm user, GitHub org, etc.) */
  publisherName?: string;
  /** Which source discovered this target */
  source: CrawlSource;
}

export type CrawlSource = 'glama' | 'npm' | 'pypi' | 'github' | 'official' | 'awesome';

/** Result from a single source crawl. */
export interface CrawlResult {
  source: CrawlSource;
  targets: CrawlTarget[];
  startedAt: string;
  finishedAt: string;
  error?: string;
}

/** A deduplicated target with merged metadata from all sources. */
export interface MergedTarget {
  /** Canonical dedup key */
  dedupKey: string;
  /** npm package name (if known) */
  npmPackage?: string;
  /** PyPI package name (if known) */
  pypiPackage?: string;
  /** GitHub repository URL (normalized) */
  repoUrl?: string;
  /** Glama ID */
  glamaId?: string;
  /** Human-readable name */
  name: string;
  /** Description (prefer longest) */
  description?: string;
  /** Primary language */
  language?: string;
  /** License */
  license?: string;
  /** Merged categories */
  categories: string[];
  /** Publisher name */
  publisherName?: string;
  /** All sources that found this target */
  sources: CrawlSource[];
}

/** Progress callback for long crawls. */
export type CrawlProgressFn = (msg: string, count: number, total?: number) => void;

/** Options for all crawlers. */
export interface CrawlOptions {
  /** Progress callback */
  onProgress?: CrawlProgressFn;
  /** Abort signal for cancellation */
  signal?: AbortSignal;
}
