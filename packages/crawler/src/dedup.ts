/**
 * Deduplication engine — merge targets from multiple crawler sources
 * into a single canonical target list.
 *
 * Dedup key hierarchy:
 *   1. npm package name (canonical for npm packages)
 *   2. Normalized GitHub repo URL
 *   3. Glama ID (fallback for Glama-only entries)
 *   4. PyPI package name
 */

import type { CrawlTarget, CrawlSource, MergedTarget } from './types.js';

/**
 * Deduplicate and merge targets from multiple crawl sources.
 */
export function deduplicateTargets(allTargets: CrawlTarget[]): MergedTarget[] {
  // Multi-key index for dedup
  const npmIndex = new Map<string, MergedTarget>();
  const repoIndex = new Map<string, MergedTarget>();
  const glamaIndex = new Map<string, MergedTarget>();
  const pypiIndex = new Map<string, MergedTarget>();
  const merged: MergedTarget[] = [];

  for (const target of allTargets) {
    const normalizedRepo = target.repoUrl ? normalizeRepo(target.repoUrl) : undefined;

    // Try to find existing target by any key
    let existing: MergedTarget | undefined;
    if (target.npmPackage) existing = npmIndex.get(target.npmPackage);
    if (!existing && normalizedRepo) existing = repoIndex.get(normalizedRepo);
    if (!existing && target.glamaId) existing = glamaIndex.get(target.glamaId);
    if (!existing && target.pypiPackage) existing = pypiIndex.get(target.pypiPackage);

    if (existing) {
      // Merge into existing target
      mergeInto(existing, target);
      // Update indexes with any new keys
      if (target.npmPackage && !npmIndex.has(target.npmPackage)) {
        npmIndex.set(target.npmPackage, existing);
      }
      if (normalizedRepo && !repoIndex.has(normalizedRepo)) {
        repoIndex.set(normalizedRepo, existing);
      }
      if (target.glamaId && !glamaIndex.has(target.glamaId)) {
        glamaIndex.set(target.glamaId, existing);
      }
      if (target.pypiPackage && !pypiIndex.has(target.pypiPackage)) {
        pypiIndex.set(target.pypiPackage, existing);
      }
    } else {
      // Create new merged target
      const dedupKey = target.npmPackage ??
        normalizedRepo ??
        target.glamaId ??
        target.pypiPackage ??
        target.name;

      const newTarget: MergedTarget = {
        dedupKey,
        npmPackage: target.npmPackage,
        pypiPackage: target.pypiPackage,
        repoUrl: target.repoUrl,
        glamaId: target.glamaId,
        name: target.name,
        description: target.description,
        language: target.language,
        license: target.license,
        categories: target.categories ? [...target.categories] : [],
        publisherName: target.publisherName,
        sources: [target.source],
      };

      merged.push(newTarget);

      // Index by all available keys
      if (target.npmPackage) npmIndex.set(target.npmPackage, newTarget);
      if (normalizedRepo) repoIndex.set(normalizedRepo, newTarget);
      if (target.glamaId) glamaIndex.set(target.glamaId, newTarget);
      if (target.pypiPackage) pypiIndex.set(target.pypiPackage, newTarget);
    }
  }

  return merged;
}

/** Merge metadata from a new target into an existing one. */
function mergeInto(existing: MergedTarget, incoming: CrawlTarget): void {
  // Add source if new
  if (!existing.sources.includes(incoming.source)) {
    existing.sources.push(incoming.source);
  }

  // Fill in missing identity keys
  if (incoming.npmPackage && !existing.npmPackage) {
    existing.npmPackage = incoming.npmPackage;
    existing.dedupKey = incoming.npmPackage; // npm package is canonical
  }
  if (incoming.pypiPackage && !existing.pypiPackage) existing.pypiPackage = incoming.pypiPackage;
  if (incoming.repoUrl && !existing.repoUrl) existing.repoUrl = incoming.repoUrl;
  if (incoming.glamaId && !existing.glamaId) existing.glamaId = incoming.glamaId;

  // Prefer longer/richer metadata
  if (incoming.description && (!existing.description || incoming.description.length > existing.description.length)) {
    existing.description = incoming.description;
  }
  if (incoming.language && !existing.language) existing.language = incoming.language;
  if (incoming.license && !existing.license) existing.license = incoming.license;
  if (incoming.publisherName && !existing.publisherName) existing.publisherName = incoming.publisherName;

  // Merge categories (deduplicated)
  if (incoming.categories) {
    for (const cat of incoming.categories) {
      if (!existing.categories.includes(cat)) {
        existing.categories.push(cat);
      }
    }
  }
}

/** Normalize a GitHub repo URL for dedup matching. */
function normalizeRepo(url: string): string {
  let normalized = url.trim().toLowerCase();
  if (normalized.endsWith('.git')) normalized = normalized.slice(0, -4);
  if (normalized.endsWith('/')) normalized = normalized.slice(0, -1);
  normalized = normalized.replace(/^git\+/, '');
  normalized = normalized.replace(/^git:\/\//, 'https://');
  normalized = normalized.replace(/^git@github\.com:/, 'https://github.com/');
  // Remove tree/branch paths
  normalized = normalized.replace(/\/tree\/[^/]+.*$/, '');
  return normalized;
}
