/**
 * Tests for the crawler package — dedup logic and crawler interfaces.
 *
 * Note: Actual API calls are not tested here (would need network mocks).
 * We test the dedup engine and type contracts.
 */

import { describe, it, expect } from 'vitest';
import { deduplicateTargets } from '../dedup.js';
import type { CrawlTarget, MergedTarget } from '../types.js';

describe('deduplicateTargets', () => {
  it('merges targets with the same npm package name', () => {
    const targets: CrawlTarget[] = [
      {
        npmPackage: '@example/mcp-server',
        name: '@example/mcp-server',
        description: 'Short desc',
        source: 'npm',
      },
      {
        npmPackage: '@example/mcp-server',
        repoUrl: 'https://github.com/example/mcp-server',
        name: 'MCP Server Example',
        description: 'A longer description for the server',
        source: 'glama',
        glamaId: 'abc123',
      },
    ];

    const merged = deduplicateTargets(targets);
    expect(merged).toHaveLength(1);
    expect(merged[0].npmPackage).toBe('@example/mcp-server');
    expect(merged[0].repoUrl).toBe('https://github.com/example/mcp-server');
    expect(merged[0].glamaId).toBe('abc123');
    expect(merged[0].sources).toContain('npm');
    expect(merged[0].sources).toContain('glama');
    // Longer description wins
    expect(merged[0].description).toBe('A longer description for the server');
  });

  it('merges targets by repo URL when npm package differs', () => {
    const targets: CrawlTarget[] = [
      {
        repoUrl: 'https://github.com/org/repo',
        name: 'From GitHub',
        source: 'github',
        language: 'typescript',
      },
      {
        repoUrl: 'https://github.com/org/repo.git', // same repo, .git suffix
        name: 'From Glama',
        source: 'glama',
        glamaId: 'xyz',
      },
    ];

    const merged = deduplicateTargets(targets);
    expect(merged).toHaveLength(1);
    expect(merged[0].sources).toContain('github');
    expect(merged[0].sources).toContain('glama');
    expect(merged[0].language).toBe('typescript');
  });

  it('keeps distinct targets separate', () => {
    const targets: CrawlTarget[] = [
      { npmPackage: 'pkg-a', name: 'A', source: 'npm' },
      { npmPackage: 'pkg-b', name: 'B', source: 'npm' },
      { repoUrl: 'https://github.com/org/c', name: 'C', source: 'github' },
    ];

    const merged = deduplicateTargets(targets);
    expect(merged).toHaveLength(3);
  });

  it('merges categories from multiple sources', () => {
    const targets: CrawlTarget[] = [
      { npmPackage: 'pkg', name: 'pkg', categories: ['tools'], source: 'npm' },
      { npmPackage: 'pkg', name: 'pkg', categories: ['remote', 'tools'], source: 'glama' },
    ];

    const merged = deduplicateTargets(targets);
    expect(merged).toHaveLength(1);
    expect(merged[0].categories).toContain('tools');
    expect(merged[0].categories).toContain('remote');
    // No duplicates
    expect(merged[0].categories.filter(c => c === 'tools')).toHaveLength(1);
  });

  it('prefers npm package as dedup key when available', () => {
    const targets: CrawlTarget[] = [
      { repoUrl: 'https://github.com/org/repo', name: 'from-github', source: 'github' },
      {
        npmPackage: '@org/mcp-server',
        repoUrl: 'https://github.com/org/repo',
        name: 'from-npm',
        source: 'npm',
      },
    ];

    const merged = deduplicateTargets(targets);
    expect(merged).toHaveLength(1);
    expect(merged[0].dedupKey).toBe('@org/mcp-server');
  });

  it('handles empty input', () => {
    expect(deduplicateTargets([])).toHaveLength(0);
  });

  it('handles large input without hanging', () => {
    const targets: CrawlTarget[] = [];
    for (let i = 0; i < 10000; i++) {
      targets.push({
        npmPackage: `pkg-${i}`,
        name: `Package ${i}`,
        source: 'npm',
      });
    }
    const start = Date.now();
    const merged = deduplicateTargets(targets);
    expect(merged).toHaveLength(10000);
    expect(Date.now() - start).toBeLessThan(2000); // should be < 2s
  });

  it('merges glama + npm + official into one target', () => {
    const targets: CrawlTarget[] = [
      { glamaId: 'g1', repoUrl: 'https://github.com/org/x', name: 'X', source: 'glama' },
      { npmPackage: '@org/x', repoUrl: 'https://github.com/org/x', name: '@org/x', source: 'npm' },
      { repoUrl: 'https://github.com/org/x', name: 'X Server', source: 'official' },
    ];

    const merged = deduplicateTargets(targets);
    expect(merged).toHaveLength(1);
    expect(merged[0].sources).toEqual(expect.arrayContaining(['glama', 'npm', 'official']));
    expect(merged[0].npmPackage).toBe('@org/x');
    expect(merged[0].glamaId).toBe('g1');
  });
});
