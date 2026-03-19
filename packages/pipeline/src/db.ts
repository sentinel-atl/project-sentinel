/**
 * PostgreSQL database operations for the scan pipeline.
 *
 * This is NOT a generic KV store — these are domain-specific queries
 * for targets, scan reports, findings, and publishers.
 */

import { randomUUID } from 'node:crypto';
import type { ScanReport, Finding } from '@sentinel-atl/scanner';
import type { MergedTarget } from '@sentinel-atl/crawler';
import { MIGRATIONS } from './schema.js';

// We type the pg Pool interface ourselves to avoid a hard import
// The actual pg module is passed in at construction time.
export interface PgPool {
  query(text: string, values?: unknown[]): Promise<{ rows: Record<string, unknown>[]; rowCount: number }>;
  end(): Promise<void>;
}

export interface DbConfig {
  /** A pg.Pool instance (caller creates it) */
  pool: PgPool;
}

export class PipelineDb {
  private pool: PgPool;

  constructor(config: DbConfig) {
    this.pool = config.pool;
  }

  // ─── Migrations ──────────────────────────────────────────

  async migrate(): Promise<void> {
    // Run each migration in order
    for (const sql of MIGRATIONS) {
      await this.pool.query(sql);
    }
  }

  // ─── Targets ─────────────────────────────────────────────

  /** Upsert a crawled target. Returns the target ID. */
  async upsertTarget(target: MergedTarget): Promise<string> {
    const id = randomUUID();

    // Try to find existing by npm_package or repo_url
    const existing = await this.pool.query(
      `SELECT id FROM targets WHERE
        (npm_package IS NOT NULL AND npm_package = $1) OR
        (repo_url IS NOT NULL AND repo_url = $2) OR
        (glama_id IS NOT NULL AND glama_id = $3) OR
        (pypi_package IS NOT NULL AND pypi_package = $4)
       LIMIT 1`,
      [target.npmPackage ?? null, target.repoUrl ?? null, target.glamaId ?? null, target.pypiPackage ?? null]
    );

    if (existing.rows.length > 0) {
      // Update existing target with any new metadata
      const existingId = existing.rows[0].id as string;
      await this.pool.query(
        `UPDATE targets SET
          npm_package = COALESCE(npm_package, $2),
          pypi_package = COALESCE(pypi_package, $3),
          repo_url = COALESCE(repo_url, $4),
          glama_id = COALESCE(glama_id, $5),
          description = CASE WHEN LENGTH($6::TEXT) > LENGTH(COALESCE(description, '')) THEN $6 ELSE description END,
          language = COALESCE(language, $7),
          license = COALESCE(license, $8),
          publisher_name = COALESCE(publisher_name, $9),
          sources = (SELECT array_agg(DISTINCT s) FROM unnest(sources || $10::TEXT[]) s),
          last_crawled_at = NOW()
         WHERE id = $1`,
        [existingId, target.npmPackage ?? null, target.pypiPackage ?? null,
         target.repoUrl ?? null, target.glamaId ?? null,
         target.description ?? null, target.language ?? null,
         target.license ?? null, target.publisherName ?? null,
         target.sources]
      );
      return existingId;
    }

    // Insert new target
    await this.pool.query(
      `INSERT INTO targets (id, npm_package, pypi_package, repo_url, glama_id, name, description,
         language, license, categories, publisher_name, sources, status, scan_priority)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'pending', $13)`,
      [id, target.npmPackage ?? null, target.pypiPackage ?? null,
       target.repoUrl ?? null, target.glamaId ?? null,
       target.name, target.description ?? null,
       target.language ?? null, target.license ?? null,
       target.categories.length > 0 ? target.categories : null,
       target.publisherName ?? null, target.sources,
       target.npmPackage ? 30 : 50] // prioritize npm packages (directly scannable)
    );

    return id;
  }

  /** Get pending targets for scanning, ordered by priority. */
  async getPendingTargets(limit: number = 100): Promise<Array<{ id: string; npm_package: string | null; repo_url: string | null; name: string }>> {
    const result = await this.pool.query(
      `SELECT id, npm_package, repo_url, name FROM targets
       WHERE status = 'pending' AND npm_package IS NOT NULL
       ORDER BY scan_priority ASC, first_seen_at ASC
       LIMIT $1`,
      [limit]
    );
    return result.rows as Array<{ id: string; npm_package: string | null; repo_url: string | null; name: string }>;
  }

  /** Mark a target as scanning. */
  async markScanning(targetId: string): Promise<void> {
    await this.pool.query(
      `UPDATE targets SET status = 'scanning' WHERE id = $1`,
      [targetId]
    );
  }

  /** Mark a target as error. */
  async markError(targetId: string, error: string): Promise<void> {
    await this.pool.query(
      `UPDATE targets SET status = 'error' WHERE id = $1`,
      [targetId]
    );
    // Store last error for debugging — truncate to 1000 chars
    const truncated = error.length > 1000 ? error.slice(0, 1000) : error;
    await this.pool.query(
      `UPDATE targets SET description = COALESCE(description, '') || E'\n[ERROR] ' || $2 WHERE id = $1`,
      [targetId, truncated]
    );
  }

  /** Mark a target as excluded from scanning. */
  async markExcluded(targetId: string, reason: string): Promise<void> {
    await this.pool.query(
      `UPDATE targets SET status = 'excluded' WHERE id = $1`,
      [targetId]
    );
  }

  // ─── Scan Reports ────────────────────────────────────────

  /** Insert a completed scan report and update the target's latest scan. */
  async insertScanReport(
    targetId: string,
    report: ScanReport,
    blobUrl: string | null,
    trigger: string = 'scheduled'
  ): Promise<string> {
    const reportId = randomUUID();

    // Count findings by severity
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of report.findings) {
      if (f.severity in counts) counts[f.severity as keyof typeof counts]++;
    }

    await this.pool.query(
      `INSERT INTO scan_reports (
         id, target_id, scanned_at, scanner_version, duration_ms, package_version, scan_depth,
         score_overall, grade,
         score_deps, score_patterns, score_perms, score_publisher, score_semantic, score_typosquat,
         score_integrity, score_behavior, score_provenance,
         code_hash, ast_findings_count,
         findings_critical, findings_high, findings_medium, findings_low, findings_info,
         report_blob_url, scan_trigger
       ) VALUES (
         $1, $2, $3, $4, $5, $6, $7,
         $8, $9,
         $10, $11, $12, $13, $14, $15,
         $16, $17, $18,
         $19, $20,
         $21, $22, $23, $24, $25,
         $26, $27
       )`,
      [
        reportId, targetId, report.scannedAt, report.scannerVersion, report.durationMs,
        report.packageVersion, report.scanDepth,
        report.trustScore.overall, report.trustScore.grade,
        report.trustScore.breakdown.dependencies,
        report.trustScore.breakdown.codePatterns,
        report.trustScore.breakdown.permissions,
        report.trustScore.breakdown.publisher,
        report.trustScore.breakdown.semantic ?? null,
        report.trustScore.breakdown.typosquat ?? null,
        report.trustScore.dimensions.integrity,
        report.trustScore.dimensions.behavior,
        report.trustScore.dimensions.provenance,
        report.codeHash, report.ast?.findings?.length ?? 0,
        counts.critical, counts.high, counts.medium, counts.low, counts.info,
        blobUrl, trigger,
      ]
    );

    // Update target's latest scan summary
    await this.pool.query(
      `UPDATE targets SET
         latest_score = $2, latest_grade = $3, latest_scan_id = $4,
         latest_version = $5, status = 'scanned'
       WHERE id = $1`,
      [targetId, report.trustScore.overall, report.trustScore.grade, reportId, report.packageVersion]
    );

    return reportId;
  }

  /** Insert findings from a scan report. */
  async insertFindings(targetId: string, reportId: string, findings: Finding[]): Promise<void> {
    if (findings.length === 0) return;

    // Batch insert in groups of 50
    for (let i = 0; i < findings.length; i += 50) {
      const batch = findings.slice(i, i + 50);
      const values: unknown[] = [];
      const placeholders: string[] = [];

      for (let j = 0; j < batch.length; j++) {
        const f = batch[j];
        const base = j * 8;
        placeholders.push(
          `($${base + 1}, $${base + 2}, $${base + 3}, $${base + 4}, $${base + 5}, $${base + 6}, $${base + 7}, $${base + 8})`
        );
        values.push(reportId, targetId, f.severity, f.category, f.title,
          f.description ?? null, f.file ?? null, f.line ?? null);
      }

      await this.pool.query(
        `INSERT INTO findings (scan_report_id, target_id, severity, category, title, description, file_path, line_number)
         VALUES ${placeholders.join(', ')}`,
        values
      );
    }
  }

  // ─── Version Watch ────────────────────────────────────────

  /** Get targets that need version checking. */
  async getWatchedTargets(limit: number = 500): Promise<Array<{
    id: string;
    npm_package: string;
    last_known_version: string | null;
    npm_etag: string | null;
  }>> {
    const result = await this.pool.query(
      `SELECT t.id, t.npm_package, vw.last_known_version, vw.npm_etag
       FROM targets t
       LEFT JOIN version_watch vw ON vw.target_id = t.id
       WHERE t.npm_package IS NOT NULL AND t.status != 'excluded'
       ORDER BY COALESCE(vw.last_checked_at, '1970-01-01'::TIMESTAMPTZ) ASC
       LIMIT $1`,
      [limit]
    );
    return result.rows as Array<{ id: string; npm_package: string; last_known_version: string | null; npm_etag: string | null }>;
  }

  /** Update version watch tracking. */
  async updateVersionWatch(targetId: string, version: string, etag: string | null): Promise<void> {
    await this.pool.query(
      `INSERT INTO version_watch (target_id, last_known_version, last_checked_at, npm_etag)
       VALUES ($1, $2, NOW(), $3)
       ON CONFLICT (target_id) DO UPDATE SET
         last_known_version = $2, last_checked_at = NOW(), npm_etag = $3`,
      [targetId, version, etag]
    );
  }

  // ─── Crawl Runs ──────────────────────────────────────────

  /** Record the start of a crawl run. */
  async startCrawlRun(source: string): Promise<string> {
    const id = randomUUID();
    await this.pool.query(
      `INSERT INTO crawl_runs (id, source, status) VALUES ($1, $2, 'running')`,
      [id, source]
    );
    return id;
  }

  /** Complete a crawl run. */
  async completeCrawlRun(runId: string, found: number, newCount: number, updated: number): Promise<void> {
    await this.pool.query(
      `UPDATE crawl_runs SET finished_at = NOW(), targets_found = $2, targets_new = $3,
         targets_updated = $4, status = 'completed' WHERE id = $1`,
      [runId, found, newCount, updated]
    );
  }

  /** Mark a crawl run as failed. */
  async failCrawlRun(runId: string, error: string): Promise<void> {
    await this.pool.query(
      `UPDATE crawl_runs SET finished_at = NOW(), status = 'failed', error_message = $2 WHERE id = $1`,
      [runId, error.slice(0, 2000)]
    );
  }

  // ─── Stats ────────────────────────────────────────────────

  /** Get summary statistics. */
  async getStats(): Promise<{
    totalTargets: number;
    totalScanned: number;
    totalPending: number;
    avgScore: number;
    gradeDistribution: Record<string, number>;
  }> {
    const total = await this.pool.query(`SELECT COUNT(*) as count FROM targets`);
    const scanned = await this.pool.query(`SELECT COUNT(*) as count FROM targets WHERE status = 'scanned'`);
    const pending = await this.pool.query(`SELECT COUNT(*) as count FROM targets WHERE status = 'pending'`);
    const avg = await this.pool.query(`SELECT COALESCE(AVG(latest_score), 0) as avg FROM targets WHERE latest_score IS NOT NULL`);
    const grades = await this.pool.query(
      `SELECT latest_grade, COUNT(*) as count FROM targets WHERE latest_grade IS NOT NULL GROUP BY latest_grade`
    );

    const gradeDistribution: Record<string, number> = {};
    for (const row of grades.rows) {
      gradeDistribution[row.latest_grade as string] = Number(row.count);
    }

    return {
      totalTargets: Number(total.rows[0].count),
      totalScanned: Number(scanned.rows[0].count),
      totalPending: Number(pending.rows[0].count),
      avgScore: Math.round(Number(avg.rows[0].avg)),
      gradeDistribution,
    };
  }

  /** Close the database connection pool. */
  async close(): Promise<void> {
    await this.pool.end();
  }
}
