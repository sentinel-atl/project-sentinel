/**
 * Database schema migration — create all tables for the data moat.
 *
 * Updated for scanner v0.5.0 fields:
 *   - code_hash, score_integrity, score_behavior, score_provenance
 *   - ast_findings_count
 *   - scan_depth
 *
 * Run: npx sentinel-migrate --database-url postgres://...
 */

export const SCHEMA_VERSION = 2;

export const MIGRATIONS: string[] = [
  // ─── V1: Core schema ────────────────────────────────────────
  `
-- Discovered MCP servers/packages (crawl output)
CREATE TABLE IF NOT EXISTS targets (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  npm_package     TEXT,
  pypi_package    TEXT,
  repo_url        TEXT,
  glama_id        TEXT,
  name            TEXT NOT NULL,
  description     TEXT,
  language        TEXT,
  license         TEXT,
  categories      TEXT[],
  publisher_name  TEXT,
  sources         TEXT[] NOT NULL DEFAULT '{}',
  first_seen_at   TIMESTAMPTZ DEFAULT NOW(),
  last_crawled_at TIMESTAMPTZ,
  latest_score    SMALLINT,
  latest_grade    CHAR(1),
  latest_scan_id  UUID,
  latest_version  TEXT,
  status          TEXT DEFAULT 'pending',
  scan_priority   SMALLINT DEFAULT 50
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_targets_npm ON targets(npm_package) WHERE npm_package IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_targets_pypi ON targets(pypi_package) WHERE pypi_package IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_targets_status ON targets(status);
CREATE INDEX IF NOT EXISTS idx_targets_grade ON targets(latest_grade);
CREATE INDEX IF NOT EXISTS idx_targets_score ON targets(latest_score);
CREATE INDEX IF NOT EXISTS idx_targets_repo ON targets(repo_url);
CREATE INDEX IF NOT EXISTS idx_targets_glama ON targets(glama_id);

-- Individual scan results
CREATE TABLE IF NOT EXISTS scan_reports (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id       UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  scanned_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  scanner_version TEXT NOT NULL,
  duration_ms     INTEGER,
  package_version TEXT,
  scan_depth      TEXT DEFAULT 'fast',
  -- Trust score
  score_overall   SMALLINT NOT NULL,
  grade           CHAR(1) NOT NULL,
  -- Per-scanner breakdown
  score_deps      SMALLINT,
  score_patterns  SMALLINT,
  score_perms     SMALLINT,
  score_publisher SMALLINT,
  score_semantic  SMALLINT,
  score_typosquat SMALLINT,
  -- Dimensional scores (v0.5.0)
  score_integrity  SMALLINT,
  score_behavior   SMALLINT,
  score_provenance SMALLINT,
  -- Content hash (v0.5.0)
  code_hash       TEXT,
  -- Finding counts
  findings_critical INTEGER DEFAULT 0,
  findings_high     INTEGER DEFAULT 0,
  findings_medium   INTEGER DEFAULT 0,
  findings_low      INTEGER DEFAULT 0,
  findings_info     INTEGER DEFAULT 0,
  ast_findings_count INTEGER DEFAULT 0,
  -- Full report reference
  report_blob_url TEXT,
  scan_trigger    TEXT DEFAULT 'scheduled',
  CONSTRAINT valid_score CHECK (score_overall BETWEEN 0 AND 100)
);

CREATE INDEX IF NOT EXISTS idx_reports_target ON scan_reports(target_id, scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_date ON scan_reports(scanned_at);
CREATE INDEX IF NOT EXISTS idx_reports_grade ON scan_reports(grade);
CREATE INDEX IF NOT EXISTS idx_reports_hash ON scan_reports(code_hash);

-- Individual findings
CREATE TABLE IF NOT EXISTS findings (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_report_id  UUID NOT NULL REFERENCES scan_reports(id) ON DELETE CASCADE,
  target_id       UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  severity        TEXT NOT NULL,
  category        TEXT NOT NULL,
  title           TEXT NOT NULL,
  description     TEXT,
  file_path       TEXT,
  line_number     INTEGER,
  evidence        TEXT,
  scanned_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_report ON findings(scan_report_id);

-- Publisher reputation
CREATE TABLE IF NOT EXISTS publishers (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  npm_username    TEXT UNIQUE,
  github_username TEXT UNIQUE,
  total_packages  INTEGER DEFAULT 0,
  avg_trust_score SMALLINT,
  packages_grade_a INTEGER DEFAULT 0,
  packages_grade_f INTEGER DEFAULT 0,
  npm_account_age_days  INTEGER,
  npm_total_downloads   BIGINT,
  first_seen_at   TIMESTAMPTZ DEFAULT NOW(),
  last_updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Crawl run tracking
CREATE TABLE IF NOT EXISTS crawl_runs (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source          TEXT NOT NULL,
  started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at     TIMESTAMPTZ,
  targets_found   INTEGER DEFAULT 0,
  targets_new     INTEGER DEFAULT 0,
  targets_updated INTEGER DEFAULT 0,
  status          TEXT DEFAULT 'running',
  error_message   TEXT
);

-- Daily aggregate stats
CREATE TABLE IF NOT EXISTS daily_stats (
  date            DATE PRIMARY KEY,
  total_targets   INTEGER,
  total_scanned   INTEGER,
  avg_score       NUMERIC(5,2),
  grade_a_count   INTEGER,
  grade_b_count   INTEGER,
  grade_c_count   INTEGER,
  grade_d_count   INTEGER,
  grade_f_count   INTEGER,
  critical_findings INTEGER,
  new_targets     INTEGER,
  rescans         INTEGER
);

-- Version change watching
CREATE TABLE IF NOT EXISTS version_watch (
  target_id       UUID PRIMARY KEY REFERENCES targets(id) ON DELETE CASCADE,
  last_known_version TEXT,
  last_checked_at TIMESTAMPTZ DEFAULT NOW(),
  npm_etag        TEXT
);

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO schema_migrations (version) VALUES (1) ON CONFLICT DO NOTHING;
  `,

  // ─── V2: Indexes for pipeline perf ──────────────────────────
  `
CREATE INDEX IF NOT EXISTS idx_targets_scan_priority ON targets(scan_priority ASC, first_seen_at ASC) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_version_watch_checked ON version_watch(last_checked_at ASC);
UPDATE schema_migrations SET version = 2 WHERE version = 1;
  `,
];
