#!/usr/bin/env node
/**
 * Database migration CLI.
 *
 * Usage: npx sentinel-migrate --database-url postgres://user:pass@host:5432/sentinel
 */

import { MIGRATIONS } from './schema.js';

async function main() {
  const dbUrl = process.env.DATABASE_URL ?? process.argv.find(a => a.startsWith('postgres'));

  if (!dbUrl) {
    console.error('Usage: sentinel-migrate --database-url postgres://...');
    console.error('  Or set DATABASE_URL environment variable.');
    process.exit(1);
  }

  console.log('Running migrations...');

  // Dynamic import of pg — peer dependency
  const { default: pg } = await import('pg');
  const pool = new pg.Pool({ connectionString: dbUrl, ssl: { rejectUnauthorized: false } });

  try {
    for (let i = 0; i < MIGRATIONS.length; i++) {
      console.log(`  Applying migration ${i + 1}/${MIGRATIONS.length}...`);
      await pool.query(MIGRATIONS[i]);
    }
    console.log('All migrations applied successfully.');
  } finally {
    await pool.end();
  }
}

main().catch(err => {
  console.error('Migration failed:', err.message);
  process.exit(1);
});
