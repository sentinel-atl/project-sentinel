/**
 * @sentinel-atl/pipeline — Scanning Pipeline & Data Storage
 *
 * Orchestrates the crawler → queue → scan → store pipeline
 * that powers the Sentinel trust intelligence database.
 */

// Database
export { PipelineDb, type PgPool, type DbConfig } from './db.js';
export { SCHEMA_VERSION, MIGRATIONS } from './schema.js';

// Queue
export {
  InMemoryQueue,
  AzureQueue,
  type ScanQueue,
  type ScanJob,
  type QueueMessage,
  type AzureQueueConfig,
} from './queue.js';

// Blob storage
export {
  LocalBlobStore,
  AzureBlobStore,
  type BlobStore,
  type AzureBlobConfig,
} from './blob.js';

// Worker
export {
  runWorker,
  checkVersionChanges,
  type WorkerConfig,
  type WorkerStats,
  type VersionWatcherConfig,
} from './worker.js';
