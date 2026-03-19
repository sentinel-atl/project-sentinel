/**
 * Blob storage adapter — store full scan report JSON blobs.
 *
 * Two implementations:
 *   - LocalBlobStore: filesystem-based for local dev
 *   - AzureBlobStore: Azure Blob Storage for production
 */

import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';

export interface BlobStore {
  /** Upload a scan report blob. Returns the blob URL/path. */
  uploadReport(targetId: string, reportId: string, report: object): Promise<string>;
  /** Download a scan report blob. */
  downloadReport(blobUrl: string): Promise<object | null>;
}

// ─── Local Filesystem Blob Store ──────────────────────────────

export class LocalBlobStore implements BlobStore {
  private basePath: string;

  constructor(basePath: string) {
    this.basePath = basePath;
  }

  async uploadReport(targetId: string, reportId: string, report: object): Promise<string> {
    const dir = join(this.basePath, 'reports', targetId);
    await mkdir(dir, { recursive: true });

    const filePath = join(dir, `${reportId}.json`);
    await writeFile(filePath, JSON.stringify(report, null, 2));

    // Also write as latest.json
    const latestPath = join(dir, 'latest.json');
    await writeFile(latestPath, JSON.stringify(report, null, 2));

    return filePath;
  }

  async downloadReport(blobUrl: string): Promise<object | null> {
    try {
      const raw = await readFile(blobUrl, 'utf-8');
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }
}

// ─── Azure Blob Storage ──────────────────────────────────────

export interface AzureBlobConfig {
  /** Azure Storage connection string */
  connectionString: string;
  /** Container name (default: 'reports') */
  containerName?: string;
}

/**
 * Azure Blob Storage adapter.
 * Requires `@azure/storage-blob` to be installed.
 */
export class AzureBlobStore implements BlobStore {
  private config: AzureBlobConfig;
  private client: unknown;

  constructor(config: AzureBlobConfig) {
    this.config = config;
  }

  private async getContainer(): Promise<{
    getBlockBlobClient(name: string): {
      upload(data: string, length: number, options?: object): Promise<unknown>;
      downloadToBuffer(): Promise<Buffer>;
      url: string;
    };
    createIfNotExists(): Promise<unknown>;
  }> {
    if (this.client) return this.client as Awaited<ReturnType<typeof this.getContainer>>;

    const { BlobServiceClient } = await import('@azure/storage-blob');
    const service = BlobServiceClient.fromConnectionString(this.config.connectionString);
    const container = service.getContainerClient(this.config.containerName ?? 'reports');
    await container.createIfNotExists();
    this.client = container;
    return container as unknown as Awaited<ReturnType<typeof this.getContainer>>;
  }

  async uploadReport(targetId: string, reportId: string, report: object): Promise<string> {
    const container = await this.getContainer();
    const blobName = `reports/${targetId}/${reportId}.json`;
    const data = JSON.stringify(report, null, 2);
    const blob = container.getBlockBlobClient(blobName);
    await blob.upload(data, Buffer.byteLength(data), {
      blobHTTPHeaders: { blobContentType: 'application/json' },
    });
    return blob.url;
  }

  async downloadReport(blobUrl: string): Promise<object | null> {
    try {
      const container = await this.getContainer();
      // Extract blob name from URL
      const url = new URL(blobUrl);
      const blobName = url.pathname.split('/').slice(2).join('/');
      const blob = container.getBlockBlobClient(blobName);
      const buffer = await blob.downloadToBuffer();
      return JSON.parse(buffer.toString('utf-8'));
    } catch {
      return null;
    }
  }
}
