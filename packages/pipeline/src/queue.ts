/**
 * Queue adapter — abstracts job queue operations.
 *
 * Two implementations:
 *   - InMemoryQueue: for local dev/testing
 *   - AzureQueue: for production (Azure Queue Storage)
 *
 * Message format: JSON-encoded ScanJob
 */

export interface ScanJob {
  targetId: string;
  npmPackage?: string;
  repoUrl?: string;
  trigger: 'first_scan' | 'version_change' | 'scheduled' | 'manual';
}

export interface QueueMessage {
  id: string;
  body: ScanJob;
  dequeueCount: number;
  /** Call to remove message from queue after successful processing. */
  complete: () => Promise<void>;
}

export interface ScanQueue {
  /** Send a job to the queue. */
  send(job: ScanJob): Promise<void>;
  /** Receive the next available message. Returns null if queue is empty. */
  receive(visibilityTimeoutSeconds?: number): Promise<QueueMessage | null>;
  /** Get approximate message count. */
  approximateCount(): Promise<number>;
}

// ─── In-Memory Queue (for local dev) ─────────────────────────

interface QueueEntry {
  id: string;
  body: ScanJob;
  dequeueCount: number;
  visibleAfter: number;
}

export class InMemoryQueue implements ScanQueue {
  private messages: QueueEntry[] = [];
  private counter = 0;

  async send(job: ScanJob): Promise<void> {
    this.messages.push({
      id: String(++this.counter),
      body: job,
      dequeueCount: 0,
      visibleAfter: 0,
    });
  }

  async receive(visibilityTimeoutSeconds: number = 300): Promise<QueueMessage | null> {
    const now = Date.now();
    const idx = this.messages.findIndex(m => m.visibleAfter <= now);
    if (idx === -1) return null;

    const entry = this.messages[idx];
    entry.dequeueCount++;
    entry.visibleAfter = now + visibilityTimeoutSeconds * 1000;

    return {
      id: entry.id,
      body: entry.body,
      dequeueCount: entry.dequeueCount,
      complete: async () => {
        const i = this.messages.indexOf(entry);
        if (i !== -1) this.messages.splice(i, 1);
      },
    };
  }

  async approximateCount(): Promise<number> {
    return this.messages.length;
  }
}

// ─── Azure Queue Storage ─────────────────────────────────────

export interface AzureQueueConfig {
  /** Azure Storage connection string */
  connectionString: string;
  /** Queue name (default: 'scan-queue') */
  queueName?: string;
}

/**
 * Azure Queue Storage adapter.
 * Requires `@azure/storage-queue` to be installed.
 */
export class AzureQueue implements ScanQueue {
  private config: AzureQueueConfig;
  private client: unknown; // QueueClient — loaded dynamically

  constructor(config: AzureQueueConfig) {
    this.config = config;
  }

  private async getClient(): Promise<{
    sendMessage(text: string): Promise<unknown>;
    receiveMessages(options: { numberOfMessages: number; visibilityTimeout: number }): Promise<{ receivedMessageItems: Array<{ messageId: string; popReceipt: string; messageText: string; dequeueCount: number }> }>;
    deleteMessage(messageId: string, popReceipt: string): Promise<unknown>;
    getProperties(): Promise<{ approximateMessagesCount?: number }>;
  }> {
    if (this.client) return this.client as ReturnType<typeof this.getClient> extends Promise<infer T> ? T : never;

    const { QueueClient } = await import('@azure/storage-queue');
    const queueName = this.config.queueName ?? 'scan-queue';
    const client = new QueueClient(this.config.connectionString, queueName);
    await client.createIfNotExists();
    this.client = client;
    return client as unknown as Awaited<ReturnType<typeof this.getClient>>;
  }

  async send(job: ScanJob): Promise<void> {
    const client = await this.getClient();
    // Base64 encode the message for Azure Queue Storage
    const text = Buffer.from(JSON.stringify(job)).toString('base64');
    await client.sendMessage(text);
  }

  async receive(visibilityTimeoutSeconds: number = 300): Promise<QueueMessage | null> {
    const client = await this.getClient();
    const response = await client.receiveMessages({
      numberOfMessages: 1,
      visibilityTimeout: visibilityTimeoutSeconds,
    });

    const items = response.receivedMessageItems;
    if (!items || items.length === 0) return null;

    const msg = items[0];
    const decoded = Buffer.from(msg.messageText, 'base64').toString('utf-8');
    const body = JSON.parse(decoded) as ScanJob;

    return {
      id: msg.messageId,
      body,
      dequeueCount: msg.dequeueCount,
      complete: async () => {
        await client.deleteMessage(msg.messageId, msg.popReceipt);
      },
    };
  }

  async approximateCount(): Promise<number> {
    const client = await this.getClient();
    const props = await client.getProperties();
    return props.approximateMessagesCount ?? 0;
  }
}
