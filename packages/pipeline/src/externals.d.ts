// Type declarations for optional/dynamic dependencies

declare module 'pg' {
  export class Pool {
    constructor(config?: { connectionString?: string; ssl?: object });
    query(text: string, values?: unknown[]): Promise<{ rows: Record<string, unknown>[]; rowCount: number }>;
    end(): Promise<void>;
  }
}

declare module '@azure/storage-queue' {
  export class QueueClient {
    constructor(connectionString: string, queueName: string);
    createIfNotExists(): Promise<void>;
    sendMessage(messageText: string): Promise<unknown>;
    receiveMessages(options: { numberOfMessages: number; visibilityTimeout: number }): Promise<{
      receivedMessageItems: Array<{
        messageId: string;
        popReceipt: string;
        messageText: string;
        dequeueCount: number;
      }>;
    }>;
    deleteMessage(messageId: string, popReceipt: string): Promise<unknown>;
    getProperties(): Promise<{ approximateMessagesCount?: number }>;
  }
}

declare module '@azure/storage-blob' {
  export class BlobServiceClient {
    static fromConnectionString(connectionString: string): BlobServiceClient;
    getContainerClient(containerName: string): ContainerClient;
  }
  export class ContainerClient {
    createIfNotExists(): Promise<void>;
    getBlockBlobClient(blobName: string): BlockBlobClient;
  }
  export class BlockBlobClient {
    upload(data: string, length: number, options?: { blobHTTPHeaders?: { blobContentType?: string } }): Promise<unknown>;
    downloadToBuffer(): Promise<Buffer>;
    url: string;
  }
}
