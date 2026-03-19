/**
 * @sentinel-atl/approval — Human Approval Workflows
 *
 * The @sentinel-atl/stepup package creates challenges and verifies approvals,
 * but has no delivery mechanism. This package DELIVERS challenges to humans
 * and collects their responses.
 *
 * Channels:
 * - **Webhook** — POST challenge to any URL, receive approval via callback
 * - **Slack** — Send interactive message with Approve/Deny buttons
 * - **Web UI** — Built-in HTTP server with approve/deny page
 * - **Console** — CLI prompt (for development/testing)
 *
 * Usage:
 *   import { ApprovalRouter, WebhookChannel, SlackChannel, WebUIChannel } from '@sentinel-atl/approval';
 *   const router = new ApprovalRouter();
 *   router.addChannel(new WebhookChannel({ url: 'https://my-api.com/approvals' }));
 *   router.addChannel(new SlackChannel({ webhookUrl: process.env.SLACK_WEBHOOK_URL! }));
 *   router.addChannel(new WebUIChannel({ port: 3200 }));
 *   const result = await router.requestApproval(challenge);
 */

import { createServer, type ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';

// ─── Retry Helper ────────────────────────────────────────────────────

interface RetryOptions {
  maxRetries: number;
  baseDelayMs: number;
  maxDelayMs: number;
}

const DEFAULT_RETRY: RetryOptions = { maxRetries: 3, baseDelayMs: 1000, maxDelayMs: 30_000 };

async function fetchWithRetry(
  url: string,
  init: RequestInit,
  opts: RetryOptions = DEFAULT_RETRY,
): Promise<Response> {
  let lastError: Error | undefined;
  for (let attempt = 0; attempt <= opts.maxRetries; attempt++) {
    try {
      const response = await fetch(url, init);
      if (response.ok || response.status < 500) return response;
      lastError = new Error(`HTTP ${response.status} ${response.statusText}`);
    } catch (err) {
      lastError = err as Error;
    }
    if (attempt < opts.maxRetries) {
      const delay = Math.min(opts.baseDelayMs * Math.pow(2, attempt), opts.maxDelayMs);
      const jitter = delay * (0.5 + Math.random() * 0.5);
      await new Promise(r => setTimeout(r, jitter));
    }
  }
  throw lastError ?? new Error('Fetch failed after retries');
}

// ─── Types ───────────────────────────────────────────────────────────

export interface ApprovalChallenge {
  challengeId: string;
  agentDid: string;
  principalDid: string;
  action: string;
  actionDescription: string;
  scope: string[];
  expiresAt: string;
}

export interface ApprovalResponse {
  challengeId: string;
  decision: 'approved' | 'denied';
  decidedBy: string;
  decidedAt: string;
  channel: string;
}

/**
 * Delivery channel interface. Implement this to add a new channel.
 */
export interface ApprovalChannel {
  readonly name: string;

  /**
   * Send a challenge to the human and wait for their response.
   * Should resolve when the human responds or the challenge expires.
   */
  requestApproval(challenge: ApprovalChallenge): Promise<ApprovalResponse>;

  /** Optional: clean up resources */
  close?(): Promise<void>;
}

// ─── Webhook Channel ─────────────────────────────────────────────────

export interface WebhookChannelConfig {
  /** URL to POST challenges to */
  url: string;
  /** URL that will receive approval callbacks (set by the recipient) */
  callbackUrl?: string;
  /** Headers to include on POST (e.g., Authorization) */
  headers?: Record<string, string>;
  /** Timeout in ms (default: 300_000 = 5 min) */
  timeoutMs?: number;
  /** Port to listen for callbacks (default: 0 = auto) */
  callbackPort?: number;
  /** Retry options for webhook delivery (default: 3 retries, exponential backoff) */
  retry?: Partial<RetryOptions>;
}

export class WebhookChannel implements ApprovalChannel {
  readonly name = 'webhook';
  private config: Required<WebhookChannelConfig>;
  private pendingCallbacks = new Map<string, (response: ApprovalResponse) => void>();
  private server: ReturnType<typeof createServer> | null = null;

  constructor(config: WebhookChannelConfig) {
    this.config = {
      url: config.url,
      callbackUrl: config.callbackUrl ?? '',
      headers: config.headers ?? {},
      timeoutMs: config.timeoutMs ?? 300_000,
      callbackPort: config.callbackPort ?? 0,
    };
  }

  async requestApproval(challenge: ApprovalChallenge): Promise<ApprovalResponse> {
    // Ensure callback server is running
    if (!this.server) {
      await this.startCallbackServer();
    }

    // POST challenge to webhook URL with retry
    const callbackUrl = this.config.callbackUrl || `http://localhost:${this.config.callbackPort}/callback`;
    const retryOpts = { ...DEFAULT_RETRY, ...this.config.retry };
    const response = await fetchWithRetry(this.config.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Idempotency-Key': challenge.challengeId,
        ...this.config.headers,
      },
      body: JSON.stringify({
        ...challenge,
        callbackUrl: `${callbackUrl}?challengeId=${challenge.challengeId}`,
      }),
    }, retryOpts);

    if (!response.ok) {
      throw new Error(`Webhook delivery failed: ${response.status} ${response.statusText}`);
    }

    // Wait for callback
    return new Promise<ApprovalResponse>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingCallbacks.delete(challenge.challengeId);
        reject(new Error(`Approval timed out after ${this.config.timeoutMs}ms`));
      }, this.config.timeoutMs);

      this.pendingCallbacks.set(challenge.challengeId, (resp) => {
        clearTimeout(timeout);
        resolve(resp);
      });
    });
  }

  private async startCallbackServer(): Promise<void> {
    this.server = createServer(async (req, res) => {
      if (req.method === 'POST' && req.url?.startsWith('/callback')) {
        const url = new URL(req.url, `http://localhost`);
        const challengeId = url.searchParams.get('challengeId');

        const body = await this.readBody(req);
        const data = JSON.parse(body);
        const callback = challengeId ? this.pendingCallbacks.get(challengeId) : undefined;

        if (callback) {
          this.pendingCallbacks.delete(challengeId!);
          callback({
            challengeId: challengeId!,
            decision: data.decision === 'approved' ? 'approved' : 'denied',
            decidedBy: data.decidedBy ?? 'webhook',
            decidedAt: new Date().toISOString(),
            channel: 'webhook',
          });
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ received: true }));
      } else {
        res.writeHead(404);
        res.end();
      }
    });

    return new Promise((resolve) => {
      this.server!.listen(this.config.callbackPort, () => {
        const addr = this.server!.address();
        if (typeof addr === 'object' && addr) {
          this.config.callbackPort = addr.port;
        }
        resolve();
      });
    });
  }

  private readBody(req: any): Promise<string> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      req.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > 65536) { reject(new Error('Body too large')); req.destroy(); return; }
        chunks.push(chunk);
      });
      req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
      req.on('error', reject);
    });
  }

  async close(): Promise<void> {
    if (this.server) {
      return new Promise((resolve) => this.server!.close(() => resolve()));
    }
  }
}

// ─── Slack Channel ───────────────────────────────────────────────────

export interface SlackChannelConfig {
  /** Slack Incoming Webhook URL */
  webhookUrl: string;
  /** Channel to post to (if using Bot token instead of webhook) */
  channel?: string;
  /** Timeout in ms (default: 300_000 = 5 min) */
  timeoutMs?: number;
  /** Callback URL for Slack interactivity (optional — without it, uses reaction-based polling) */
  interactivityUrl?: string;
  /** Port for interactivity callback server */
  callbackPort?: number;
  /** Retry options for Slack webhook delivery (default: 3 retries, exponential backoff) */
  retry?: Partial<RetryOptions>;
}

export class SlackChannel implements ApprovalChannel {
  readonly name = 'slack';
  private config: Required<SlackChannelConfig>;
  private pendingCallbacks = new Map<string, (response: ApprovalResponse) => void>();
  private server: ReturnType<typeof createServer> | null = null;

  constructor(config: SlackChannelConfig) {
    this.config = {
      webhookUrl: config.webhookUrl,
      channel: config.channel ?? '',
      timeoutMs: config.timeoutMs ?? 300_000,
      interactivityUrl: config.interactivityUrl ?? '',
      callbackPort: config.callbackPort ?? 0,
      retry: config.retry ?? {},
    };
  }

  async requestApproval(challenge: ApprovalChallenge): Promise<ApprovalResponse> {
    // Start callback server if we have interactivity
    if (this.config.interactivityUrl && !this.server) {
      await this.startCallbackServer();
    }

    // Build Slack Block Kit message with interactive buttons
    const blocks = [
      {
        type: 'header',
        text: { type: 'plain_text', text: '🔐 Sentinel Step-Up Approval Required' },
      },
      {
        type: 'section',
        fields: [
          { type: 'mrkdwn', text: `*Agent:*\n\`${challenge.agentDid.slice(0, 32)}...\`` },
          { type: 'mrkdwn', text: `*Action:*\n${challenge.action}` },
        ],
      },
      {
        type: 'section',
        text: { type: 'mrkdwn', text: `*Description:*\n${challenge.actionDescription}` },
      },
      {
        type: 'section',
        fields: [
          { type: 'mrkdwn', text: `*Scopes:*\n${challenge.scope.join(', ')}` },
          { type: 'mrkdwn', text: `*Expires:*\n${challenge.expiresAt}` },
        ],
      },
      {
        type: 'actions',
        block_id: `sentinel_approval_${challenge.challengeId}`,
        elements: [
          {
            type: 'button',
            text: { type: 'plain_text', text: '✅ Approve' },
            style: 'primary',
            action_id: 'sentinel_approve',
            value: challenge.challengeId,
          },
          {
            type: 'button',
            text: { type: 'plain_text', text: '❌ Deny' },
            style: 'danger',
            action_id: 'sentinel_deny',
            value: challenge.challengeId,
          },
        ],
      },
    ];

    // Post to Slack with retry
    const retryOpts = { ...DEFAULT_RETRY, ...this.config.retry };
    const response = await fetchWithRetry(this.config.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ blocks, text: `Sentinel approval needed: ${challenge.action}` }),
    }, retryOpts);

    if (!response.ok) {
      throw new Error(`Slack webhook failed: ${response.status}`);
    }

    // Wait for interactive response (or timeout)
    if (this.config.interactivityUrl) {
      return new Promise<ApprovalResponse>((resolve, reject) => {
        const timeout = setTimeout(() => {
          this.pendingCallbacks.delete(challenge.challengeId);
          reject(new Error('Slack approval timed out'));
        }, this.config.timeoutMs);

        this.pendingCallbacks.set(challenge.challengeId, (resp) => {
          clearTimeout(timeout);
          resolve(resp);
        });
      });
    }

    // Without interactivity, the message is fire-and-forget.
    // Caller should use polling or a different channel for the response.
    throw new Error(
      'Slack channel requires interactivityUrl for receiving responses. ' +
      'Set up Slack interactivity and provide the callback URL.'
    );
  }

  private async startCallbackServer(): Promise<void> {
    this.server = createServer(async (req, res) => {
      if (req.method === 'POST' && req.url === '/slack/actions') {
        const body = await this.readBody(req);
        // Slack sends form-encoded payload
        const params = new URLSearchParams(body);
        const payloadStr = params.get('payload');
        if (payloadStr) {
          const payload = JSON.parse(payloadStr);
          for (const action of payload.actions ?? []) {
            const challengeId = action.value;
            const decision = action.action_id === 'sentinel_approve' ? 'approved' : 'denied';
            const callback = this.pendingCallbacks.get(challengeId);
            if (callback) {
              this.pendingCallbacks.delete(challengeId);
              callback({
                challengeId,
                decision: decision as 'approved' | 'denied',
                decidedBy: payload.user?.name ?? 'slack-user',
                decidedAt: new Date().toISOString(),
                channel: 'slack',
              });
            }
          }
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } else {
        res.writeHead(404);
        res.end();
      }
    });

    return new Promise((resolve) => {
      this.server!.listen(this.config.callbackPort, () => {
        const addr = this.server!.address();
        if (typeof addr === 'object' && addr) {
          this.config.callbackPort = addr.port;
        }
        resolve();
      });
    });
  }

  private readBody(req: any): Promise<string> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      req.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > 65536) { reject(new Error('Body too large')); req.destroy(); return; }
        chunks.push(chunk);
      });
      req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
      req.on('error', reject);
    });
  }

  async close(): Promise<void> {
    if (this.server) {
      return new Promise((resolve) => this.server!.close(() => resolve()));
    }
  }
}

// ─── Web UI Channel ──────────────────────────────────────────────────

export interface WebUIChannelConfig {
  /** Port for the approval web UI (default: 3200) */
  port?: number;
  /** Title for the page */
  title?: string;
}

export class WebUIChannel implements ApprovalChannel {
  readonly name = 'web-ui';
  private config: { port: number; title: string };
  private server: ReturnType<typeof createServer> | null = null;
  private pendingChallenges = new Map<string, {
    challenge: ApprovalChallenge;
    resolve: (resp: ApprovalResponse) => void;
    reject: (err: Error) => void;
  }>();

  constructor(config?: WebUIChannelConfig) {
    this.config = {
      port: config?.port ?? 3200,
      title: config?.title ?? 'Sentinel Approval Portal',
    };
  }

  async requestApproval(challenge: ApprovalChallenge): Promise<ApprovalResponse> {
    if (!this.server) await this.startServer();

    return new Promise<ApprovalResponse>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingChallenges.delete(challenge.challengeId);
        reject(new Error('Web UI approval timed out'));
      }, new Date(challenge.expiresAt).getTime() - Date.now());

      this.pendingChallenges.set(challenge.challengeId, {
        challenge,
        resolve: (resp) => { clearTimeout(timeout); resolve(resp); },
        reject: (err) => { clearTimeout(timeout); reject(err); },
      });
    });
  }

  private async startServer(): Promise<void> {
    this.server = createServer(async (req, res) => {
      const url = new URL(req.url ?? '/', `http://localhost:${this.config.port}`);

      if (url.pathname === '/' && req.method === 'GET') {
        this.renderDashboard(res);
      } else if (url.pathname === '/api/pending' && req.method === 'GET') {
        this.handleListPending(res);
      } else if (url.pathname === '/api/decide' && req.method === 'POST') {
        await this.handleDecision(req, res);
      } else {
        res.writeHead(404);
        res.end('Not Found');
      }
    });

    return new Promise((resolve) => {
      this.server!.listen(this.config.port, () => resolve());
    });
  }

  private renderDashboard(res: ServerResponse): void {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${this.config.title}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0d1117; color: #e6edf3; padding: 24px; }
    h1 { font-size: 28px; margin-bottom: 8px; }
    .subtitle { color: #8b949e; margin-bottom: 24px; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 16px; }
    .card h3 { margin-bottom: 12px; color: #58a6ff; }
    .field { display: flex; gap: 12px; margin-bottom: 8px; }
    .field .label { color: #8b949e; min-width: 120px; }
    .field .value { color: #e6edf3; font-family: monospace; word-break: break-all; }
    .actions { display: flex; gap: 12px; margin-top: 16px; }
    .btn { padding: 10px 24px; border: none; border-radius: 6px; font-size: 14px; font-weight: 600; cursor: pointer; }
    .btn-approve { background: #238636; color: white; }
    .btn-approve:hover { background: #2ea043; }
    .btn-deny { background: #da3633; color: white; }
    .btn-deny:hover { background: #f85149; }
    .empty { text-align: center; padding: 48px; color: #8b949e; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; background: #388bfd26; color: #58a6ff; }
  </style>
</head>
<body>
  <h1>🔐 ${this.config.title}</h1>
  <p class="subtitle">Pending step-up authentication requests from AI agents</p>
  <div id="challenges"></div>
  <script>
    async function load() {
      const res = await fetch('/api/pending');
      const challenges = await res.json();
      const el = document.getElementById('challenges');
      if (challenges.length === 0) {
        el.innerHTML = '<div class="empty">No pending approvals</div>';
        return;
      }
      el.innerHTML = challenges.map(c => \`
        <div class="card" id="card-\${c.challengeId}">
          <h3>\${c.action}</h3>
          <div class="field"><span class="label">Description</span><span class="value">\${c.actionDescription}</span></div>
          <div class="field"><span class="label">Agent DID</span><span class="value">\${c.agentDid}</span></div>
          <div class="field"><span class="label">Scopes</span><span class="value">\${c.scope.map(s => '<span class="badge">'+s+'</span>').join(' ')}</span></div>
          <div class="field"><span class="label">Expires</span><span class="value">\${new Date(c.expiresAt).toLocaleString()}</span></div>
          <div class="actions">
            <button class="btn btn-approve" onclick="decide('\${c.challengeId}','approved')">✅ Approve</button>
            <button class="btn btn-deny" onclick="decide('\${c.challengeId}','denied')">❌ Deny</button>
          </div>
        </div>
      \`).join('');
    }
    async function decide(id, decision) {
      await fetch('/api/decide', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ challengeId: id, decision })
      });
      document.getElementById('card-' + id)?.remove();
    }
    load();
    setInterval(load, 5000);
  </script>
</body>
</html>`);
  }

  private handleListPending(res: ServerResponse): void {
    const pending = Array.from(this.pendingChallenges.values()).map(p => p.challenge);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(pending));
  }

  private async handleDecision(req: any, res: ServerResponse): Promise<void> {
    const body = await new Promise<string>((resolve, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      req.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > 65536) { reject(new Error('Body too large')); req.destroy(); return; }
        chunks.push(chunk);
      });
      req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
      req.on('error', reject);
    });

    const { challengeId, decision } = JSON.parse(body);
    const pending = this.pendingChallenges.get(challengeId);

    if (!pending) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Challenge not found' }));
      return;
    }

    this.pendingChallenges.delete(challengeId);
    pending.resolve({
      challengeId,
      decision: decision === 'approved' ? 'approved' : 'denied',
      decidedBy: 'web-ui',
      decidedAt: new Date().toISOString(),
      channel: 'web-ui',
    });

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
  }

  async close(): Promise<void> {
    for (const [, p] of this.pendingChallenges) {
      p.reject(new Error('Server shutting down'));
    }
    this.pendingChallenges.clear();
    if (this.server) {
      return new Promise((resolve) => this.server!.close(() => resolve()));
    }
  }
}

// ─── Console Channel (for dev/testing) ───────────────────────────────

export class ConsoleChannel implements ApprovalChannel {
  readonly name = 'console';
  private autoDecision?: 'approved' | 'denied';

  constructor(options?: { autoDecision?: 'approved' | 'denied' }) {
    this.autoDecision = options?.autoDecision;
  }

  async requestApproval(challenge: ApprovalChallenge): Promise<ApprovalResponse> {
    console.log('\n╔══════════════════════════════════════════════════╗');
    console.log('║  🔐 SENTINEL STEP-UP APPROVAL REQUIRED          ║');
    console.log('╠══════════════════════════════════════════════════╣');
    console.log(`║  Action:  ${challenge.action}`);
    console.log(`║  Agent:   ${challenge.agentDid.slice(0, 40)}...`);
    console.log(`║  Desc:    ${challenge.actionDescription}`);
    console.log(`║  Scopes:  ${challenge.scope.join(', ')}`);
    console.log(`║  Expires: ${challenge.expiresAt}`);
    console.log('╚══════════════════════════════════════════════════╝');

    if (this.autoDecision) {
      console.log(`  → Auto-${this.autoDecision} (test mode)`);
      return {
        challengeId: challenge.challengeId,
        decision: this.autoDecision,
        decidedBy: 'console-auto',
        decidedAt: new Date().toISOString(),
        channel: 'console',
      };
    }

    // Use readline for interactive prompt
    const { createInterface } = await import('node:readline');
    const rl = createInterface({ input: process.stdin, output: process.stdout });

    return new Promise((resolve) => {
      rl.question('  Approve? (y/n): ', (answer) => {
        rl.close();
        const decision = answer.toLowerCase().startsWith('y') ? 'approved' : 'denied';
        resolve({
          challengeId: challenge.challengeId,
          decision,
          decidedBy: 'console-user',
          decidedAt: new Date().toISOString(),
          channel: 'console',
        });
      });
    });
  }
}

// ─── Approval Router ─────────────────────────────────────────────────

export interface ApprovalRouterConfig {
  /** Send to all channels simultaneously (default: false — uses first channel) */
  fanOut?: boolean;
  /** Default timeout if challenge doesn't have expiresAt */
  defaultTimeoutMs?: number;
}

export class ApprovalRouter {
  private channels: ApprovalChannel[] = [];
  private config: Required<ApprovalRouterConfig>;

  constructor(config?: ApprovalRouterConfig) {
    this.config = {
      fanOut: config?.fanOut ?? false,
      defaultTimeoutMs: config?.defaultTimeoutMs ?? 300_000,
    };
  }

  addChannel(channel: ApprovalChannel): void {
    this.channels.push(channel);
  }

  async requestApproval(challenge: ApprovalChallenge): Promise<ApprovalResponse> {
    if (this.channels.length === 0) {
      throw new Error('No approval channels configured');
    }

    if (this.config.fanOut) {
      // Race: first channel to respond wins
      return Promise.race(
        this.channels.map(ch => ch.requestApproval(challenge))
      );
    }

    // Sequential: try first channel
    return this.channels[0].requestApproval(challenge);
  }

  async close(): Promise<void> {
    for (const ch of this.channels) {
      await ch.close?.();
    }
  }
}
