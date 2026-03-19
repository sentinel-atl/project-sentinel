/**
 * @sentinel-atl/dashboard — Trust Visualization Dashboard
 *
 * A lightweight, zero-dependency web dashboard for visualizing:
 *
 * 1. **Trust Graph** — Agent DIDs as nodes, handshakes/delegations as edges
 * 2. **Reputation Scores** — Real-time score cards with vouch history
 * 3. **Delegation Chains** — Tree view of scope narrowing through delegation
 * 4. **Audit Trail** — Searchable, filterable event log with hash-chain status
 * 5. **Revocation Status** — Live view of revoked VCs/DIDs and kill events
 * 6. **Offline Status** — Cache stats, pending transactions, CRDT state
 *
 * The dashboard serves a single HTML page with embedded CSS/JS.
 * No build step, no bundler, no React — just Node.js HTTP.
 *
 * Blueprint ref: Phase 3, Milestone 3c (Dashboard)
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { ReputationScore } from '@sentinel-atl/reputation';
import type { AuditLog } from '@sentinel-atl/audit';
import type { RevocationManager } from '@sentinel-atl/revocation';
import type { OfflineManager } from '@sentinel-atl/offline';

// ─── Data Sources ────────────────────────────────────────────────────

export interface TrustGraphNode {
  did: string;
  label: string;
  type: 'principal' | 'agent' | 'sub-agent';
  reputation?: ReputationScore;
  revoked?: boolean;
}

export interface TrustGraphEdge {
  from: string;
  to: string;
  type: 'authorization' | 'delegation' | 'handshake' | 'vouch';
  label?: string;
  scope?: string[];
}

export interface DashboardData {
  nodes: TrustGraphNode[];
  edges: TrustGraphEdge[];
  auditEntries: AuditEntry[];
  revocationStats: { revokedVCs: number; revokedDIDs: number; killEvents: number };
  offlineStats?: { vcCacheSize: number; reputationCacheSize: number; pendingTransactions: number; crdtEntries: number; isOnline: boolean };
}

export interface AuditEntry {
  timestamp: string;
  eventType: string;
  actorDid: string;
  targetDid?: string;
  result: string;
  reason?: string;
  metadata?: Record<string, unknown>;
  prevHash?: string;
}

export interface DashboardConfig {
  /** Port to serve on (default: 3000) */
  port?: number;
  /** Host to bind to (default: localhost) */
  host?: string;
  /** Dashboard title */
  title?: string;
  /** Data source — call this to get fresh data */
  getData: () => Promise<DashboardData> | DashboardData;
  /** Optional: Bearer token for dashboard access (if set, /api/* requires Authorization header) */
  authToken?: string;
  /** Refresh interval in ms for SSE push (default: 5000) */
  refreshIntervalMs?: number;
}

// ─── Dashboard Server ────────────────────────────────────────────────

export class DashboardServer {
  private config: Required<Pick<DashboardConfig, 'port' | 'host' | 'title' | 'refreshIntervalMs'>> & DashboardConfig;
  private server: ReturnType<typeof createServer> | null = null;
  private sseClients = new Set<ServerResponse>();
  private refreshTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config: DashboardConfig) {
    this.config = {
      port: 3000,
      host: 'localhost',
      title: 'Sentinel Trust Dashboard',
      refreshIntervalMs: 5000,
      ...config,
    };
  }

  /**
   * Start the dashboard server.
   */
  async start(): Promise<{ url: string }> {
    return new Promise((resolve) => {
      this.server = createServer(async (req, res) => {
        await this.handleRequest(req, res);
      });

      this.server.listen(this.config.port, this.config.host, () => {
        const url = `http://${this.config.host}:${this.config.port}`;
        // Start SSE push timer
        this.refreshTimer = setInterval(() => this.pushToSSEClients(), this.config.refreshIntervalMs);
        resolve({ url });
      });
    });
  }

  /**
   * Stop the dashboard server.
   */
  async stop(): Promise<void> {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = null;
    }
    for (const client of this.sseClients) {
      client.end();
    }
    this.sseClients.clear();
    return new Promise((resolve, reject) => {
      if (!this.server) return resolve();
      this.server.close((err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  private async pushToSSEClients(): Promise<void> {
    if (this.sseClients.size === 0) return;
    try {
      const data = await this.config.getData();
      const payload = `data: ${JSON.stringify(data)}\n\n`;
      for (const client of this.sseClients) {
        client.write(payload);
      }
    } catch { /* ignore push errors */ }
  }

  private checkAuth(req: IncomingMessage, res: ServerResponse): boolean {
    if (!this.config.authToken) return true;
    const auth = req.headers.authorization;
    if (auth === `Bearer ${this.config.authToken}`) return true;
    // Also check query param for SSE connections
    const url = new URL(req.url ?? '/', `http://localhost:${this.config.port}`);
    if (url.searchParams.get('token') === this.config.authToken) return true;
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Unauthorized' }));
    return false;
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = req.url ?? '/';
    const pathname = new URL(url, `http://localhost:${this.config.port}`).pathname;

    if (pathname === '/api/data') {
      if (!this.checkAuth(req, res)) return;
      try {
        const data = await this.config.getData();
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Cache-Control': 'no-cache',
        });
        res.end(JSON.stringify(data));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Failed to load data' }));
      }
      return;
    }

    if (pathname === '/api/events') {
      if (!this.checkAuth(req, res)) return;
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
      });
      res.write(':\n\n'); // initial comment to flush headers
      this.sseClients.add(res);
      req.on('close', () => this.sseClients.delete(res));
      return;
    }

    // Serve the dashboard HTML
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache',
    });
    res.end(this.renderHTML());
  }

  private renderHTML(): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(this.config.title)}</title>
<style>
:root {
  --bg: #0d1117; --surface: #161b22; --border: #30363d;
  --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff;
  --green: #3fb950; --red: #f85149; --yellow: #d29922; --purple: #bc8cff;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
  background: var(--bg); color: var(--text); line-height: 1.5; }
.header { background: var(--surface); border-bottom: 1px solid var(--border);
  padding: 16px 24px; display: flex; align-items: center; gap: 12px; }
.header h1 { font-size: 20px; font-weight: 600; }
.header .shield { font-size: 24px; }
.header .status { margin-left: auto; font-size: 13px; padding: 4px 12px;
  border-radius: 12px; font-weight: 500; }
.header .status.online { background: #0d1f0d; color: var(--green); }
.header .status.offline { background: #2d1515; color: var(--red); }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px;
  padding: 24px; max-width: 1400px; margin: 0 auto; }
.card { background: var(--surface); border: 1px solid var(--border);
  border-radius: 8px; padding: 16px; }
.card h2 { font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px;
  color: var(--muted); margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }
.card.full { grid-column: 1 / -1; }
.node { display: inline-flex; align-items: center; gap: 6px; padding: 6px 12px;
  background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
  margin: 4px; font-size: 13px; }
.node .icon { font-size: 16px; }
.node .did { font-family: monospace; font-size: 11px; color: var(--muted); }
.node.revoked { border-color: var(--red); opacity: 0.6; text-decoration: line-through; }
.edge { font-size: 12px; color: var(--muted); padding: 4px 0; border-bottom: 1px solid var(--border); }
.edge .type { font-weight: 600; color: var(--accent); }
.score-card { display: flex; align-items: center; gap: 12px; padding: 8px 12px;
  background: var(--bg); border-radius: 6px; margin-bottom: 8px; }
.score-bar { flex: 1; height: 8px; background: var(--border); border-radius: 4px; overflow: hidden; }
.score-bar .fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
.score-val { font-weight: 700; font-size: 18px; min-width: 40px; text-align: right; }
.audit-row { font-size: 12px; padding: 6px 0; border-bottom: 1px solid var(--border);
  display: grid; grid-template-columns: 140px 160px 1fr 80px; gap: 8px; align-items: center; }
.audit-row .ts { color: var(--muted); font-family: monospace; font-size: 11px; }
.audit-row .event { font-weight: 600; }
.audit-row .result.success { color: var(--green); }
.audit-row .result.failure { color: var(--red); }
.stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; }
.stat { background: var(--bg); border-radius: 6px; padding: 12px; text-align: center; }
.stat .value { font-size: 28px; font-weight: 700; }
.stat .label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }
.stat.danger .value { color: var(--red); }
.stat.warn .value { color: var(--yellow); }
.stat.good .value { color: var(--green); }
.graph-canvas { width: 100%; height: 300px; position: relative; }
.graph-node { position: absolute; padding: 8px 12px; background: var(--bg);
  border: 2px solid var(--accent); border-radius: 8px; font-size: 12px;
  cursor: default; text-align: center; z-index: 2; }
.graph-node.principal { border-color: var(--purple); }
.graph-node.revoked { border-color: var(--red); opacity: 0.5; }
svg.graph-edges { position: absolute; top: 0; left: 0; width: 100%; height: 100%; z-index: 1; }
svg.graph-edges line { stroke: var(--border); stroke-width: 2; }
svg.graph-edges line.auth { stroke: var(--purple); }
svg.graph-edges line.delegation { stroke: var(--accent); }
svg.graph-edges line.handshake { stroke: var(--green); }
svg.graph-edges line.vouch { stroke: var(--yellow); stroke-dasharray: 4; }
.empty { color: var(--muted); font-style: italic; font-size: 13px; padding: 12px; }
.refresh-btn { background: var(--accent); color: #fff; border: none; padding: 6px 16px;
  border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 600; }
.refresh-btn:hover { opacity: 0.9; }
@media (max-width: 768px) { .grid { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<div class="header">
  <span class="shield">🛡️</span>
  <h1>${escapeHtml(this.config.title)}</h1>
  <span id="status" class="status online">● Online</span>
  <button class="refresh-btn" onclick="loadData()">↻ Refresh</button>
</div>
<div class="grid" id="grid">
  <div class="card"><h2>Loading...</h2></div>
</div>
<script>
let data = null;

async function loadData() {
  try {
    const res = await fetch('/api/data');
    data = await res.json();
    render();
  } catch(e) {
    document.getElementById('grid').innerHTML = '<div class="card full"><h2>⚠ Error loading data</h2></div>';
  }
}

function did(d) { return d ? d.slice(0, 20) + '...' : '—'; }
function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function scoreColor(s) {
  if (s >= 70) return 'var(--green)';
  if (s >= 40) return 'var(--yellow)';
  return 'var(--red)';
}

function render() {
  if (!data) return;
  const g = document.getElementById('grid');
  const online = data.offlineStats ? data.offlineStats.isOnline : true;
  document.getElementById('status').className = 'status ' + (online ? 'online' : 'offline');
  document.getElementById('status').textContent = online ? '● Online' : '● Offline';

  g.innerHTML = renderStats() + renderGraph() + renderReputation() + renderAudit() + renderRevocation();
}

function renderStats() {
  const n = data.nodes.length;
  const e = data.edges.length;
  const a = data.auditEntries.length;
  const rv = data.revocationStats;
  const off = data.offlineStats;
  return '<div class="card full"><h2>📊 Overview</h2><div class="stat-grid">'
    + stat(n, 'Agents', 'good') + stat(e, 'Connections', 'good')
    + stat(a, 'Audit Events', '') + stat(rv.revokedVCs, 'Revoked VCs', rv.revokedVCs > 0 ? 'danger' : '')
    + stat(rv.revokedDIDs, 'Revoked DIDs', rv.revokedDIDs > 0 ? 'danger' : '')
    + stat(rv.killEvents, 'Kill Events', rv.killEvents > 0 ? 'danger' : '')
    + (off ? stat(off.pendingTransactions, 'Pending Tx', off.pendingTransactions > 0 ? 'warn' : '')
           + stat(off.crdtEntries, 'CRDT Entries', '') : '')
    + '</div></div>';
}

function stat(v, l, cls) {
  return '<div class="stat ' + cls + '"><div class="value">' + v + '</div><div class="label">' + l + '</div></div>';
}

function renderGraph() {
  if (data.nodes.length === 0) return '<div class="card"><h2>🔗 Trust Graph</h2><p class="empty">No agents</p></div>';
  const W = 600, H = 300;
  const cx = W/2, cy = H/2;
  const positions = {};
  data.nodes.forEach(function(n, i) {
    const angle = (2 * Math.PI * i) / data.nodes.length - Math.PI/2;
    const r = Math.min(W, H) * 0.35;
    positions[n.did] = { x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle) };
  });

  let svgLines = '';
  data.edges.forEach(function(e) {
    const p1 = positions[e.from]; const p2 = positions[e.to];
    if (p1 && p2) svgLines += '<line x1="'+p1.x+'" y1="'+p1.y+'" x2="'+p2.x+'" y2="'+p2.y+'" class="'+e.type+'"/>';
  });

  let nodes = '';
  data.nodes.forEach(function(n) {
    const p = positions[n.did];
    const cls = (n.type === 'principal' ? ' principal' : '') + (n.revoked ? ' revoked' : '');
    const icon = n.type === 'principal' ? '👤' : '🤖';
    nodes += '<div class="graph-node' + cls + '" style="left:' + (p.x-40) + 'px;top:' + (p.y-20) + 'px">'
      + icon + ' ' + escHtml(n.label) + '<br><span style="font-size:10px;color:var(--muted)">' + did(n.did) + '</span></div>';
  });

  return '<div class="card"><h2>🔗 Trust Graph</h2>'
    + '<div class="graph-canvas"><svg class="graph-edges" viewBox="0 0 '+W+' '+H+'">' + svgLines + '</svg>' + nodes + '</div></div>';
}

function renderReputation() {
  const agents = data.nodes.filter(function(n) { return n.reputation; });
  if (agents.length === 0) return '<div class="card"><h2>📈 Reputation</h2><p class="empty">No reputation data</p></div>';
  let html = '<div class="card"><h2>📈 Reputation Scores</h2>';
  agents.forEach(function(n) {
    const r = n.reputation;
    const q = r.isQuarantined ? ' <span style="color:var(--red)">[QUARANTINED]</span>' : '';
    html += '<div class="score-card"><div style="min-width:120px">' + escHtml(n.label) + q + '</div>'
      + '<div class="score-bar"><div class="fill" style="width:'+r.score+'%;background:'+scoreColor(r.score)+'"></div></div>'
      + '<div class="score-val" style="color:'+scoreColor(r.score)+'">' + r.score + '</div></div>';
  });
  return html + '</div>';
}

function renderAudit() {
  const entries = data.auditEntries.slice(-20).reverse();
  if (entries.length === 0) return '<div class="card full"><h2>📋 Audit Log</h2><p class="empty">No events</p></div>';
  let html = '<div class="card full"><h2>📋 Audit Log (last 20)</h2>';
  html += '<div class="audit-row" style="font-weight:600;color:var(--muted)"><span>Timestamp</span><span>Event</span><span>Actor</span><span>Result</span></div>';
  entries.forEach(function(e) {
    const ts = e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : '—';
    html += '<div class="audit-row"><span class="ts">' + ts + '</span>'
      + '<span class="event">' + escHtml(e.eventType) + '</span>'
      + '<span style="font-family:monospace;font-size:11px">' + did(e.actorDid) + '</span>'
      + '<span class="result ' + e.result + '">' + e.result + '</span></div>';
  });
  return html + '</div>';
}

function renderRevocation() {
  const rv = data.revocationStats;
  if (rv.revokedVCs === 0 && rv.revokedDIDs === 0 && rv.killEvents === 0) {
    return '<div class="card"><h2>🚫 Revocation</h2><p class="empty">No revocations</p></div>';
  }
  return '<div class="card"><h2>🚫 Revocation Status</h2><div class="stat-grid">'
    + stat(rv.revokedVCs, 'Revoked VCs', 'danger')
    + stat(rv.revokedDIDs, 'Revoked DIDs', 'danger')
    + stat(rv.killEvents, 'Kill Events', 'danger')
    + '</div></div>';
}

loadData();
// Use SSE for real-time updates instead of polling
const evtSource = new EventSource('/api/events');
evtSource.onmessage = function(e) {
  try { data = JSON.parse(e.data); render(); } catch {}
};
evtSource.onerror = function() {
  // Fallback to polling if SSE fails
  evtSource.close();
  setInterval(loadData, 5000);
};
</script>
</body>
</html>`;
  }
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/**
 * Create and start a dashboard server.
 */
export async function createDashboard(config: DashboardConfig): Promise<DashboardServer> {
  const server = new DashboardServer(config);
  await server.start();
  return server;
}

/**
 * Helper: build DashboardData from Sentinel components.
 */
export async function buildDashboardData(options: {
  nodes: TrustGraphNode[];
  edges: TrustGraphEdge[];
  auditLog?: AuditLog;
  revocationManager?: RevocationManager;
  offlineManager?: OfflineManager;
}): Promise<DashboardData> {
  const auditEntries: AuditEntry[] = [];
  if (options.auditLog) {
    const raw = await options.auditLog.readAll();
    for (const entry of raw) {
      auditEntries.push({
        timestamp: entry.timestamp,
        eventType: entry.eventType,
        actorDid: entry.actorDid,
        targetDid: entry.targetDid,
        result: entry.result,
        reason: entry.reason,
        metadata: entry.metadata,
        prevHash: entry.prevHash,
      });
    }
  }

  const revocationStats = options.revocationManager
    ? options.revocationManager.getStats()
    : { revokedVCs: 0, revokedDIDs: 0, killEvents: 0 };

  const offlineStats = options.offlineManager
    ? options.offlineManager.getStats()
    : undefined;

  return {
    nodes: options.nodes,
    edges: options.edges,
    auditEntries,
    revocationStats,
    offlineStats,
  };
}
