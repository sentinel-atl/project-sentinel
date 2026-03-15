import { describe, it, expect, afterEach } from 'vitest';
import {
  DashboardServer,
  buildDashboardData,
  type DashboardData,
  type TrustGraphNode,
  type TrustGraphEdge,
} from '../index.js';

describe('@sentinel-atl/dashboard', () => {
  let server: DashboardServer | null = null;

  afterEach(async () => {
    if (server) {
      await server.stop();
      server = null;
    }
  });

  const mockNodes: TrustGraphNode[] = [
    { did: 'did:key:z6MkPrincipal', label: 'Human', type: 'principal' },
    { did: 'did:key:z6MkAgentA', label: 'TravelBot', type: 'agent', reputation: {
      did: 'did:key:z6MkAgentA', score: 72, totalVouches: 5, positiveVouches: 4,
      negativeVouches: 1, isQuarantined: false, lastUpdated: new Date().toISOString(), source: 'live',
    }},
    { did: 'did:key:z6MkAgentB', label: 'PayBot', type: 'sub-agent', revoked: true },
  ];

  const mockEdges: TrustGraphEdge[] = [
    { from: 'did:key:z6MkPrincipal', to: 'did:key:z6MkAgentA', type: 'authorization', scope: ['travel:search'] },
    { from: 'did:key:z6MkAgentA', to: 'did:key:z6MkAgentB', type: 'delegation', scope: ['payment:process'] },
    { from: 'did:key:z6MkAgentA', to: 'did:key:z6MkAgentB', type: 'handshake' },
  ];

  const mockData: DashboardData = {
    nodes: mockNodes,
    edges: mockEdges,
    auditEntries: [
      { timestamp: new Date().toISOString(), eventType: 'identity_created', actorDid: 'did:key:z6MkPrincipal', result: 'success' },
      { timestamp: new Date().toISOString(), eventType: 'vc_issued', actorDid: 'did:key:z6MkPrincipal', targetDid: 'did:key:z6MkAgentA', result: 'success' },
      { timestamp: new Date().toISOString(), eventType: 'handshake_complete', actorDid: 'did:key:z6MkAgentA', targetDid: 'did:key:z6MkAgentB', result: 'success' },
    ],
    revocationStats: { revokedVCs: 1, revokedDIDs: 1, killEvents: 1 },
    offlineStats: { vcCacheSize: 2, reputationCacheSize: 3, pendingTransactions: 0, crdtEntries: 1, isOnline: true },
  };

  // ─── Server ────────────────────────────────────────────────────

  describe('DashboardServer', () => {
    it('starts and serves HTML on /', async () => {
      server = new DashboardServer({
        port: 0, // Let OS pick a port — we'll use a fixed port
        getData: () => mockData,
      });

      // Use a specific high port to avoid conflicts
      server = new DashboardServer({
        port: 19876,
        host: '127.0.0.1',
        getData: () => mockData,
      });
      const { url } = await server.start();
      expect(url).toContain('19876');

      const res = await fetch(url);
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toContain('<!DOCTYPE html>');
      expect(html).toContain('Sentinel Trust Dashboard');
      expect(html).toContain('Trust Graph');
    });

    it('serves JSON data on /api/data', async () => {
      server = new DashboardServer({
        port: 19877,
        host: '127.0.0.1',
        getData: () => mockData,
      });
      const { url } = await server.start();

      const res = await fetch(`${url}/api/data`);
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.nodes).toHaveLength(3);
      expect(json.edges).toHaveLength(3);
      expect(json.auditEntries).toHaveLength(3);
      expect(json.revocationStats.killEvents).toBe(1);
    });

    it('accepts custom title', async () => {
      server = new DashboardServer({
        port: 19878,
        host: '127.0.0.1',
        title: 'My Agent Trust View',
        getData: () => mockData,
      });
      const { url } = await server.start();

      const html = await (await fetch(url)).text();
      expect(html).toContain('My Agent Trust View');
    });

    it('stops cleanly', async () => {
      server = new DashboardServer({
        port: 19879,
        host: '127.0.0.1',
        getData: () => mockData,
      });
      await server.start();
      await server.stop();
      server = null;
      // Should not throw
    });

    it('handles async getData', async () => {
      server = new DashboardServer({
        port: 19880,
        host: '127.0.0.1',
        getData: async () => {
          await new Promise(r => setTimeout(r, 10));
          return mockData;
        },
      });
      const { url } = await server.start();

      const res = await fetch(`${url}/api/data`);
      const json = await res.json();
      expect(json.nodes).toHaveLength(3);
    });
  });

  // ─── buildDashboardData ────────────────────────────────────────

  describe('buildDashboardData', () => {
    it('builds data from components', async () => {
      const data = await buildDashboardData({
        nodes: mockNodes,
        edges: mockEdges,
      });
      expect(data.nodes).toHaveLength(3);
      expect(data.edges).toHaveLength(3);
      expect(data.revocationStats.revokedVCs).toBe(0);
      expect(data.offlineStats).toBeUndefined();
    });

    it('includes audit entries when auditLog is provided', async () => {
      // Mock audit log with readAll method
      const mockAuditLog = {
        readAll: async () => [
          { timestamp: '2026-01-01T00:00:00Z', eventType: 'identity_created', actorDid: 'did:key:z6Mk1', result: 'success' },
        ],
      } as any;

      const data = await buildDashboardData({
        nodes: [],
        edges: [],
        auditLog: mockAuditLog,
      });
      expect(data.auditEntries).toHaveLength(1);
      expect(data.auditEntries[0].eventType).toBe('identity_created');
    });

    it('includes revocation stats when revocationManager is provided', async () => {
      const mockRevMgr = {
        getStats: () => ({ revokedVCs: 3, revokedDIDs: 1, killEvents: 2 }),
      } as any;

      const data = await buildDashboardData({
        nodes: [],
        edges: [],
        revocationManager: mockRevMgr,
      });
      expect(data.revocationStats.revokedVCs).toBe(3);
      expect(data.revocationStats.killEvents).toBe(2);
    });

    it('includes offline stats when offlineManager is provided', async () => {
      const mockOfflineMgr = {
        getStats: () => ({
          vcCacheSize: 5,
          reputationCacheSize: 10,
          revocationCacheSize: 2,
          pendingTransactions: 1,
          crdtEntries: 3,
          isOnline: false,
        }),
      } as any;

      const data = await buildDashboardData({
        nodes: [],
        edges: [],
        offlineManager: mockOfflineMgr,
      });
      expect(data.offlineStats).toBeDefined();
      expect(data.offlineStats!.isOnline).toBe(false);
      expect(data.offlineStats!.pendingTransactions).toBe(1);
    });
  });
});
