# @sentinel/dashboard

Web dashboard for visualizing trust graphs, reputation scores, delegation chains, and audit logs.

## Features

- **Trust graph** — interactive SVG visualization of agent nodes and trust edges
- **Reputation cards** — color-coded score bars per agent
- **Audit trail** — real-time table of last 20 events
- **Revocation stats** — revoked VCs, DIDs, and kill events
- **Offline indicator** — shows connectivity status
- **Zero dependencies** — embedded HTML/CSS/JS, dark theme, auto-refresh every 5s

## Install

```bash
npm install @sentinel/dashboard
```

## Quick Start

```ts
import { createDashboard, buildDashboardData } from '@sentinel/dashboard';

const server = await createDashboard({
  port: 3000,
  title: 'My Trust Dashboard',
  getData: async () => buildDashboardData({
    nodes: [{ id: 'did:key:z6Mk...', label: 'Agent A', type: 'agent' }],
    edges: [{ from: 'did:key:z6MkA...', to: 'did:key:z6MkB...', label: 'trusts', weight: 0.9 }],
    auditLog,
    revocationManager,
    offlineManager,
  }),
});

const { url } = await server.start();
console.log(`Dashboard: ${url}`);
```

## API

| Export | Description |
|---|---|
| `createDashboard(config)` | Factory — creates a `DashboardServer` |
| `DashboardServer` | HTTP server serving the dashboard UI |
| `buildDashboardData(options)` | Build dashboard data from Sentinel components |

## License

MIT
