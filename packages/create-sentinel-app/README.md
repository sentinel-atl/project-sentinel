# create-sentinel-app

Scaffold a Sentinel-powered AI agent app in seconds.

## Usage

```bash
npx create-sentinel-app my-agent
```

## Templates

### `quickstart` (default)
Minimal trusted agent with identity, credentials, and content safety.

```bash
npx create-sentinel-app my-agent
```

### `mcp-secure-server`
MCP server with Sentinel security gateway — every tool call is authenticated and audited.

```bash
npx create-sentinel-app my-server --template mcp-secure-server
```

### `two-agent-handshake`
Two agents performing zero-trust mutual verification.

```bash
npx create-sentinel-app handshake-demo --template two-agent-handshake
```

## What You Get

```
my-agent/
├── src/index.ts     # Working demo — run it immediately
├── package.json     # Dependencies pre-configured
├── tsconfig.json    # TypeScript ready
└── README.md        # Explains what the app does
```

Run `npm start` and see trust in action.
