# Sentinel MCP Trust Scanner — VS Code Extension

Scan MCP server packages for security vulnerabilities directly in VS Code.

## Features

- **Scan any npm package** — `Cmd+Shift+P` → "Sentinel: Scan MCP Package"
- **Scan current workspace** — `Cmd+Shift+P` → "Sentinel: Scan Current Workspace"
- **Validate gateway config** — `Cmd+Shift+P` → "Sentinel: Validate Gateway Config"

## Commands

| Command | Description |
|---------|-------------|
| `Sentinel: Scan MCP Package` | Enter a package name, get a trust score |
| `Sentinel: Scan Current Workspace` | Scan the package in your open workspace |
| `Sentinel: Validate Gateway Config` | Check your sentinel.yaml for issues |

## How It Works

The extension uses `@sentinel-atl/scanner` to analyze packages for:

- Dependency vulnerabilities (npm audit)
- Dangerous code patterns (eval, child_process, obfuscation)
- Permission analysis (filesystem, network, native)
- Publisher identity (npm registry checks)

Results appear as a VS Code notification with the trust score and grade. Click "View Full Report" to see the complete JSON analysis.

## Install

Search for "Sentinel MCP Trust Scanner" in the VS Code Extensions marketplace.

Or install from the command line:
```bash
code --install-extension sentinel-atl.sentinel-trust-scanner
```
