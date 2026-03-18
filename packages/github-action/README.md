# Sentinel MCP Trust Scanner — GitHub Action

Scan MCP server packages for security vulnerabilities in your CI pipeline.

## Usage

```yaml
# .github/workflows/trust-scan.yml
name: MCP Trust Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan MCP Server
        uses: sentinel-atl/project-sentinel/packages/github-action@main
        id: trust
        with:
          package: my-mcp-server
          min-score: 70
          min-grade: C

      - name: Use results
        run: |
          echo "Score: ${{ steps.trust.outputs.score }}"
          echo "Grade: ${{ steps.trust.outputs.grade }}"
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `package` | Yes | — | Package name to scan |
| `min-score` | No | `0` | Minimum trust score (0-100). Fails if below |
| `min-grade` | No | `F` | Minimum grade (A-F). Fails if below |
| `node-version` | No | `20` | Node.js version |

## Outputs

| Output | Description |
|--------|-------------|
| `score` | Trust score (0-100) |
| `grade` | Trust grade (A-F) |
| `report` | Path to full JSON report |

## What It Checks

- **Dependency vulnerabilities** — npm audit integration
- **Dangerous code patterns** — eval, child_process, obfuscation, data exfiltration
- **Permission analysis** — filesystem, network, process, native modules
- **Publisher identity** — npm registry age, downloads, maintainers

## Example: Fail PR if Trust Score Drops

```yaml
- name: Scan
  uses: sentinel-atl/project-sentinel/packages/github-action@main
  with:
    package: my-mcp-server
    min-score: 75
    min-grade: B
```

If the score drops below 75 or grade below B, the workflow fails and blocks the PR.
