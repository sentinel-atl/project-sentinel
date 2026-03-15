# @sentinel-atl/adapters

Framework adapters for LangChain, CrewAI, AutoGen, and OpenAI Agents SDK — integrate Sentinel trust in any AI agent framework.

## Features

- **LangChain** — `langchainToolWrapper()` wraps any LangChain tool with trust verification
- **CrewAI** — `crewaiTaskGuard()` guards CrewAI task execution
- **AutoGen** — `createAutoGenMessageFilter()` filters multi-agent messages
- **OpenAI Agents SDK** — `openaiAgentGuardrail()` adds function-level guardrails
- **Universal** — `withTrust()` wraps any async function with trust checks
- **Zero dependencies** — no framework SDKs required

## Install

```bash
npm install @sentinel-atl/adapters
```

## Quick Start

```ts
import { withTrust, StubTrustVerifier } from '@sentinel-atl/adapters';

const verifier = new StubTrustVerifier({ allowed: true });

const protectedFn = withTrust(verifier, {
  fn: async (input: string) => `Result: ${input}`,
  agentDid: 'did:key:z6Mk...',
  toolName: 'my-tool',
});

const result = await protectedFn('hello');
console.log(result); // "Result: hello"
```

### LangChain

```ts
import { langchainToolWrapper } from '@sentinel-atl/adapters';

const wrapped = langchainToolWrapper(verifier, {
  name: 'search',
  description: 'Search the web',
  fn: async (query) => searchWeb(query),
  agentDid: 'did:key:z6Mk...',
});

const result = await wrapped.fn('AI safety');
```

### OpenAI Agents SDK

```ts
import { openaiAgentGuardrail } from '@sentinel-atl/adapters';

const guardrail = openaiAgentGuardrail(verifier, {
  agentDid: 'did:key:z6Mk...',
  toolName: 'code_exec',
  fn: async (code: string) => eval(code),
});
```

## API

| Export | Description |
|---|---|
| `withTrust(verifier, config)` | Universal trust wrapper for any async function |
| `langchainToolWrapper(verifier, config)` | LangChain tool wrapper |
| `crewaiTaskGuard(verifier, config)` | CrewAI task guard |
| `createAutoGenMessageFilter(config)` | AutoGen message filter |
| `openaiAgentGuardrail(verifier, config)` | OpenAI Agents SDK guardrail |
| `StubTrustVerifier` | Test stub for `TrustVerifier` interface |
| `TrustVerifier` | Interface for trust verification |

## License

MIT
