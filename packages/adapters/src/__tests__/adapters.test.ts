import { describe, it, expect, beforeEach } from 'vitest';
import {
  StubTrustVerifier,
  langchainToolWrapper,
  crewaiTaskGuard,
  createAutoGenMessageFilter,
  openaiAgentGuardrail,
  withTrust,
  type TrustVerifier,
  type TrustContext,
  type TrustVerifyResult,
} from '../index.js';

describe('@sentinel/adapters', () => {
  let verifier: StubTrustVerifier;

  beforeEach(() => {
    verifier = new StubTrustVerifier();
  });

  // ─── StubTrustVerifier ─────────────────────────────────────────

  describe('StubTrustVerifier', () => {
    it('allows requests with a valid callerDid', async () => {
      const result = await verifier.verify({ callerDid: 'did:key:z6MkAgent' }, 'test');
      expect(result.allowed).toBe(true);
      expect(result.checks.identity).toBe(true);
    });

    it('denies requests with empty callerDid', async () => {
      const result = await verifier.verify({ callerDid: '' }, 'test');
      expect(result.allowed).toBe(false);
    });

    it('records outcomes', () => {
      verifier.recordOutcome({ callerDid: 'did:key:z6MkAgent' }, 'test', true);
      verifier.recordOutcome({ callerDid: 'did:key:z6MkAgent' }, 'test', false);
      expect(verifier.getOutcomes()).toHaveLength(2);
    });
  });

  // ─── LangChain Adapter ────────────────────────────────────────

  describe('LangChain adapter', () => {
    it('wraps a tool function with trust verification', async () => {
      const wrapped = langchainToolWrapper(verifier, {
        name: 'search_flights',
        requiredScopes: ['flight:search'],
        func: async (input: { dest: string }) => ({ flights: [`To ${input.dest}`] }),
        extractContext: () => ({ callerDid: 'did:key:z6MkTravelBot' }),
      });

      const result = await wrapped.func({ dest: 'Tokyo' });
      expect(result).toEqual({ flights: ['To Tokyo'] });
      expect(verifier.getOutcomes()[0].success).toBe(true);
    });

    it('blocks untrusted callers', async () => {
      const wrapped = langchainToolWrapper(verifier, {
        name: 'search_flights',
        func: async () => ({ flights: [] }),
        extractContext: () => ({ callerDid: '' }), // Empty DID = not trusted
      });

      const result = await wrapped.func({});
      expect(result).toHaveProperty('error');
    });

    it('preserves tool name and description', () => {
      const wrapped = langchainToolWrapper(verifier, {
        name: 'my_tool',
        description: 'A test tool',
        func: async () => 42,
      });
      expect(wrapped.name).toBe('my_tool');
      expect(wrapped.description).toBe('A test tool');
    });
  });

  // ─── CrewAI Adapter ───────────────────────────────────────────

  describe('CrewAI adapter', () => {
    it('guards a task execution', async () => {
      const guarded = crewaiTaskGuard(verifier, {
        taskName: 'research_market',
        agentDid: 'did:key:z6MkResearcher',
        execute: async (input: { topic: string }) => ({ report: `Report on ${input.topic}` }),
      });

      const result = await guarded.execute({ topic: 'AI trust' });
      expect(result).toEqual({ report: 'Report on AI trust' });
    });

    it('denies tasks from untrusted agents', async () => {
      // Use a custom verifier that always denies
      const denyVerifier: TrustVerifier = {
        verify: async () => ({
          allowed: false,
          reason: 'Not authorized',
          context: { callerDid: '' },
          timestamp: new Date().toISOString(),
          checks: { identity: false, credentials: false, reputation: false, intent: false, scope: false },
        }),
        recordOutcome: () => {},
      };

      const guarded = crewaiTaskGuard(denyVerifier, {
        taskName: 'research_market',
        agentDid: 'did:key:z6MkRogue',
        execute: async () => ({ report: 'Should not run' }),
      });

      const result = await guarded.execute({});
      expect(result).toHaveProperty('trustDenied', true);
    });
  });

  // ─── AutoGen Adapter ──────────────────────────────────────────

  describe('AutoGen adapter', () => {
    it('allows messages from trusted agents', async () => {
      const filter = createAutoGenMessageFilter(verifier);
      const result = await filter.onMessage({
        senderDid: 'did:key:z6MkSender',
        recipientDid: 'did:key:z6MkRecipient',
        content: 'Hello!',
        type: 'text',
      });
      expect(result.allowed).toBe(true);
      expect(result.blocked).toBe(false);
    });

    it('blocks messages with untrusted senders', async () => {
      const filter = createAutoGenMessageFilter(verifier);
      const result = await filter.onMessage({
        senderDid: '', // No DID
        recipientDid: 'did:key:z6MkRecipient',
        content: 'Hello!',
        type: 'text',
      });
      expect(result.blocked).toBe(true);
    });

    it('checks tool calls in messages against scopes', async () => {
      const denyVerifier: TrustVerifier = {
        verify: async (_ctx, action) => ({
          allowed: action !== 'dangerous_tool',
          reason: action === 'dangerous_tool' ? 'Scope denied' : undefined,
          context: _ctx,
          timestamp: new Date().toISOString(),
          checks: { identity: true, credentials: true, reputation: true, intent: true, scope: action !== 'dangerous_tool' },
        }),
        recordOutcome: () => {},
      };

      const filter = createAutoGenMessageFilter(denyVerifier, {
        sensitiveTools: ['dangerous_tool'],
      });

      const result = await filter.onMessage({
        senderDid: 'did:key:z6MkSender',
        recipientDid: 'did:key:z6MkRecipient',
        content: 'Use tool',
        type: 'function_call',
        toolCalls: [{ name: 'dangerous_tool', args: {} }],
      });

      expect(result.blocked).toBe(true);
      expect(result.reason).toContain('dangerous_tool');
    });

    it('passes through messages without tool calls', async () => {
      const filter = createAutoGenMessageFilter(verifier, {
        sensitiveTools: ['admin_tool'],
      });

      const result = await filter.onMessage({
        senderDid: 'did:key:z6MkSender',
        recipientDid: 'did:key:z6MkRecipient',
        content: 'Just chatting',
        type: 'text',
      });

      expect(result.allowed).toBe(true);
    });
  });

  // ─── OpenAI Agents SDK Adapter ────────────────────────────────

  describe('OpenAI Agents SDK adapter', () => {
    it('wraps a function tool with Sentinel guardrail', async () => {
      const guarded = openaiAgentGuardrail(verifier, {
        toolName: 'get_weather',
        callerDid: 'did:key:z6MkWeatherBot',
        handler: async (args: { city: string }) => ({ temp: 72, city: args.city }),
      });

      const result = await guarded.handler({ city: 'Tokyo' });
      expect(result).toEqual({ temp: 72, city: 'Tokyo' });
    });

    it('blocks unauthorized calls with sentinel_blocked flag', async () => {
      const denyVerifier: TrustVerifier = {
        verify: async () => ({
          allowed: false,
          reason: 'No authorization',
          context: { callerDid: '' },
          timestamp: new Date().toISOString(),
          checks: { identity: false, credentials: false, reputation: false, intent: false, scope: false },
        }),
        recordOutcome: () => {},
      };

      const guarded = openaiAgentGuardrail(denyVerifier, {
        toolName: 'get_weather',
        callerDid: 'did:key:z6MkRogue',
        handler: async () => ({ temp: 72 }),
      });

      const result = await guarded.handler({});
      expect(result).toHaveProperty('sentinel_blocked', true);
    });
  });

  // ─── Universal withTrust ──────────────────────────────────────

  describe('withTrust universal wrapper', () => {
    it('wraps any async function with trust', async () => {
      const riskyFn = async (amount: number, currency: string) =>
        `Processed ${amount} ${currency}`;

      const trusted = withTrust(verifier, {
        name: 'process_payment',
        callerDid: 'did:key:z6MkPaymentBot',
        scopes: ['payment:process'],
        fn: riskyFn,
      });

      const result = await trusted(500, 'USD');
      expect(result).toBe('Processed 500 USD');
    });

    it('throws on untrusted calls', async () => {
      const trusted = withTrust(verifier, {
        name: 'delete_account',
        callerDid: '', // Empty = not trusted by stub
        fn: async () => 'deleted',
      });

      await expect(trusted()).rejects.toThrow('Sentinel trust check failed');
    });

    it('records failures when the wrapped function throws', async () => {
      const trusted = withTrust(verifier, {
        name: 'flaky_fn',
        callerDid: 'did:key:z6MkAgent',
        fn: async () => { throw new Error('boom'); },
      });

      await expect(trusted()).rejects.toThrow('boom');
      expect(verifier.getOutcomes()[0].success).toBe(false);
    });
  });
});
