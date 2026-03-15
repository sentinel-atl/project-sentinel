/**
 * @sentinel-atl/adapters — Multi-Framework AI Agent Trust Adapters
 *
 * Plug Sentinel's trust layer into any AI agent framework with
 * minimal code changes. Each adapter wraps the framework's tool/agent
 * execution boundary with Sentinel verification.
 *
 * Supported frameworks:
 * - **LangChain** — Tool wrapper + agent executor middleware
 * - **CrewAI** — Agent/Task trust decorator
 * - **AutoGen** — Message filter for multi-agent conversations
 * - **OpenAI Agents SDK** — Function tool guardrail
 *
 * These adapters are framework-agnostic wrappers. They don't depend on
 * the framework SDKs at runtime (no peer deps) — they define the shapes
 * and hooks that framework users wire in. This keeps @sentinel-atl/adapters
 * lightweight and avoids version conflicts.
 *
 * Blueprint ref: Phase 3, Milestone 3d (Multi-Framework Adapters)
 */

import type { VerifiableCredential, IntentEnvelope } from '@sentinel-atl/core';
import type { ReputationScore } from '@sentinel-atl/reputation';

// ─── Common Types ────────────────────────────────────────────────────

export interface TrustContext {
  /** Caller agent's DID */
  callerDid: string;
  /** Credentials presented */
  credentials?: VerifiableCredential[];
  /** Intent envelope for this action */
  intent?: IntentEnvelope;
  /** Caller's reputation (if available) */
  reputation?: ReputationScore;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

export interface TrustVerifyResult {
  /** Whether the action is allowed */
  allowed: boolean;
  /** Reason for denial */
  reason?: string;
  /** Trust context used for the decision */
  context: TrustContext;
  /** Timestamp of the decision */
  timestamp: string;
  /** Checks performed */
  checks: {
    identity: boolean;
    credentials: boolean;
    reputation: boolean;
    intent: boolean;
    scope: boolean;
  };
}

export interface TrustVerifier {
  /** Verify a trust context before executing an action */
  verify(context: TrustContext, action: string, scope?: string[]): Promise<TrustVerifyResult>;
  /** Record the result of an action (for reputation feedback) */
  recordOutcome(context: TrustContext, action: string, success: boolean): void;
}

// ─── Stub Trust Verifier (for testing without full Sentinel) ─────────

export class StubTrustVerifier implements TrustVerifier {
  private outcomes: Array<{ action: string; success: boolean }> = [];

  async verify(context: TrustContext, action: string): Promise<TrustVerifyResult> {
    return {
      allowed: !!context.callerDid,
      context,
      timestamp: new Date().toISOString(),
      checks: {
        identity: !!context.callerDid,
        credentials: true,
        reputation: true,
        intent: true,
        scope: true,
      },
    };
  }

  recordOutcome(_context: TrustContext, action: string, success: boolean): void {
    this.outcomes.push({ action, success });
  }

  getOutcomes() {
    return [...this.outcomes];
  }
}

// ─── LangChain Adapter ──────────────────────────────────────────────

/**
 * LangChain integration shape.
 *
 * In LangChain, tools are called via `StructuredTool.call()` or
 * `DynamicTool.func()`. This adapter wraps a tool function with
 * Sentinel trust verification.
 *
 * Usage:
 * ```ts
 * const wrappedTool = langchainToolWrapper(verifier, {
 *   name: 'search_flights',
 *   requiredScopes: ['flight:search'],
 *   func: async (input) => { ... },
 * });
 * // wrappedTool.func now checks trust before executing
 * ```
 */

export interface LangChainToolConfig<TInput = unknown, TOutput = unknown> {
  /** Tool name (for audit logging) */
  name: string;
  /** Tool description */
  description?: string;
  /** Required scopes for this tool */
  requiredScopes?: string[];
  /** The actual tool function */
  func: (input: TInput) => Promise<TOutput>;
  /** Extract trust context from the input */
  extractContext?: (input: TInput) => TrustContext;
}

export interface WrappedLangChainTool<TInput = unknown, TOutput = unknown> {
  name: string;
  description?: string;
  func: (input: TInput) => Promise<TOutput | { error: string }>;
}

/**
 * Wrap a LangChain-style tool function with Sentinel trust verification.
 */
export function langchainToolWrapper<TInput = unknown, TOutput = unknown>(
  verifier: TrustVerifier,
  config: LangChainToolConfig<TInput, TOutput>
): WrappedLangChainTool<TInput, TOutput> {
  return {
    name: config.name,
    description: config.description,
    func: async (input: TInput): Promise<TOutput | { error: string }> => {
      const context = config.extractContext
        ? config.extractContext(input)
        : { callerDid: '' };

      const result = await verifier.verify(context, config.name, config.requiredScopes);
      if (!result.allowed) {
        verifier.recordOutcome(context, config.name, false);
        return { error: `Trust check failed: ${result.reason ?? 'unauthorized'}` };
      }

      try {
        const output = await config.func(input);
        verifier.recordOutcome(context, config.name, true);
        return output;
      } catch (err) {
        verifier.recordOutcome(context, config.name, false);
        throw err;
      }
    },
  };
}

// ─── CrewAI Adapter ──────────────────────────────────────────────────

/**
 * CrewAI integration shape.
 *
 * CrewAI uses Agents executing Tasks. This adapter decorates
 * a task's execution function with trust verification.
 *
 * Usage:
 * ```ts
 * const trustedTask = crewaiTaskGuard(verifier, {
 *   taskName: 'research_market',
 *   agentDid: agent.did,
 *   execute: async (input) => { ... },
 * });
 * ```
 */

export interface CrewAITaskConfig<TInput = unknown, TOutput = unknown> {
  /** Task name */
  taskName: string;
  /** The agent DID executing this task */
  agentDid: string;
  /** Required scopes */
  requiredScopes?: string[];
  /** Credentials the agent holds */
  credentials?: VerifiableCredential[];
  /** Task execution function */
  execute: (input: TInput) => Promise<TOutput>;
}

export interface GuardedCrewAITask<TInput = unknown, TOutput = unknown> {
  taskName: string;
  agentDid: string;
  execute: (input: TInput) => Promise<TOutput | { error: string; trustDenied: true }>;
}

export function crewaiTaskGuard<TInput = unknown, TOutput = unknown>(
  verifier: TrustVerifier,
  config: CrewAITaskConfig<TInput, TOutput>
): GuardedCrewAITask<TInput, TOutput> {
  return {
    taskName: config.taskName,
    agentDid: config.agentDid,
    execute: async (input: TInput) => {
      const context: TrustContext = {
        callerDid: config.agentDid,
        credentials: config.credentials,
      };

      const result = await verifier.verify(context, config.taskName, config.requiredScopes);
      if (!result.allowed) {
        verifier.recordOutcome(context, config.taskName, false);
        return { error: `Trust denied for task ${config.taskName}: ${result.reason}`, trustDenied: true as const };
      }

      try {
        const output = await config.execute(input);
        verifier.recordOutcome(context, config.taskName, true);
        return output;
      } catch (err) {
        verifier.recordOutcome(context, config.taskName, false);
        throw err;
      }
    },
  };
}

// ─── AutoGen Adapter ─────────────────────────────────────────────────

/**
 * AutoGen integration shape.
 *
 * AutoGen uses multi-agent conversations where agents exchange messages.
 * This adapter acts as a message filter that verifies trust before
 * allowing a message through to the recipient.
 *
 * Usage:
 * ```ts
 * const filter = createAutoGenMessageFilter(verifier, {
 *   minReputation: 30,
 * });
 * const result = await filter.onMessage(message);
 * if (result.blocked) { /* handle blocked message *\/ }
 * ```
 */

export interface AutoGenMessage {
  /** Sender agent DID */
  senderDid: string;
  /** Recipient agent DID */
  recipientDid: string;
  /** Message content (opaque to this layer) */
  content: unknown;
  /** Message type */
  type: string;
  /** Sender's credentials */
  credentials?: VerifiableCredential[];
  /** Tool calls in this message (if any) */
  toolCalls?: Array<{ name: string; args: unknown }>;
}

export interface MessageFilterResult {
  /** Whether the message is allowed through */
  allowed: boolean;
  /** Whether the message was blocked */
  blocked: boolean;
  /** Reason for blocking */
  reason?: string;
  /** The original message (passed through if allowed) */
  message: AutoGenMessage;
}

export interface AutoGenMessageFilterConfig {
  /** Minimum reputation to accept messages (default: 0) */
  minReputation?: number;
  /** Tool names that require extra trust verification */
  sensitiveTools?: string[];
  /** Required scopes per tool name */
  toolScopes?: Record<string, string[]>;
}

export interface AutoGenMessageFilter {
  onMessage(message: AutoGenMessage): Promise<MessageFilterResult>;
}

export function createAutoGenMessageFilter(
  verifier: TrustVerifier,
  config?: AutoGenMessageFilterConfig
): AutoGenMessageFilter {
  const minRep = config?.minReputation ?? 0;
  const sensitiveTools = new Set(config?.sensitiveTools ?? []);

  return {
    onMessage: async (message: AutoGenMessage): Promise<MessageFilterResult> => {
      const context: TrustContext = {
        callerDid: message.senderDid,
        credentials: message.credentials,
        metadata: {
          recipientDid: message.recipientDid,
          messageType: message.type,
        },
      };

      // Check reputation threshold
      if (context.reputation && context.reputation.score < minRep) {
        return {
          allowed: false,
          blocked: true,
          reason: `Sender reputation ${context.reputation.score} below minimum ${minRep}`,
          message,
        };
      }

      // If message contains tool calls, verify each
      if (message.toolCalls && message.toolCalls.length > 0) {
        for (const call of message.toolCalls) {
          const scopes = config?.toolScopes?.[call.name];
          const isSensitive = sensitiveTools.has(call.name);

          if (isSensitive || scopes) {
            const result = await verifier.verify(context, call.name, scopes);
            if (!result.allowed) {
              return {
                allowed: false,
                blocked: true,
                reason: `Tool ${call.name} blocked: ${result.reason}`,
                message,
              };
            }
          }
        }
      }

      // Basic identity verification
      const result = await verifier.verify(context, message.type);
      return {
        allowed: result.allowed,
        blocked: !result.allowed,
        reason: result.allowed ? undefined : result.reason,
        message,
      };
    },
  };
}

// ─── OpenAI Agents SDK Adapter ───────────────────────────────────────

/**
 * OpenAI Agents SDK integration shape.
 *
 * The OpenAI Agents SDK uses function tools that agents can call.
 * This adapter wraps function tool definitions with Sentinel guardrails.
 *
 * Usage:
 * ```ts
 * const guardedTool = openaiAgentGuardrail(verifier, {
 *   toolName: 'get_weather',
 *   requiredScopes: ['weather:read'],
 *   callerDid: agent.did,
 *   handler: async (args) => { ... },
 * });
 * // Use guardedTool.handler in your agent's tool list
 * ```
 */

export interface OpenAIAgentToolConfig<TArgs = unknown, TResult = unknown> {
  /** Tool name */
  toolName: string;
  /** Tool description */
  description?: string;
  /** Required scopes */
  requiredScopes?: string[];
  /** The calling agent's DID */
  callerDid: string;
  /** Credentials */
  credentials?: VerifiableCredential[];
  /** The tool handler */
  handler: (args: TArgs) => Promise<TResult>;
}

export interface GuardedOpenAITool<TArgs = unknown, TResult = unknown> {
  toolName: string;
  description?: string;
  handler: (args: TArgs) => Promise<TResult | { error: string; sentinel_blocked: true }>;
}

export function openaiAgentGuardrail<TArgs = unknown, TResult = unknown>(
  verifier: TrustVerifier,
  config: OpenAIAgentToolConfig<TArgs, TResult>
): GuardedOpenAITool<TArgs, TResult> {
  return {
    toolName: config.toolName,
    description: config.description,
    handler: async (args: TArgs) => {
      const context: TrustContext = {
        callerDid: config.callerDid,
        credentials: config.credentials,
      };

      const result = await verifier.verify(context, config.toolName, config.requiredScopes);
      if (!result.allowed) {
        verifier.recordOutcome(context, config.toolName, false);
        return { error: `Sentinel blocked: ${result.reason}`, sentinel_blocked: true as const };
      }

      try {
        const output = await config.handler(args);
        verifier.recordOutcome(context, config.toolName, true);
        return output;
      } catch (err) {
        verifier.recordOutcome(context, config.toolName, false);
        throw err;
      }
    },
  };
}

// ─── Universal Adapter Factory ───────────────────────────────────────

/**
 * Create a framework-agnostic trust wrapper for any async function.
 * This is the simplest integration point — one function, any framework.
 *
 * Usage:
 * ```ts
 * const trustedFn = withTrust(verifier, {
 *   name: 'process_payment',
 *   callerDid: agent.did,
 *   scopes: ['payment:process'],
 *   fn: async (amount: number) => { ... },
 * });
 *
 * const result = await trustedFn(500); // Sentinel checks first
 * ```
 */

export interface WithTrustConfig<TArgs extends unknown[], TResult> {
  /** Action name (for audit) */
  name: string;
  /** Caller DID */
  callerDid: string;
  /** Required scopes */
  scopes?: string[];
  /** Credentials */
  credentials?: VerifiableCredential[];
  /** The function to protect */
  fn: (...args: TArgs) => Promise<TResult>;
}

export function withTrust<TArgs extends unknown[], TResult>(
  verifier: TrustVerifier,
  config: WithTrustConfig<TArgs, TResult>
): (...args: TArgs) => Promise<TResult> {
  return async (...args: TArgs): Promise<TResult> => {
    const context: TrustContext = {
      callerDid: config.callerDid,
      credentials: config.credentials,
    };

    const result = await verifier.verify(context, config.name, config.scopes);
    if (!result.allowed) {
      throw new Error(`Sentinel trust check failed for ${config.name}: ${result.reason ?? 'unauthorized'}`);
    }

    try {
      const output = await config.fn(...args);
      verifier.recordOutcome(context, config.name, true);
      return output;
    } catch (err) {
      verifier.recordOutcome(context, config.name, false);
      throw err;
    }
  };
}
