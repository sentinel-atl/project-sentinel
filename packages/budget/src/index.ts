/**
 * @sentinel-atl/budget — Token & Cost Budget Enforcement
 *
 * The #1 operational pain for agent developers: runaway costs.
 * This package provides per-agent and per-tool token/cost budgets,
 * circuit breakers, and usage attribution.
 *
 * Usage:
 *   import { BudgetManager } from '@sentinel-atl/budget';
 *   const budget = new BudgetManager();
 *   budget.setAgentBudget('did:key:z6Mk...', { maxTokens: 100_000, maxCostUsd: 5.00 });
 *   const check = budget.checkBudget('did:key:z6Mk...', 1500, 0.003);
 *   if (!check.allowed) console.log(check.reason); // "Token budget exceeded"
 *   budget.recordUsage('did:key:z6Mk...', { tokens: 1500, costUsd: 0.003, tool: 'gpt-4o' });
 */

// ─── Types ───────────────────────────────────────────────────────────

export interface AgentBudget {
  /** Maximum tokens this agent can consume (0 = unlimited) */
  maxTokens: number;
  /** Maximum cost in USD (0 = unlimited) */
  maxCostUsd: number;
  /** Budget window in ms (0 = lifetime, default: 0) */
  windowMs: number;
  /** Per-tool limits (optional) */
  toolLimits?: Record<string, { maxTokens?: number; maxCostUsd?: number }>;
  /** Auto-reset budget when window expires (default: true) */
  autoReset?: boolean;
}

export interface UsageRecord {
  /** Tokens consumed */
  tokens: number;
  /** Cost in USD */
  costUsd: number;
  /** Which tool consumed these tokens */
  tool?: string;
  /** Model used (for attribution) */
  model?: string;
  /** Timestamp (defaults to now) */
  timestamp?: string;
}

export interface UsageSummary {
  /** Total tokens consumed */
  totalTokens: number;
  /** Total cost in USD */
  totalCostUsd: number;
  /** Tokens remaining (Infinity if unlimited) */
  tokensRemaining: number;
  /** Cost remaining in USD (Infinity if unlimited) */
  costRemaining: number;
  /** Per-tool breakdown */
  byTool: Map<string, { tokens: number; costUsd: number; calls: number }>;
  /** Per-model breakdown */
  byModel: Map<string, { tokens: number; costUsd: number; calls: number }>;
  /** Window start */
  windowStart: string;
  /** Total calls */
  totalCalls: number;
}

export interface BudgetCheckResult {
  /** Whether the operation is allowed */
  allowed: boolean;
  /** Reason for denial */
  reason?: string;
  /** Current usage at check time */
  usage: { tokens: number; costUsd: number };
  /** Budget limits */
  limits: { maxTokens: number; maxCostUsd: number };
  /** Whether the circuit breaker is open */
  circuitBreakerOpen: boolean;
}

export interface CircuitBreakerConfig {
  /** Number of consecutive budget denials before tripping (default: 5) */
  tripThreshold: number;
  /** Cool-down period in ms (default: 60000 = 1 min) */
  cooldownMs: number;
}

// ─── Internal State ──────────────────────────────────────────────────

interface AgentState {
  budget: AgentBudget;
  records: UsageRecord[];
  windowStart: number;
  circuitBreaker: {
    consecutiveDenials: number;
    trippedAt: number | null;
  };
}

// ─── Budget Manager ──────────────────────────────────────────────────

export class BudgetManager {
  private agents = new Map<string, AgentState>();
  private circuitBreakerConfig: Required<CircuitBreakerConfig>;
  private globalDailyLimitUsd: number;
  private globalDailyUsage = { costUsd: 0, date: '' };

  constructor(options?: {
    circuitBreaker?: Partial<CircuitBreakerConfig>;
    /** Global daily cost ceiling across ALL agents */
    globalDailyLimitUsd?: number;
  }) {
    this.circuitBreakerConfig = {
      tripThreshold: options?.circuitBreaker?.tripThreshold ?? 5,
      cooldownMs: options?.circuitBreaker?.cooldownMs ?? 60_000,
    };
    this.globalDailyLimitUsd = options?.globalDailyLimitUsd ?? 0;
  }

  /**
   * Set a budget for an agent.
   */
  setAgentBudget(agentDid: string, budget: Partial<AgentBudget>): void {
    const existing = this.agents.get(agentDid);
    const fullBudget: AgentBudget = {
      maxTokens: budget.maxTokens ?? 0,
      maxCostUsd: budget.maxCostUsd ?? 0,
      windowMs: budget.windowMs ?? 0,
      toolLimits: budget.toolLimits,
      autoReset: budget.autoReset ?? true,
    };

    if (existing) {
      existing.budget = fullBudget;
    } else {
      this.agents.set(agentDid, {
        budget: fullBudget,
        records: [],
        windowStart: Date.now(),
        circuitBreaker: { consecutiveDenials: 0, trippedAt: null },
      });
    }
  }

  /**
   * Check whether an agent can spend the given tokens/cost.
   * Does NOT record usage — call recordUsage() after the operation succeeds.
   */
  checkBudget(agentDid: string, estimatedTokens: number, estimatedCostUsd: number, tool?: string): BudgetCheckResult {
    const state = this.agents.get(agentDid);
    if (!state) {
      return {
        allowed: true,
        usage: { tokens: 0, costUsd: 0 },
        limits: { maxTokens: 0, maxCostUsd: 0 },
        circuitBreakerOpen: false,
      };
    }

    // Check window reset
    this.maybeResetWindow(state);

    // Check circuit breaker
    if (state.circuitBreaker.trippedAt !== null) {
      const elapsed = Date.now() - state.circuitBreaker.trippedAt;
      if (elapsed < this.circuitBreakerConfig.cooldownMs) {
        return {
          allowed: false,
          reason: `Circuit breaker open — too many budget denials. Cooldown: ${Math.ceil((this.circuitBreakerConfig.cooldownMs - elapsed) / 1000)}s remaining`,
          usage: this.currentUsage(state),
          limits: { maxTokens: state.budget.maxTokens, maxCostUsd: state.budget.maxCostUsd },
          circuitBreakerOpen: true,
        };
      }
      // Reset circuit breaker after cooldown
      state.circuitBreaker.trippedAt = null;
      state.circuitBreaker.consecutiveDenials = 0;
    }

    const usage = this.currentUsage(state);

    // Check global daily limit
    if (this.globalDailyLimitUsd > 0) {
      const today = new Date().toISOString().slice(0, 10);
      if (this.globalDailyUsage.date !== today) {
        this.globalDailyUsage = { costUsd: 0, date: today };
      }
      if (this.globalDailyUsage.costUsd + estimatedCostUsd > this.globalDailyLimitUsd) {
        this.tripCircuitBreaker(state);
        return {
          allowed: false,
          reason: `Global daily cost limit exceeded: $${this.globalDailyUsage.costUsd.toFixed(4)} / $${this.globalDailyLimitUsd.toFixed(2)}`,
          usage,
          limits: { maxTokens: state.budget.maxTokens, maxCostUsd: state.budget.maxCostUsd },
          circuitBreakerOpen: false,
        };
      }
    }

    // Check per-agent token limit
    if (state.budget.maxTokens > 0 && usage.tokens + estimatedTokens > state.budget.maxTokens) {
      this.tripCircuitBreaker(state);
      return {
        allowed: false,
        reason: `Token budget exceeded: ${usage.tokens + estimatedTokens} / ${state.budget.maxTokens}`,
        usage,
        limits: { maxTokens: state.budget.maxTokens, maxCostUsd: state.budget.maxCostUsd },
        circuitBreakerOpen: false,
      };
    }

    // Check per-agent cost limit
    if (state.budget.maxCostUsd > 0 && usage.costUsd + estimatedCostUsd > state.budget.maxCostUsd) {
      this.tripCircuitBreaker(state);
      return {
        allowed: false,
        reason: `Cost budget exceeded: $${(usage.costUsd + estimatedCostUsd).toFixed(4)} / $${state.budget.maxCostUsd.toFixed(2)}`,
        usage,
        limits: { maxTokens: state.budget.maxTokens, maxCostUsd: state.budget.maxCostUsd },
        circuitBreakerOpen: false,
      };
    }

    // Check per-tool limits
    if (tool && state.budget.toolLimits?.[tool]) {
      const toolLimit = state.budget.toolLimits[tool];
      const toolUsage = this.toolUsage(state, tool);
      if (toolLimit.maxTokens && toolUsage.tokens + estimatedTokens > toolLimit.maxTokens) {
        return {
          allowed: false,
          reason: `Tool '${tool}' token limit exceeded: ${toolUsage.tokens + estimatedTokens} / ${toolLimit.maxTokens}`,
          usage,
          limits: { maxTokens: state.budget.maxTokens, maxCostUsd: state.budget.maxCostUsd },
          circuitBreakerOpen: false,
        };
      }
      if (toolLimit.maxCostUsd && toolUsage.costUsd + estimatedCostUsd > toolLimit.maxCostUsd) {
        return {
          allowed: false,
          reason: `Tool '${tool}' cost limit exceeded: $${(toolUsage.costUsd + estimatedCostUsd).toFixed(4)} / $${toolLimit.maxCostUsd.toFixed(2)}`,
          usage,
          limits: { maxTokens: state.budget.maxTokens, maxCostUsd: state.budget.maxCostUsd },
          circuitBreakerOpen: false,
        };
      }
    }

    // Reset consecutive denials on success
    state.circuitBreaker.consecutiveDenials = 0;

    return {
      allowed: true,
      usage,
      limits: { maxTokens: state.budget.maxTokens, maxCostUsd: state.budget.maxCostUsd },
      circuitBreakerOpen: false,
    };
  }

  /**
   * Record actual usage after an operation.
   */
  recordUsage(agentDid: string, record: UsageRecord): void {
    let state = this.agents.get(agentDid);
    if (!state) {
      // Auto-create agent entry with unlimited budget
      this.setAgentBudget(agentDid, {});
      state = this.agents.get(agentDid)!;
    }

    state.records.push({
      ...record,
      timestamp: record.timestamp ?? new Date().toISOString(),
    });

    // Update global daily usage
    if (this.globalDailyLimitUsd > 0) {
      const today = new Date().toISOString().slice(0, 10);
      if (this.globalDailyUsage.date !== today) {
        this.globalDailyUsage = { costUsd: 0, date: today };
      }
      this.globalDailyUsage.costUsd += record.costUsd;
    }
  }

  /**
   * Get usage summary for an agent.
   */
  getUsageSummary(agentDid: string): UsageSummary | undefined {
    const state = this.agents.get(agentDid);
    if (!state) return undefined;

    this.maybeResetWindow(state);
    const records = this.activeRecords(state);

    const byTool = new Map<string, { tokens: number; costUsd: number; calls: number }>();
    const byModel = new Map<string, { tokens: number; costUsd: number; calls: number }>();
    let totalTokens = 0;
    let totalCostUsd = 0;

    for (const r of records) {
      totalTokens += r.tokens;
      totalCostUsd += r.costUsd;

      const toolKey = r.tool ?? 'unknown';
      const toolEntry = byTool.get(toolKey) ?? { tokens: 0, costUsd: 0, calls: 0 };
      toolEntry.tokens += r.tokens;
      toolEntry.costUsd += r.costUsd;
      toolEntry.calls++;
      byTool.set(toolKey, toolEntry);

      const modelKey = r.model ?? 'unknown';
      const modelEntry = byModel.get(modelKey) ?? { tokens: 0, costUsd: 0, calls: 0 };
      modelEntry.tokens += r.tokens;
      modelEntry.costUsd += r.costUsd;
      modelEntry.calls++;
      byModel.set(modelKey, modelEntry);
    }

    return {
      totalTokens,
      totalCostUsd,
      tokensRemaining: state.budget.maxTokens > 0
        ? Math.max(0, state.budget.maxTokens - totalTokens)
        : Infinity,
      costRemaining: state.budget.maxCostUsd > 0
        ? Math.max(0, state.budget.maxCostUsd - totalCostUsd)
        : Infinity,
      byTool,
      byModel,
      windowStart: new Date(state.windowStart).toISOString(),
      totalCalls: records.length,
    };
  }

  /**
   * Get all tracked agent DIDs.
   */
  getTrackedAgents(): string[] {
    return Array.from(this.agents.keys());
  }

  /**
   * Reset an agent's usage (keep the budget, clear records).
   */
  resetUsage(agentDid: string): void {
    const state = this.agents.get(agentDid);
    if (state) {
      state.records = [];
      state.windowStart = Date.now();
      state.circuitBreaker = { consecutiveDenials: 0, trippedAt: null };
    }
  }

  /**
   * Remove an agent entirely.
   */
  removeAgent(agentDid: string): boolean {
    return this.agents.delete(agentDid);
  }

  // ─── Internals ───────────────────────────────────────────────────

  private currentUsage(state: AgentState): { tokens: number; costUsd: number } {
    const records = this.activeRecords(state);
    let tokens = 0;
    let costUsd = 0;
    for (const r of records) {
      tokens += r.tokens;
      costUsd += r.costUsd;
    }
    return { tokens, costUsd };
  }

  private toolUsage(state: AgentState, tool: string): { tokens: number; costUsd: number } {
    const records = this.activeRecords(state).filter(r => r.tool === tool);
    let tokens = 0;
    let costUsd = 0;
    for (const r of records) {
      tokens += r.tokens;
      costUsd += r.costUsd;
    }
    return { tokens, costUsd };
  }

  private activeRecords(state: AgentState): UsageRecord[] {
    if (state.budget.windowMs <= 0) return state.records;
    const cutoff = new Date(state.windowStart).toISOString();
    return state.records.filter(r => (r.timestamp ?? '') >= cutoff);
  }

  private maybeResetWindow(state: AgentState): void {
    if (state.budget.windowMs <= 0) return;
    if (!state.budget.autoReset) return;
    const elapsed = Date.now() - state.windowStart;
    if (elapsed >= state.budget.windowMs) {
      state.windowStart = Date.now();
      state.records = [];
      state.circuitBreaker = { consecutiveDenials: 0, trippedAt: null };
    }
  }

  private tripCircuitBreaker(state: AgentState): void {
    state.circuitBreaker.consecutiveDenials++;
    if (state.circuitBreaker.consecutiveDenials >= this.circuitBreakerConfig.tripThreshold) {
      state.circuitBreaker.trippedAt = Date.now();
    }
  }
}

// ─── Model pricing reference (for cost estimation) ───────────────────

export const MODEL_PRICING: Record<string, { inputPer1k: number; outputPer1k: number }> = {
  'gpt-4o': { inputPer1k: 0.0025, outputPer1k: 0.01 },
  'gpt-4o-mini': { inputPer1k: 0.00015, outputPer1k: 0.0006 },
  'gpt-4-turbo': { inputPer1k: 0.01, outputPer1k: 0.03 },
  'gpt-3.5-turbo': { inputPer1k: 0.0005, outputPer1k: 0.0015 },
  'claude-3-opus': { inputPer1k: 0.015, outputPer1k: 0.075 },
  'claude-3-sonnet': { inputPer1k: 0.003, outputPer1k: 0.015 },
  'claude-3-haiku': { inputPer1k: 0.00025, outputPer1k: 0.00125 },
  'claude-3.5-sonnet': { inputPer1k: 0.003, outputPer1k: 0.015 },
  'gemini-1.5-pro': { inputPer1k: 0.00125, outputPer1k: 0.005 },
  'gemini-1.5-flash': { inputPer1k: 0.000075, outputPer1k: 0.0003 },
};

/**
 * Estimate cost for a given model and token count.
 */
export function estimateCost(
  model: string,
  inputTokens: number,
  outputTokens: number
): number {
  const pricing = MODEL_PRICING[model];
  if (!pricing) return 0;
  return (inputTokens / 1000) * pricing.inputPer1k + (outputTokens / 1000) * pricing.outputPer1k;
}
