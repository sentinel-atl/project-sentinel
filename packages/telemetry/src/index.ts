/**
 * @sentinel-atl/telemetry — OpenTelemetry Instrumentation for Sentinel
 *
 * Plugs Sentinel's trust decisions into your existing observability stack
 * (Datadog, Grafana, Azure Monitor, Jaeger, etc.) via OpenTelemetry.
 *
 * What gets instrumented:
 * - Every trust verification → a trace span with pass/fail, latency, checks
 * - Handshake negotiations → spans for each step
 * - Reputation queries → spans + score as attributes
 * - Safety checks → spans with violation details
 * - Gateway tool calls → end-to-end spans
 *
 * Metrics exported:
 * - sentinel.trust.decisions (counter) — total trust decisions by outcome
 * - sentinel.trust.latency (histogram) — decision latency in ms
 * - sentinel.reputation.score (gauge) — current score per agent
 * - sentinel.safety.violations (counter) — safety violations by category
 * - sentinel.budget.tokens (counter) — tokens consumed per agent
 * - sentinel.gateway.calls (counter) — gateway tool calls by tool + caller
 *
 * Usage:
 *   import { SentinelTelemetry } from '@sentinel-atl/telemetry';
 *   const tel = new SentinelTelemetry({ serviceName: 'my-agent-service' });
 *   // Wrap any operation:
 *   const result = await tel.traceVerification('verify-vc', callerDid, async (span) => {
 *     span.setAttribute('vc.type', 'AgentAuthorization');
 *     return verifyVC(vc);
 *   });
 */

import { trace, metrics, context, SpanStatusCode, type Span, type Tracer, type Meter, type Counter, type Histogram } from '@opentelemetry/api';

// ─── Types ───────────────────────────────────────────────────────────

export interface TelemetryConfig {
  /** Service name for OTLP export (default: 'sentinel-atl') */
  serviceName?: string;
  /** Whether to enable tracing (default: true) */
  enableTracing?: boolean;
  /** Whether to enable metrics (default: true) */
  enableMetrics?: boolean;
  /** Custom tracer (default: uses global provider) */
  tracer?: Tracer;
  /** Custom meter (default: uses global provider) */
  meter?: Meter;
}

export interface TrustDecisionAttributes {
  callerDid?: string;
  targetDid?: string;
  action?: string;
  tool?: string;
  outcome: 'allow' | 'deny' | 'error';
  denyReason?: string;
  checks?: Record<string, boolean>;
  latencyMs?: number;
}

export interface SafetyEventAttributes {
  classifierId: string;
  category: string;
  severity: string;
  confidence: number;
  blocked: boolean;
}

export interface BudgetEventAttributes {
  agentDid: string;
  tokensUsed: number;
  costUsd: number;
  budgetRemaining: number;
  tool?: string;
}

// ─── Sentinel Telemetry ──────────────────────────────────────────────

export class SentinelTelemetry {
  private tracer: Tracer;
  private meter: Meter;
  private config: Required<TelemetryConfig>;

  // Metrics instruments
  private trustDecisions: Counter;
  private trustLatency: Histogram;
  private reputationGauge: Histogram; // OTel doesn't have a simple gauge; use histogram
  private safetyViolations: Counter;
  private budgetTokens: Counter;
  private budgetCost: Counter;
  private gatewayCalls: Counter;

  constructor(config: TelemetryConfig = {}) {
    this.config = {
      serviceName: config.serviceName ?? 'sentinel-atl',
      enableTracing: config.enableTracing ?? true,
      enableMetrics: config.enableMetrics ?? true,
      tracer: config.tracer ?? trace.getTracer(config.serviceName ?? 'sentinel-atl', '0.1.2'),
      meter: config.meter ?? metrics.getMeter(config.serviceName ?? 'sentinel-atl', '0.1.2'),
    };
    this.tracer = this.config.tracer;
    this.meter = this.config.meter;

    // Initialize metric instruments
    this.trustDecisions = this.meter.createCounter('sentinel.trust.decisions', {
      description: 'Total trust decisions by outcome',
    });
    this.trustLatency = this.meter.createHistogram('sentinel.trust.latency', {
      description: 'Trust decision latency in milliseconds',
      unit: 'ms',
    });
    this.reputationGauge = this.meter.createHistogram('sentinel.reputation.score', {
      description: 'Reputation score observations per agent',
    });
    this.safetyViolations = this.meter.createCounter('sentinel.safety.violations', {
      description: 'Content safety violations by category',
    });
    this.budgetTokens = this.meter.createCounter('sentinel.budget.tokens', {
      description: 'Tokens consumed per agent',
    });
    this.budgetCost = this.meter.createCounter('sentinel.budget.cost_usd', {
      description: 'Cost in USD consumed per agent',
    });
    this.gatewayCalls = this.meter.createCounter('sentinel.gateway.calls', {
      description: 'Gateway tool calls by tool and caller',
    });
  }

  /**
   * Trace a trust verification operation.
   * Creates a span and records metrics for the decision.
   */
  async traceVerification<T>(
    operationName: string,
    callerDid: string,
    fn: (span: Span) => Promise<T>
  ): Promise<T> {
    if (!this.config.enableTracing) return fn(undefined as any);

    return this.tracer.startActiveSpan(`sentinel.verify.${operationName}`, async (span) => {
      const start = Date.now();
      span.setAttribute('sentinel.caller_did', callerDid);
      span.setAttribute('sentinel.operation', operationName);

      try {
        const result = await fn(span);
        const latencyMs = Date.now() - start;
        span.setAttribute('sentinel.latency_ms', latencyMs);
        span.setStatus({ code: SpanStatusCode.OK });
        this.trustLatency.record(latencyMs, { operation: operationName });
        return result;
      } catch (err) {
        const latencyMs = Date.now() - start;
        span.setAttribute('sentinel.latency_ms', latencyMs);
        span.setStatus({ code: SpanStatusCode.ERROR, message: (err as Error).message });
        span.recordException(err as Error);
        throw err;
      } finally {
        span.end();
      }
    });
  }

  /**
   * Record a trust decision (allow/deny/error).
   */
  recordTrustDecision(attrs: TrustDecisionAttributes): void {
    if (!this.config.enableMetrics) return;

    this.trustDecisions.add(1, {
      outcome: attrs.outcome,
      action: attrs.action ?? 'unknown',
      tool: attrs.tool ?? 'unknown',
    });

    if (attrs.latencyMs !== undefined) {
      this.trustLatency.record(attrs.latencyMs, {
        action: attrs.action ?? 'unknown',
        outcome: attrs.outcome,
      });
    }
  }

  /**
   * Record a reputation score observation.
   */
  recordReputation(agentDid: string, score: number): void {
    if (!this.config.enableMetrics) return;
    this.reputationGauge.record(score, { agent_did: agentDid });
  }

  /**
   * Record a safety violation.
   */
  recordSafetyEvent(attrs: SafetyEventAttributes): void {
    if (!this.config.enableMetrics) return;
    this.safetyViolations.add(1, {
      classifier: attrs.classifierId,
      category: attrs.category,
      severity: attrs.severity,
      blocked: String(attrs.blocked),
    });
  }

  /**
   * Record token/cost budget consumption.
   */
  recordBudgetUsage(attrs: BudgetEventAttributes): void {
    if (!this.config.enableMetrics) return;
    this.budgetTokens.add(attrs.tokensUsed, {
      agent_did: attrs.agentDid,
      tool: attrs.tool ?? 'unknown',
    });
    this.budgetCost.add(attrs.costUsd, {
      agent_did: attrs.agentDid,
    });
  }

  /**
   * Record a gateway tool call.
   */
  recordGatewayCall(tool: string, callerDid: string, outcome: 'allow' | 'deny' | 'error'): void {
    if (!this.config.enableMetrics) return;
    this.gatewayCalls.add(1, {
      tool,
      caller_did: callerDid,
      outcome,
    });
  }

  /**
   * Trace a handshake operation end-to-end.
   */
  async traceHandshake<T>(
    initiatorDid: string,
    responderDid: string,
    fn: (span: Span) => Promise<T>
  ): Promise<T> {
    return this.tracer.startActiveSpan('sentinel.handshake', async (span) => {
      span.setAttribute('sentinel.initiator_did', initiatorDid);
      span.setAttribute('sentinel.responder_did', responderDid);
      const start = Date.now();
      try {
        const result = await fn(span);
        span.setAttribute('sentinel.latency_ms', Date.now() - start);
        span.setStatus({ code: SpanStatusCode.OK });
        return result;
      } catch (err) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: (err as Error).message });
        span.recordException(err as Error);
        throw err;
      } finally {
        span.end();
      }
    });
  }

  /**
   * Trace a safety pipeline check.
   */
  async traceSafetyCheck<T>(
    fn: (span: Span) => Promise<T>
  ): Promise<T> {
    return this.tracer.startActiveSpan('sentinel.safety.check', async (span) => {
      const start = Date.now();
      try {
        const result = await fn(span);
        span.setAttribute('sentinel.latency_ms', Date.now() - start);
        span.setStatus({ code: SpanStatusCode.OK });
        return result;
      } catch (err) {
        span.setStatus({ code: SpanStatusCode.ERROR, message: (err as Error).message });
        span.recordException(err as Error);
        throw err;
      } finally {
        span.end();
      }
    });
  }

  /**
   * Get the underlying tracer for custom spans.
   */
  getTracer(): Tracer {
    return this.tracer;
  }

  /**
   * Get the underlying meter for custom metrics.
   */
  getMeter(): Meter {
    return this.meter;
  }
}

// ─── Convenience: No-op telemetry for when OTel is not configured ────

export class NoopTelemetry extends SentinelTelemetry {
  constructor() {
    super({ enableTracing: false, enableMetrics: false });
  }

  override async traceVerification<T>(
    _operationName: string,
    _callerDid: string,
    fn: (span: Span) => Promise<T>
  ): Promise<T> {
    return fn(undefined as any);
  }

  override recordTrustDecision(): void {}
  override recordReputation(): void {}
  override recordSafetyEvent(): void {}
  override recordBudgetUsage(): void {}
  override recordGatewayCall(): void {}
}
