/**
 * @sentinel-atl/safety — Content Safety Hooks
 *
 * The trust layer verifies *identity and authorization*, not *content*.
 * However, agents that handle user-facing content need safety checks.
 *
 * This module provides:
 *
 * 1. **Pre-Dispatch Hook** — Inspect payloads BEFORE they reach the tool.
 *    Block or flag unsafe content (prompt injection, PII, hate speech, etc.)
 *
 * 2. **Post-Response Hook** — Inspect tool outputs BEFORE returning them
 *    to the calling agent. Redact or block unsafe responses.
 *
 * 3. **Pluggable Classifiers** — Bring your own classifier (Azure Content
 *    Safety, OpenAI Moderation, custom ML, regex rules). The `ContentClassifier`
 *    interface makes integration a one-liner.
 *
 * 4. **Safety Pipeline** — Chain multiple classifiers for defense-in-depth.
 *    First violation stops the pipeline.
 *
 * Agents that enable safety hooks can advertise `ContentSafetyCompliant`
 * in their Agent Passport.
 *
 * Blueprint ref: Section 6.3 (Content Safety Integration)
 */

import { AuditLog } from '@sentinel-atl/audit';

// ─── Classification Types ────────────────────────────────────────────

export type SafetyCategory =
  | 'hate_speech'
  | 'violence'
  | 'sexual_content'
  | 'self_harm'
  | 'prompt_injection'
  | 'pii_exposure'
  | 'jailbreak'
  | 'misinformation'
  | 'malware'
  | 'custom';

export type SafetySeverity = 'low' | 'medium' | 'high' | 'critical';

export interface SafetyViolation {
  /** Category of the violation */
  category: SafetyCategory;
  /** Severity level */
  severity: SafetySeverity;
  /** Confidence score (0-1) */
  confidence: number;
  /** Human-readable description */
  description: string;
  /** Which span of text triggered it (optional) */
  span?: { start: number; end: number };
}

export interface ClassificationResult {
  /** Whether the content is safe */
  safe: boolean;
  /** Violations found (empty if safe) */
  violations: SafetyViolation[];
  /** The classifier that produced this result */
  classifierId: string;
  /** Processing time in ms */
  latencyMs: number;
}

// ─── Classifier Interface ────────────────────────────────────────────

/**
 * Content classifier interface. Implement this to plug in any
 * content safety service (Azure, OpenAI, custom ML, regex, etc.)
 */
export interface ContentClassifier {
  /** Unique ID for this classifier */
  readonly id: string;
  /** Human-readable name */
  readonly name: string;
  /** Classify a text payload */
  classify(text: string): Promise<ClassificationResult>;
}

// ─── Built-in Classifiers ────────────────────────────────────────────

/**
 * Regex-based classifier for common safety patterns.
 * Not a substitute for ML classifiers — use as a first-pass filter.
 */
export class RegexClassifier implements ContentClassifier {
  readonly id = 'regex-basic';
  readonly name = 'Regex Basic Safety';

  private rules: Array<{
    pattern: RegExp;
    category: SafetyCategory;
    severity: SafetySeverity;
    description: string;
  }>;

  constructor(rules?: Array<{
    pattern: RegExp;
    category: SafetyCategory;
    severity: SafetySeverity;
    description: string;
  }>) {
    this.rules = rules ?? RegexClassifier.defaultRules();
  }

  async classify(text: string): Promise<ClassificationResult> {
    const start = Date.now();
    const violations: SafetyViolation[] = [];

    for (const rule of this.rules) {
      const match = rule.pattern.exec(text);
      if (match) {
        violations.push({
          category: rule.category,
          severity: rule.severity,
          confidence: 0.7, // Regex matches are not high-confidence
          description: rule.description,
          span: { start: match.index, end: match.index + match[0].length },
        });
      }
    }

    return {
      safe: violations.length === 0,
      violations,
      classifierId: this.id,
      latencyMs: Date.now() - start,
    };
  }

  static defaultRules() {
    return [
      {
        pattern: /ignore\s+(previous|above|all)\s+(instructions?|prompts?|rules?)/i,
        category: 'prompt_injection' as SafetyCategory,
        severity: 'high' as SafetySeverity,
        description: 'Potential prompt injection attempt detected',
      },
      {
        pattern: /you\s+are\s+now\s+(a|an|the)\s+/i,
        category: 'jailbreak' as SafetyCategory,
        severity: 'high' as SafetySeverity,
        description: 'Potential jailbreak attempt (role reassignment)',
      },
      {
        pattern: /\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b/,
        category: 'pii_exposure' as SafetyCategory,
        severity: 'medium' as SafetySeverity,
        description: 'Potential SSN-like pattern detected',
      },
      {
        pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/i,
        category: 'pii_exposure' as SafetyCategory,
        severity: 'low' as SafetySeverity,
        description: 'Email address detected in content',
      },
    ];
  }
}

/**
 * Keyword list classifier. Checks text against a deny-list of terms.
 * Useful for domain-specific safety rules.
 */
export class KeywordClassifier implements ContentClassifier {
  readonly id: string;
  readonly name: string;
  private keywords: Map<string, { category: SafetyCategory; severity: SafetySeverity }>;

  constructor(
    id: string,
    name: string,
    keywords: Array<{ term: string; category: SafetyCategory; severity: SafetySeverity }>
  ) {
    this.id = id;
    this.name = name;
    this.keywords = new Map(
      keywords.map(k => [k.term.toLowerCase(), { category: k.category, severity: k.severity }])
    );
  }

  async classify(text: string): Promise<ClassificationResult> {
    const start = Date.now();
    const violations: SafetyViolation[] = [];
    const lower = text.toLowerCase();

    for (const [term, meta] of this.keywords) {
      const idx = lower.indexOf(term);
      if (idx !== -1) {
        violations.push({
          category: meta.category,
          severity: meta.severity,
          confidence: 0.9,
          description: `Blocked keyword "${term}" detected`,
          span: { start: idx, end: idx + term.length },
        });
      }
    }

    return {
      safe: violations.length === 0,
      violations,
      classifierId: this.id,
      latencyMs: Date.now() - start,
    };
  }
}

// ─── Safety Pipeline ─────────────────────────────────────────────────

export interface SafetyPipelineConfig {
  /** Classifiers to run (in order — first violation stops pipeline) */
  classifiers: ContentClassifier[];
  /** Minimum severity to block (default: 'medium') — 'low' violations are logged but pass through */
  blockThreshold?: SafetySeverity;
  /** Audit log instance (optional — logs all safety decisions) */
  auditLog?: AuditLog;
  /** Actor DID for audit logging */
  actorDid?: string;
}

export interface SafetyCheckResult {
  /** Whether the content passed all safety checks */
  safe: boolean;
  /** Whether the content was blocked */
  blocked: boolean;
  /** All violations found across all classifiers */
  violations: SafetyViolation[];
  /** Per-classifier results */
  classifierResults: ClassificationResult[];
  /** Total processing time */
  totalLatencyMs: number;
}

const SEVERITY_ORDER: Record<SafetySeverity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

export class SafetyPipeline {
  private config: SafetyPipelineConfig;
  private blockThreshold: number;

  constructor(config: SafetyPipelineConfig) {
    this.config = config;
    this.blockThreshold = SEVERITY_ORDER[config.blockThreshold ?? 'medium'];
  }

  /**
   * Run all classifiers on the content.
   * Stops at the first classifier that produces a blocking violation.
   */
  async check(text: string): Promise<SafetyCheckResult> {
    const startTime = Date.now();
    const allViolations: SafetyViolation[] = [];
    const classifierResults: ClassificationResult[] = [];
    let blocked = false;

    for (const classifier of this.config.classifiers) {
      const result = await classifier.classify(text);
      classifierResults.push(result);
      allViolations.push(...result.violations);

      // Check if any violation exceeds the block threshold
      const blockingViolation = result.violations.find(
        v => SEVERITY_ORDER[v.severity] >= this.blockThreshold
      );

      if (blockingViolation) {
        blocked = true;
        break; // Stop pipeline on first blocking violation
      }
    }

    const totalLatencyMs = Date.now() - startTime;

    // Audit log
    if (this.config.auditLog) {
      await this.config.auditLog.log({
        eventType: blocked ? 'intent_rejected' : 'intent_validated',
        actorDid: this.config.actorDid ?? 'system',
        result: blocked ? 'failure' : 'success',
        reason: blocked ? `Content safety: ${allViolations[0]?.description}` : undefined,
        metadata: {
          safetyCheck: true,
          violations: allViolations.length,
          blocked,
          latencyMs: totalLatencyMs,
        },
      });
    }

    return {
      safe: allViolations.length === 0,
      blocked,
      violations: allViolations,
      classifierResults,
      totalLatencyMs,
    };
  }

  // ─── Pre/Post Dispatch Hooks ─────────────────────────────────

  /**
   * Pre-dispatch hook: Check payload before sending to a tool.
   * Returns the content if safe, or throws/blocks if unsafe.
   */
  async preDispatch(payload: string): Promise<{ allowed: boolean; result: SafetyCheckResult }> {
    const result = await this.check(payload);
    return { allowed: !result.blocked, result };
  }

  /**
   * Post-response hook: Check tool output before returning to caller.
   */
  async postResponse(response: string): Promise<{ allowed: boolean; result: SafetyCheckResult }> {
    const result = await this.check(response);
    return { allowed: !result.blocked, result };
  }

  /** Get the current classifiers */
  getClassifiers(): ContentClassifier[] {
    return [...this.config.classifiers];
  }

  /** Add a classifier to the pipeline */
  addClassifier(classifier: ContentClassifier): void {
    this.config.classifiers.push(classifier);
  }
}

// ─── Azure Content Safety Classifier ─────────────────────────────────

/**
 * Real Azure Content Safety integration.
 * Requires an Azure Content Safety resource.
 *
 * Usage:
 *   const classifier = new AzureContentSafetyClassifier({
 *     endpoint: 'https://my-resource.cognitiveservices.azure.com',
 *     apiKey: process.env.AZURE_CONTENT_SAFETY_KEY!,
 *   });
 */
export interface AzureContentSafetyConfig {
  /** Azure Content Safety endpoint URL */
  endpoint: string;
  /** API key (or use DefaultAzureCredential externally and pass a token fetcher) */
  apiKey?: string;
  /** Custom token provider (alternative to apiKey) */
  getToken?: () => Promise<string>;
  /** API version (default: '2024-09-01') */
  apiVersion?: string;
  /** Categories to check (default: all) */
  categories?: Array<'Hate' | 'Violence' | 'SelfHarm' | 'Sexual'>;
  /** Block at or above this severity (0-6, default: 2) */
  blockSeverity?: number;
}

const AZURE_CATEGORY_MAP: Record<string, SafetyCategory> = {
  'Hate': 'hate_speech',
  'Violence': 'violence',
  'SelfHarm': 'self_harm',
  'Sexual': 'sexual_content',
};

const AZURE_SEVERITY_MAP = (severity: number): SafetySeverity => {
  if (severity >= 6) return 'critical';
  if (severity >= 4) return 'high';
  if (severity >= 2) return 'medium';
  return 'low';
};

export class AzureContentSafetyClassifier implements ContentClassifier {
  readonly id = 'azure-content-safety';
  readonly name = 'Azure Content Safety';
  private config: Required<AzureContentSafetyConfig>;

  constructor(config: AzureContentSafetyConfig) {
    this.config = {
      endpoint: config.endpoint.replace(/\/$/, ''),
      apiKey: config.apiKey ?? '',
      getToken: config.getToken ?? (async () => ''),
      apiVersion: config.apiVersion ?? '2024-09-01',
      categories: config.categories ?? ['Hate', 'Violence', 'SelfHarm', 'Sexual'],
      blockSeverity: config.blockSeverity ?? 2,
    };
  }

  async classify(text: string): Promise<ClassificationResult> {
    const start = Date.now();
    const url = `${this.config.endpoint}/contentsafety/text:analyze?api-version=${this.config.apiVersion}`;

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (this.config.apiKey) {
      headers['Ocp-Apim-Subscription-Key'] = this.config.apiKey;
    } else {
      const token = await this.config.getToken();
      headers['Authorization'] = `Bearer ${token}`;
    }

    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        text,
        categories: this.config.categories,
        outputType: 'FourSeverityLevels',
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Azure Content Safety API error: ${response.status} ${errorText}`);
    }

    const data = await response.json() as {
      categoriesAnalysis: Array<{ category: string; severity: number }>;
    };

    const violations: SafetyViolation[] = [];
    for (const cat of data.categoriesAnalysis) {
      if (cat.severity >= this.config.blockSeverity) {
        violations.push({
          category: AZURE_CATEGORY_MAP[cat.category] ?? 'custom',
          severity: AZURE_SEVERITY_MAP(cat.severity),
          confidence: cat.severity / 6,
          description: `Azure Content Safety: ${cat.category} detected (severity ${cat.severity})`,
        });
      }
    }

    return {
      safe: violations.length === 0,
      violations,
      classifierId: this.id,
      latencyMs: Date.now() - start,
    };
  }
}

// ─── OpenAI Moderation Classifier ────────────────────────────────────

/**
 * Real OpenAI Moderation API integration.
 *
 * Usage:
 *   const classifier = new OpenAIModerationClassifier({
 *     apiKey: process.env.OPENAI_API_KEY!,
 *   });
 */
export interface OpenAIModerationConfig {
  /** OpenAI API key */
  apiKey: string;
  /** Model to use (default: 'omni-moderation-latest') */
  model?: string;
  /** Base URL (default: 'https://api.openai.com/v1') */
  baseUrl?: string;
}

const OPENAI_CATEGORY_MAP: Record<string, SafetyCategory> = {
  'hate': 'hate_speech',
  'hate/threatening': 'hate_speech',
  'harassment': 'hate_speech',
  'harassment/threatening': 'hate_speech',
  'self-harm': 'self_harm',
  'self-harm/intent': 'self_harm',
  'self-harm/instructions': 'self_harm',
  'sexual': 'sexual_content',
  'sexual/minors': 'sexual_content',
  'violence': 'violence',
  'violence/graphic': 'violence',
};

export class OpenAIModerationClassifier implements ContentClassifier {
  readonly id = 'openai-moderation';
  readonly name = 'OpenAI Moderation';
  private config: Required<OpenAIModerationConfig>;

  constructor(config: OpenAIModerationConfig) {
    this.config = {
      apiKey: config.apiKey,
      model: config.model ?? 'omni-moderation-latest',
      baseUrl: config.baseUrl ?? 'https://api.openai.com/v1',
    };
  }

  async classify(text: string): Promise<ClassificationResult> {
    const start = Date.now();
    const url = `${this.config.baseUrl}/moderations`;

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.config.apiKey}`,
      },
      body: JSON.stringify({ input: text, model: this.config.model }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`OpenAI Moderation API error: ${response.status} ${errorText}`);
    }

    const data = await response.json() as {
      results: Array<{
        flagged: boolean;
        categories: Record<string, boolean>;
        category_scores: Record<string, number>;
      }>;
    };

    const violations: SafetyViolation[] = [];
    const result = data.results[0];
    if (result?.flagged) {
      for (const [category, flagged] of Object.entries(result.categories)) {
        if (flagged) {
          const score = result.category_scores[category] ?? 0;
          violations.push({
            category: OPENAI_CATEGORY_MAP[category] ?? 'custom',
            severity: score > 0.9 ? 'critical' : score > 0.7 ? 'high' : score > 0.4 ? 'medium' : 'low',
            confidence: score,
            description: `OpenAI Moderation: ${category} flagged (score ${score.toFixed(3)})`,
          });
        }
      }
    }

    return {
      safe: violations.length === 0,
      violations,
      classifierId: this.id,
      latencyMs: Date.now() - start,
    };
  }
}

// ─── Llama Guard Classifier (self-hosted) ────────────────────────────

/**
 * Llama Guard classifier for self-hosted safety models.
 * Calls an OpenAI-compatible endpoint running Llama Guard.
 *
 * Usage:
 *   const classifier = new LlamaGuardClassifier({
 *     endpoint: 'http://localhost:8080/v1/chat/completions',
 *   });
 */
export interface LlamaGuardConfig {
  /** OpenAI-compatible API endpoint */
  endpoint: string;
  /** Model name (default: 'llama-guard-3-8b') */
  model?: string;
  /** API key if required */
  apiKey?: string;
}

export class LlamaGuardClassifier implements ContentClassifier {
  readonly id = 'llama-guard';
  readonly name = 'Llama Guard';
  private config: Required<LlamaGuardConfig>;

  constructor(config: LlamaGuardConfig) {
    this.config = {
      endpoint: config.endpoint,
      model: config.model ?? 'llama-guard-3-8b',
      apiKey: config.apiKey ?? '',
    };
  }

  async classify(text: string): Promise<ClassificationResult> {
    const start = Date.now();

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (this.config.apiKey) {
      headers['Authorization'] = `Bearer ${this.config.apiKey}`;
    }

    const response = await fetch(this.config.endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        model: this.config.model,
        messages: [
          {
            role: 'user',
            content: [{ type: 'text', text }],
          },
        ],
        max_tokens: 100,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Llama Guard API error: ${response.status} ${errorText}`);
    }

    const data = await response.json() as {
      choices: Array<{ message: { content: string } }>;
    };

    const output = data.choices[0]?.message?.content ?? '';
    const violations: SafetyViolation[] = [];

    // Llama Guard outputs "safe" or "unsafe\n<category>"
    if (output.toLowerCase().startsWith('unsafe')) {
      const lines = output.split('\n');
      const category = lines[1]?.trim() ?? 'unknown';
      violations.push({
        category: this.mapCategory(category),
        severity: 'high',
        confidence: 0.85,
        description: `Llama Guard: content classified as unsafe (${category})`,
      });
    }

    return {
      safe: violations.length === 0,
      violations,
      classifierId: this.id,
      latencyMs: Date.now() - start,
    };
  }

  private mapCategory(llamaCategory: string): SafetyCategory {
    const lower = llamaCategory.toLowerCase();
    if (lower.includes('violence')) return 'violence';
    if (lower.includes('hate')) return 'hate_speech';
    if (lower.includes('sexual')) return 'sexual_content';
    if (lower.includes('self-harm') || lower.includes('self_harm') || lower.includes('suicide')) return 'self_harm';
    if (lower.includes('criminal') || lower.includes('malware')) return 'malware';
    return 'custom';
  }
}
