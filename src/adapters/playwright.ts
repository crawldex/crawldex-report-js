import type {
  AgentProfileInput,
  CrawlDexOutcome,
  CrawlDexReporter,
  EvidenceInput,
  OutcomeInput,
  ReportResult
} from "../index.js";
import { stripUrlQuery } from "../index.js";

export interface AdapterRunResult {
  outcome: CrawlDexOutcome;
  friction?: string[];
  evidenceSignals?: string[];
  evidence_signals?: string[];
}

export interface AdapterReportResult {
  outcome: CrawlDexOutcome;
  friction: string[];
  steps: number;
  durationSec: number;
  evidenceSignals: string[];
  receipt: ReportResult;
}

export interface PlaywrightAdapterOptions {
  reporter: CrawlDexReporter;
  page: unknown;
  site: string;
  task: string;
  recordId?: string;
  record_id?: string;
  agentProfile?: AgentProfileInput;
  agent_profile?: AgentProfileInput;
  sourceTier?: OutcomeInput["sourceTier"];
  source_tier?: OutcomeInput["source_tier"];
  occurredAt?: string;
  occurred_at?: string;
}

export interface PlaywrightRunContext<TPage = unknown> {
  page: TPage;
  step: <T>(name: string, action: () => T | Promise<T>) => Promise<T>;
  friction: (code: string) => void;
  evidence: (signal: string) => void;
}

export async function withPlaywright<TPage = unknown>(
  options: PlaywrightAdapterOptions & { page: TPage },
  run: (context: PlaywrightRunContext<TPage>) => Promise<CrawlDexOutcome | AdapterRunResult> | CrawlDexOutcome | AdapterRunResult
): Promise<AdapterReportResult> {
  const startedAt = Date.now();
  let steps = 0;
  const frictionCodes = new Set<string>();
  const signals = new Set<string>();

  const context: PlaywrightRunContext<TPage> = {
    page: options.page,
    async step<T>(_name: string, action: () => T | Promise<T>): Promise<T> {
      steps += 1;
      return await action();
    },
    friction(code: string): void {
      frictionCodes.add(code);
    },
    evidence(signal: string): void {
      signals.add(signal);
    }
  };

  const result = await run(context);
  const normalized = normalizeRunResult(result);
  for (const code of normalized.friction ?? []) {
    frictionCodes.add(code);
  }
  for (const signal of normalized.evidenceSignals ?? normalized.evidence_signals ?? []) {
    signals.add(signal);
  }

  const pageUrl = getPageUrl(options.page);
  const evidenceArtifact = buildEvidenceArtifact([...signals], pageUrl);
  const durationSec = Math.max(0, Math.round((Date.now() - startedAt) / 1000));
  const receipt = await options.reporter.reportOutcome({
    site: options.site,
    task: options.task,
    recordId: options.recordId ?? options.record_id,
    agentProfile: {
      stack: "playwright",
      ...(options.agentProfile ?? options.agent_profile ?? {})
    },
    outcome: normalized.outcome,
    friction: [...frictionCodes],
    steps,
    durationSec,
    sourceTier: options.sourceTier ?? options.source_tier,
    evidence: evidenceArtifact,
    occurredAt: options.occurredAt ?? options.occurred_at
  });

  return {
    outcome: normalized.outcome,
    friction: [...frictionCodes],
    steps,
    durationSec,
    evidenceSignals: [...signals],
    receipt
  };
}

function normalizeRunResult(result: CrawlDexOutcome | AdapterRunResult): AdapterRunResult {
  return typeof result === "string" ? { outcome: result } : result;
}

function buildEvidenceArtifact(signals: string[], pageUrl: string | null): EvidenceInput | undefined {
  if (!signals.length && !pageUrl) {
    return undefined;
  }

  return {
    artifact: {
      schema: "crawldex.evidence.redacted.v1",
      redaction_status: "hash_only",
      signals,
      final_url: pageUrl,
      removed_fields: ["screenshots", "cookies", "storage_state", "network_bodies", "form_values"]
    },
    artifactTypes: ["action_summary"],
    redactionStatus: "hash_only"
  };
}

function getPageUrl(page: unknown): string | null {
  if (!page || typeof page !== "object") {
    return null;
  }
  const maybeUrl = (page as { url?: unknown }).url;
  if (typeof maybeUrl === "function") {
    const value = maybeUrl.call(page);
    return typeof value === "string" ? stripUrlQuery(value) : null;
  }
  if (typeof maybeUrl === "string") {
    return stripUrlQuery(maybeUrl);
  }
  return null;
}
