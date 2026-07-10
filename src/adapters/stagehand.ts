import type {
  AgentProfileInput,
  CrawlDexOutcome,
  CrawlDexReporter,
  EvidenceInput,
  OutcomeInput,
  ReportResult
} from "../index.js";

export interface StagehandRunResult {
  outcome: CrawlDexOutcome;
  friction?: string[];
  evidenceSignals?: string[];
  evidence_signals?: string[];
}

export interface StagehandAdapterOptions {
  reporter: CrawlDexReporter;
  stagehand: { page?: unknown };
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
  run: (context: StagehandRunContext) => Promise<StagehandRunResult> | StagehandRunResult;
}

export interface StagehandRunContext {
  page: unknown;
  mark: (signal: string) => void;
}

export interface StagehandReportResult {
  outcome: CrawlDexOutcome;
  friction: string[];
  steps: number;
  durationSec: number;
  evidenceSignals: string[];
  receipt: ReportResult;
}

export async function reportStagehandRun(options: StagehandAdapterOptions): Promise<StagehandReportResult> {
  const startedAt = Date.now();
  const signals = new Set<string>();
  const result = await options.run({
    page: options.stagehand.page,
    mark(signal: string): void {
      signals.add(signal);
    }
  });

  for (const signal of result.evidenceSignals ?? result.evidence_signals ?? []) {
    signals.add(signal);
  }

  const evidence = buildStagehandEvidence([...signals]);
  const durationSec = Math.max(0, Math.round((Date.now() - startedAt) / 1000));
  const receipt = await options.reporter.reportOutcome({
    site: options.site,
    task: options.task,
    recordId: options.recordId ?? options.record_id,
    agentProfile: {
      stack: "stagehand",
      ...(options.agentProfile ?? options.agent_profile ?? {})
    },
    outcome: result.outcome,
    friction: result.friction ?? [],
    steps: 0,
    durationSec,
    sourceTier: options.sourceTier ?? options.source_tier,
    evidence,
    occurredAt: options.occurredAt ?? options.occurred_at
  });

  return {
    outcome: result.outcome,
    friction: result.friction ?? [],
    steps: 0,
    durationSec,
    evidenceSignals: [...signals],
    receipt
  };
}

function buildStagehandEvidence(signals: string[]): EvidenceInput | undefined {
  if (!signals.length) {
    return undefined;
  }

  return {
    artifact: {
      schema: "crawldex.evidence.redacted.v1",
      redaction_status: "hash_only",
      signals,
      removed_fields: ["natural_language_prompts", "page_text", "screenshots", "cookies", "storage_state", "network_bodies", "form_values"]
    },
    artifactTypes: ["action_summary"],
    redactionStatus: "hash_only"
  };
}
