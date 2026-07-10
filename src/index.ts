import { createHash } from "node:crypto";

import { crawldexClientHeaders } from "./instance.js";

export const CRAWLDEX_OUTCOMES = [
  "success",
  "success_with_handoff",
  "partial",
  "blocked",
  "failed",
  "abandoned"
] as const;

export type CrawlDexOutcome = (typeof CRAWLDEX_OUTCOMES)[number];

export const CRAWLDEX_ECHO_ACTIONS = ["followed", "overrode", "partial"] as const;

export type CrawlDexEchoAction = (typeof CRAWLDEX_ECHO_ACTIONS)[number];

export const CRAWLDEX_SOURCE_TIERS = [
  "seeded_example",
  "anonymous_report",
  "merchant_report",
  "attested_sdk",
  "synthetic_canary"
] as const;

export type CrawlDexSourceTier = (typeof CRAWLDEX_SOURCE_TIERS)[number];

export const REDACTION_STATUSES = [
  "not_captured",
  "redacted",
  "hash_only",
  "private_artifact",
  "unsafe_not_submitted"
] as const;

export type RedactionStatus = (typeof REDACTION_STATUSES)[number];

export type RecommendationCode =
  | "proceed_with_recipe"
  | "proceed_with_guardrails"
  | "use_browser_with_user_present"
  | "avoid_until_fresh_evidence"
  | "collect_evidence_first";

export type RiskLevel = "low" | "medium" | "high" | "unknown";
export type FreshnessStatus = "fresh" | "aging" | "stale" | "unknown";
export type HandoffLikelihood = "low" | "medium" | "high" | "unknown";

export interface ReporterOptions {
  reportUrl?: string;
  echoUrl?: string;
  trustRecordUrl?: string;
  apiOrigin?: string;
  agentKey?: string;
  ingestToken?: string;
  dryRun?: boolean;
  autoReport?: boolean;
  timeoutMs?: number;
  fetch?: typeof fetch;
  logger?: Pick<Console, "warn">;
}

export interface AgentProfileInput {
  stack?: string;
  model?: string;
  browserRuntime?: string;
  browser_runtime?: string;
  version?: string;
  identityClass?: string;
  identity_class?: string;
  capabilities?: Record<string, boolean | number | string>;
}

export interface AttemptInput {
  site: string;
  task: string;
  agentProfile?: AgentProfileInput;
  agent_profile?: AgentProfileInput;
}

export interface PreflightInput extends AttemptInput {
  intent?: string;
  constraints?: Record<string, unknown>;
}

export interface OutcomeInput extends AttemptInput {
  outcome: CrawlDexOutcome;
  recordId?: string;
  record_id?: string;
  echoAction?: CrawlDexEchoAction;
  echo_action?: CrawlDexEchoAction;
  taskAttempted?: boolean;
  task_attempted?: boolean;
  friction?: string[];
  steps?: number;
  durationSec?: number;
  duration_sec?: number;
  tokenCostUsd?: number;
  token_cost_usd?: number;
  accessFeeUsd?: number;
  access_fee_usd?: number;
  sourceTier?: CrawlDexSourceTier;
  source_tier?: CrawlDexSourceTier;
  evidence?: EvidenceInput;
  reporter?: ReporterMetadataInput;
  occurredAt?: string;
  occurred_at?: string;
}

export interface EvidenceInput {
  id?: string;
  artifact?: unknown;
  artifactPath?: string;
  artifact_path?: string;
  hash?: string;
  uri?: string;
  artifactTypes?: string[];
  artifact_types?: string[];
  redactionStatus?: RedactionStatus;
  redaction_status?: RedactionStatus;
  signature?: string;
}

export interface ReporterMetadataInput {
  id?: string;
  publicKeyId?: string;
  public_key_id?: string;
  signature?: string;
  attestationType?: "none" | "api_key" | "signed_report" | "local_operator" | "canary_worker";
  attestation_type?: "none" | "api_key" | "signed_report" | "local_operator" | "canary_worker";
}

export interface RunReportPayload {
  site: string;
  task: string;
  agent_profile?: {
    stack?: string;
    model?: string;
    browser_runtime?: string;
    version?: string;
    identity_class?: string;
    capabilities?: Record<string, boolean | number | string>;
  };
  outcome: CrawlDexOutcome;
  friction?: string[];
  steps?: number;
  duration_sec?: number;
  token_cost_usd?: number;
  access_fee_usd?: number;
  source_tier?: CrawlDexSourceTier;
  evidence?: {
    id?: string;
    hash?: string;
    uri?: string;
    artifact_types?: string[];
    signature?: string;
  };
  reporter?: {
    id?: string;
    public_key_id?: string;
    signature?: string;
    attestation_type?: "none" | "api_key" | "signed_report" | "local_operator" | "canary_worker";
  };
  occurred_at?: string;
}

export interface SubmissionReceipt {
  accepted: true;
  acceptance: "trusted" | "anonymous" | "dry_run";
  endpoint: string;
  runId: string | null;
  sourceTier: CrawlDexSourceTier | string | null;
  reporterId: string | null;
  trustLevel: "untrusted" | "low" | "medium" | "high" | string | null;
  updatedAes: number | null;
  payload: RunReportPayload;
  warning?: string;
}

export interface FailOpenSubmissionReceipt {
  accepted: false;
  failOpen: true;
  endpoint: string;
  warning: string;
  payload: RunReportPayload;
}

export type ReportResult = SubmissionReceipt | FailOpenSubmissionReceipt;

export interface EchoReceipt {
  accepted: true;
  endpoint: string;
  payload: DecisionEchoPayload;
}

export interface SkippedEchoReceipt {
  accepted: false;
  skipped: true;
  endpoint: string;
  warning: string;
  payload: DecisionEchoPayload | null;
}

export interface FailOpenEchoReceipt {
  accepted: false;
  failOpen: true;
  endpoint: string;
  warning: string;
  payload: DecisionEchoPayload;
}

export type EchoResult = EchoReceipt | SkippedEchoReceipt | FailOpenEchoReceipt;

export interface DecisionEchoPayload {
  record_id: string;
  action_taken: CrawlDexEchoAction;
  task_attempted: boolean;
}

export interface ConfidenceSummary {
  score?: number;
  level?: "low" | "medium" | "high";
  sample_size?: number;
  rationale?: string;
}

export interface FreshnessSummary {
  updated_at: string | null;
  age_days: number | null;
  status: FreshnessStatus;
  rationale?: string;
}

export interface PreflightResponse {
  site: string;
  task: string;
  decision: {
    recommendation: RecommendationCode;
    risk_level: RiskLevel;
    should_attempt_autonomously: boolean;
    rationale: string;
  };
  score?: {
    aes?: number | null;
    outcome_rate?: number | null;
    known_blockers?: string[];
    freshness?: FreshnessSummary;
  };
  known_good_path?: unknown;
  alternatives?: unknown[];
  confidence?: ConfidenceSummary;
  freshness?: FreshnessSummary;
  evidence?: unknown;
  trust?: unknown;
  recommended_actions?: unknown[];
  reporting?: {
    report_url?: string;
    auth_header?: string;
  };
}

export interface PreflightVerdict {
  verdict: RecommendationCode | "unknown";
  outcome_rate: number | null;
  outcomeRate: number | null;
  blockers: string[];
  handoff_likelihood: HandoffLikelihood;
  handoffLikelihood: HandoffLikelihood;
  freshness: FreshnessSummary;
  should_attempt_autonomously: boolean;
  shouldAttemptAutonomously: boolean;
  risk_level: RiskLevel;
  riskLevel: RiskLevel;
  response?: PreflightResponse;
  warning?: string;
}

export type AtrUnknown = "unknown";
export type AtrVerdict = "proceed" | "proceed_with_guardrails" | "handoff_required" | "user_needed" | "avoid" | "unknown";
export type AgentHostility = "none" | "low" | "medium" | "high" | "wall" | AtrUnknown;
export type DomainRisk = "none" | "caution" | "risk" | AtrUnknown;

export interface TrustRecord {
  atr_version: "0.1";
  site: string;
  task: string | null;
  issued_at: string;
  record_id: string;
  verdict: AtrVerdict;
  confidence: number;
  accessibility: {
    reachable: boolean | AtrUnknown;
    agent_hostility: AgentHostility;
    success_rate: number | AtrUnknown;
    handoff_rate: number | AtrUnknown;
    blocked_rate: number | AtrUnknown;
    n: number;
    last_verified: string | null;
  };
  safety: {
    canonical: boolean | AtrUnknown;
    canonical_alternative: string | null;
    domain_risk: DomainRisk;
    notes: string[];
  };
  freshness: {
    median_evidence_age_days: number | null;
    surface_last_changed: string | null;
    stale: boolean | AtrUnknown;
  };
  task_compatibility: {
    supported: boolean | AtrUnknown;
    expected_steps: number | AtrUnknown;
    recipe_available: boolean;
    alternatives: string[];
  };
  known_blockers: Array<{
    kind: string;
    since: string | AtrUnknown;
    n: number | AtrUnknown;
    persistent: boolean | AtrUnknown;
  }>;
  user_present: {
    required: boolean | AtrUnknown;
    reasons: string[];
    irreversible_action: boolean | AtrUnknown;
  };
  agent_instruction: string;
  evidence: {
    sources: Record<string, number>;
    canonical_url: string;
    dispute_url: string;
  };
  publisher: {
    claimed: boolean;
    statement: string | null;
  };
  how_to_improve: string | null;
}

export interface FailOpenTrustRecord extends Omit<TrustRecord, "issued_at" | "record_id"> {
  issued_at: null;
  record_id: null;
  failOpen: true;
  warning: string;
}

export type TrustRecordResult = TrustRecord | FailOpenTrustRecord;

export interface RedactionPolicy {
  redactionStatus?: Exclude<RedactionStatus, "unsafe_not_submitted">;
  sensitiveKeyPattern?: RegExp;
}

export interface RedactedEvidenceArtifact {
  schema: "crawldex.evidence.redacted.v1";
  redaction_status: Exclude<RedactionStatus, "unsafe_not_submitted">;
  artifact: unknown;
  removed_fields: string[];
}

export interface CrawlDexReporter {
  preflight(site: string, task: string, agentProfile?: AgentProfileInput): Promise<PreflightVerdict>;
  preflight(input: PreflightInput): Promise<PreflightVerdict>;
  trustRecord(site: string, task?: string | null): Promise<TrustRecordResult>;
  echo(recordId: string, action: CrawlDexEchoAction, taskAttempted?: boolean): Promise<EchoResult>;
  report(input: OutcomeInput): Promise<ReportResult>;
  reportOutcome(input: OutcomeInput): Promise<ReportResult>;
  mapToRunReport(input: OutcomeInput): RunReportPayload;
}

const CONTROL_CHARS = /[\u0000-\u001f\u007f]/g;
const DEFAULT_SENSITIVE_KEY_PATTERN = /(?:password|passcode|otp|mfa|totp|cookie|cookies|authorization|auth(?:orization)?_?header|bearer|token|api_?key|secret|csrf|session|storage|local_?storage|session_?storage|indexeddb|screenshot|dom|accessibility|html|body|form_?value|card|cvv|ssn|bank|medical|address|phone|email|email_body|download)/i;
const URL_WITH_QUERY = /\bhttps?:\/\/[^\s"'<>]+/gi;
const EMAIL_PATTERN = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;
const TRUST_RECORD_TIMEOUT_MS = 5_000;
const ECHO_TIMEOUT_MS = 5_000;
const DEFAULT_API_ORIGINS = [
  "https://api.crawldex.com",
  "https://crawldex.com",
  "https://crawldex.vercel.app"
] as const;
const RESPONSE_BODY_PREVIEW_CHARS = 240;
const ECHO_RECORD_ID_PATTERN = /^atr_[0-9a-f]{16}$/;
const SECRET_STRING_PATTERNS = [
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi,
  /\baa_agent_[A-Za-z0-9._-]+/gi,
  /\b(?:sk|pk|ghp|gho|github_pat)_[A-Za-z0-9_=-]{12,}\b/gi,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  /\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password)\s*[:=]\s*["']?[^"',\s}]+/gi,
  /\b(?:\d[ -]*?){13,19}\b/g
];

export function createReporter(options: ReporterOptions = {}): CrawlDexReporter {
  const env = getEnv();
  const reportEndpoint = options.reportUrl ?? env.CRAWLDEX_REPORT_URL;
  const trustRecordEndpoint = options.trustRecordUrl ?? env.CRAWLDEX_TRUST_RECORD_URL;
  const apiOrigin = options.apiOrigin ?? env.CRAWLDEX_API_ORIGIN;
  const apiOriginCandidates = resolveApiOrigins(apiOrigin, reportEndpoint);
  const reportEndpoints = reportEndpoint ? [reportEndpoint] : endpointCandidates(apiOriginCandidates, "/api/v1/runs");
  const echoEndpoints = resolveEchoEndpoints({
    explicitEchoEndpoint: options.echoUrl,
    apiOriginCandidates,
    reportEndpoint
  });
  const agentKey = options.agentKey ?? env.CRAWLDEX_AGENT_KEY;
  const ingestToken = options.ingestToken ?? env.CRAWLDEX_INGEST_TOKEN;
  const dryRun = options.dryRun ?? false;
  const autoReport = options.autoReport === true;
  const fetchImpl = options.fetch ?? globalThis.fetch;
  const logger = options.logger ?? console;
  const timeoutMs = options.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
  const trustRecordTimeoutMs = Math.min(timeoutMs, TRUST_RECORD_TIMEOUT_MS);
  const echoTimeoutMs = Math.min(timeoutMs, ECHO_TIMEOUT_MS);

  async function report(input: OutcomeInput): Promise<ReportResult> {
    const payload = mapToRunReport(input);
    const endpoint = reportEndpoints[0] ?? "";

    if (dryRun) {
      return dryRunReceipt(payload, endpoint);
    }

    if (!endpoint) {
      return failOpenReport("CrawlDex report skipped: reportUrl or CRAWLDEX_REPORT_URL is not configured.", endpoint, payload, logger);
    }

    if (!fetchImpl) {
      return failOpenReport("CrawlDex report skipped: no fetch implementation is available.", endpoint, payload, logger);
    }

    try {
      const { response, endpoint: usedEndpoint } = await fetchWithFallback(fetchImpl, reportEndpoints, {
        method: "POST",
        headers: buildHeaders(agentKey, ingestToken),
        body: JSON.stringify(payload)
      }, timeoutMs);

      if (!response.ok) {
        const bodyPreview = await readRawBodyPreview(response);
        return failOpenReport(`CrawlDex report skipped: HTTP ${response.status}: ${bodyPreview}.`, usedEndpoint, payload, logger);
      }

      const body = await readJsonResponse(response, usedEndpoint);
      const receipt = receiptFromResponse(usedEndpoint, payload, body);
      await maybeAutoEcho(input, receipt);
      return receipt;
    } catch (error) {
      return failOpenReport(`CrawlDex report skipped: ${errorSummary(error)}.`, endpoint, payload, logger);
    }
  }

  async function preflight(siteOrInput: string | PreflightInput, task?: string, agentProfile?: AgentProfileInput): Promise<PreflightVerdict> {
    const input = normalizePreflightInput(siteOrInput, task, agentProfile);
    const endpoints = resolvePreflightEndpoints(reportEndpoint, env.CRAWLDEX_PREFLIGHT_URL, apiOriginCandidates);

    if (dryRun) {
      return failOpenPreflight("CrawlDex preflight skipped: dryRun is enabled.", undefined, logger);
    }

    if (endpoints.length === 0) {
      return failOpenPreflight("CrawlDex preflight skipped: reportUrl/CRAWLDEX_REPORT_URL or CRAWLDEX_PREFLIGHT_URL is not configured.", undefined, logger);
    }

    if (!fetchImpl) {
      return failOpenPreflight("CrawlDex preflight skipped: no fetch implementation is available.", undefined, logger);
    }

    try {
      const { response, endpoint } = await fetchWithFallback(fetchImpl, endpoints, {
        method: "POST",
        headers: buildHeaders(agentKey, ingestToken),
        body: JSON.stringify(mapPreflightPayload(input))
      }, timeoutMs);

      if (!response.ok) {
        const bodyPreview = await readRawBodyPreview(response);
        return failOpenPreflight(`CrawlDex preflight skipped: HTTP ${response.status}: ${bodyPreview}.`, undefined, logger);
      }

      const body = await readJsonResponse(response, endpoint);
      return verdictFromPreflightResponse(body as PreflightResponse);
    } catch (error) {
      return failOpenPreflight(`CrawlDex preflight skipped: ${errorSummary(error)}.`, undefined, logger);
    }
  }

  async function trustRecord(site: string, task?: string | null): Promise<TrustRecordResult> {
    const cleanSite = validateText("site", redactString(site), 253);
    const cleanTask = task === null || task === undefined ? null : validateText("task", redactString(task), 160);
    const endpoints = resolveTrustRecordEndpoints({
      explicitTrustRecordEndpoint: trustRecordEndpoint,
      apiOriginCandidates,
      site: cleanSite,
      task: cleanTask
    });

    if (dryRun) {
      return failOpenTrustRecord(cleanSite, cleanTask, "CrawlDex trustRecord skipped: dryRun is enabled.", logger);
    }

    if (endpoints.length === 0) {
      return failOpenTrustRecord(cleanSite, cleanTask, "CrawlDex trustRecord skipped: trustRecordUrl, apiOrigin, reportUrl, or CRAWLDEX_API_ORIGIN is not configured.", logger);
    }

    if (!fetchImpl) {
      return failOpenTrustRecord(cleanSite, cleanTask, "CrawlDex trustRecord skipped: no fetch implementation is available.", logger);
    }

    try {
      const { response, endpoint } = await fetchWithFallback(fetchImpl, endpoints, {
        method: "GET",
        headers: buildHeaders(agentKey, ingestToken)
      }, trustRecordTimeoutMs);

      if (!response.ok) {
        const bodyPreview = await readRawBodyPreview(response);
        return failOpenTrustRecord(cleanSite, cleanTask, `CrawlDex trustRecord skipped: HTTP ${response.status}: ${bodyPreview}.`, logger);
      }

      const body = await readJsonResponse(response, endpoint);
      return trustRecordFromResponse(body);
    } catch (error) {
      return failOpenTrustRecord(cleanSite, cleanTask, `CrawlDex trustRecord skipped: ${errorSummary(error)}.`, logger);
    }
  }

  async function echo(recordId: string, action: CrawlDexEchoAction, taskAttempted = true): Promise<EchoResult> {
    const payload = buildEchoPayload(recordId, action, taskAttempted);
    const echoEndpoint = echoEndpoints[0] ?? "";

    if (dryRun) {
      return skippedEcho("CrawlDex echo skipped: dryRun is enabled.", echoEndpoint, payload);
    }

    if (echoEndpoints.length === 0) {
      return failOpenEcho("CrawlDex echo skipped: echoUrl, apiOrigin, reportUrl, or CRAWLDEX_API_ORIGIN is not configured.", "", payload, logger);
    }

    if (!fetchImpl) {
      return failOpenEcho("CrawlDex echo skipped: no fetch implementation is available.", echoEndpoint, payload, logger);
    }

    try {
      const { response, endpoint } = await fetchWithFallback(fetchImpl, echoEndpoints, {
        method: "POST",
        headers: buildHeaders(undefined, undefined),
        body: JSON.stringify(payload)
      }, echoTimeoutMs);

      if (!response.ok) {
        const bodyPreview = await readRawBodyPreview(response);
        return failOpenEcho(`CrawlDex echo skipped: HTTP ${response.status}: ${bodyPreview}.`, endpoint, payload, logger);
      }

      return {
        accepted: true,
        endpoint,
        payload
      };
    } catch (error) {
      return failOpenEcho(`CrawlDex echo skipped: ${errorSummary(error)}.`, echoEndpoint, payload, logger);
    }
  }

  async function maybeAutoEcho(input: OutcomeInput, receipt: ReportResult): Promise<void> {
    if (!autoReport || !receipt.accepted) {
      return;
    }

    const recordId = chooseAlias<string>(input, "recordId", "record_id");
    if (!recordId) {
      return;
    }

    try {
      await echo(
        recordId,
        chooseAlias<CrawlDexEchoAction>(input, "echoAction", "echo_action") ?? "followed",
        chooseAlias<boolean>(input, "taskAttempted", "task_attempted") ?? true
      );
    } catch (error) {
      logger.warn(`CrawlDex autoReport echo skipped: ${errorSummary(error)}.`);
    }
  }

  return {
    preflight,
    trustRecord,
    echo,
    report,
    reportOutcome: report,
    mapToRunReport
  };
}

export async function reportOutcome(input: OutcomeInput, options?: ReporterOptions): Promise<ReportResult> {
  return createReporter(options).reportOutcome(input);
}

export async function trustRecord(site: string, task?: string | null, options?: ReporterOptions): Promise<TrustRecordResult> {
  return createReporter(options).trustRecord(site, task);
}

export async function echo(recordId: string, action: CrawlDexEchoAction, options?: ReporterOptions & { taskAttempted?: boolean }): Promise<EchoResult> {
  return createReporter(options).echo(recordId, action, options?.taskAttempted);
}

export function mapToRunReport(input: OutcomeInput): RunReportPayload {
  const payload: RunReportPayload = {
    site: validateText("site", redactString(input.site), 253),
    task: validateText("task", redactString(input.task), 160),
    outcome: validateEnum("outcome", input.outcome, CRAWLDEX_OUTCOMES)
  };

  const agentProfile = mapAgentProfile(chooseAlias<AgentProfileInput>(input, "agentProfile", "agent_profile"));
  if (agentProfile) {
    payload.agent_profile = agentProfile;
  }

  const friction = input.friction?.map((value) => validateText("friction", redactString(value), 128));
  if (friction?.length) {
    if (friction.length > 50) {
      throw new Error("friction must contain at most 50 entries.");
    }
    payload.friction = friction;
  }

  setNumber(payload, "steps", input.steps, { integer: true });
  setNumber(payload, "duration_sec", chooseAlias<number>(input, "durationSec", "duration_sec"));
  setNumber(payload, "token_cost_usd", chooseAlias<number>(input, "tokenCostUsd", "token_cost_usd"));
  setNumber(payload, "access_fee_usd", chooseAlias<number>(input, "accessFeeUsd", "access_fee_usd"));

  const sourceTier = chooseAlias<CrawlDexSourceTier>(input, "sourceTier", "source_tier");
  if (sourceTier !== undefined) {
    payload.source_tier = validateEnum("sourceTier", sourceTier, CRAWLDEX_SOURCE_TIERS);
  }

  const evidence = mapEvidence(input.evidence, payload);
  if (evidence) {
    payload.evidence = evidence;
  }

  const reporter = mapReporter(input.reporter);
  if (reporter) {
    payload.reporter = reporter;
  }

  const occurredAt = chooseAlias<string>(input, "occurredAt", "occurred_at");
  if (occurredAt !== undefined) {
    validateIsoDateTime("occurredAt", occurredAt);
    payload.occurred_at = occurredAt;
  }

  return payload;
}

export function hashEvidenceArtifact(artifact: unknown | string | Uint8Array): `sha256:${string}` {
  let bytes: Buffer;
  if (typeof artifact === "string") {
    bytes = Buffer.from(artifact, "utf8");
  } else if (artifact instanceof Uint8Array) {
    bytes = Buffer.from(artifact);
  } else {
    bytes = Buffer.from(canonicalJson(artifact), "utf8");
  }

  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

export function redactEvidenceArtifact(
  artifact: unknown,
  policy: RedactionPolicy = {}
): RedactedEvidenceArtifact {
  const removed = new Set<string>();
  const redacted = redactValue(
    artifact,
    "$",
    removed,
    policy.sensitiveKeyPattern ?? DEFAULT_SENSITIVE_KEY_PATTERN
  );

  return {
    schema: "crawldex.evidence.redacted.v1",
    redaction_status: policy.redactionStatus ?? "hash_only",
    artifact: redacted,
    removed_fields: [...removed].sort()
  };
}

export function stripUrlQuery(value: string): string {
  try {
    const parsed = new URL(value);
    parsed.search = "";
    parsed.hash = "";
    return parsed.toString();
  } catch {
    return value;
  }
}

export function canonicalJson(value: unknown): string {
  return serializeJsonValue(value, "$", new WeakSet<object>());
}

function normalizePreflightInput(siteOrInput: string | PreflightInput, task?: string, agentProfile?: AgentProfileInput): PreflightInput {
  if (typeof siteOrInput === "string") {
    if (task === undefined) {
      throw new Error("task is required when preflight is called with a site string.");
    }
    return { site: siteOrInput, task, agentProfile };
  }
  return siteOrInput;
}

function mapPreflightPayload(input: PreflightInput): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    site: validateText("site", redactString(input.site), 253),
    task: validateText("task", redactString(input.task), 160)
  };
  const agentProfile = mapAgentProfile(chooseAlias<AgentProfileInput>(input, "agentProfile", "agent_profile"));
  if (agentProfile) {
    payload.agent_profile = agentProfile;
  }
  if (input.intent !== undefined) {
    payload.intent = validateText("intent", redactString(input.intent), 500);
  }
  if (input.constraints !== undefined) {
    payload.constraints = input.constraints;
  }
  return payload;
}

function mapAgentProfile(input: AgentProfileInput | undefined): RunReportPayload["agent_profile"] | undefined {
  if (!input) {
    return undefined;
  }

  const profile: NonNullable<RunReportPayload["agent_profile"]> = {};
  setText(profile, "stack", redactOptional(input.stack), 128);
  setText(profile, "model", redactOptional(input.model), 128);
  setText(profile, "browser_runtime", redactOptional(chooseAlias<string>(input, "browserRuntime", "browser_runtime")), 128);
  setText(profile, "version", redactOptional(input.version), 128);
  setText(profile, "identity_class", redactOptional(chooseAlias<string>(input, "identityClass", "identity_class")), 128);

  if (input.capabilities) {
    const capabilities: Record<string, boolean | number | string> = {};
    for (const [key, value] of Object.entries(input.capabilities)) {
      const cleanKey = validateText("agent_profile.capabilities key", key, 128);
      if (typeof value === "string") {
        capabilities[cleanKey] = validateText(`agent_profile.capabilities.${cleanKey}`, redactString(value), 128);
      } else if (typeof value === "number") {
        validateFiniteNonNegative(`agent_profile.capabilities.${cleanKey}`, value, false);
        capabilities[cleanKey] = value;
      } else if (typeof value === "boolean") {
        capabilities[cleanKey] = value;
      } else {
        throw new Error(`agent_profile.capabilities.${cleanKey} must be a boolean, number, or string.`);
      }
    }
    if (Object.keys(capabilities).length) {
      profile.capabilities = capabilities;
    }
  }

  return Object.keys(profile).length ? profile : undefined;
}

function mapEvidence(
  input: EvidenceInput | undefined,
  payload: RunReportPayload
): RunReportPayload["evidence"] | undefined {
  if (!input) {
    return undefined;
  }

  const redactionStatus = chooseAlias<RedactionStatus>(input, "redactionStatus", "redaction_status");
  if (redactionStatus !== undefined) {
    validateEnum("evidence.redactionStatus", redactionStatus, REDACTION_STATUSES);
    if (redactionStatus === "unsafe_not_submitted") {
      throw new Error("evidence.redactionStatus is unsafe_not_submitted; refusing to submit.");
    }
    payload.agent_profile ??= {};
    payload.agent_profile.capabilities = {
      ...payload.agent_profile.capabilities,
      evidence_redaction: redactionStatus
    };
  }

  const evidence: NonNullable<RunReportPayload["evidence"]> = {};
  setText(evidence, "id", input.id, 128);
  setText(evidence, "uri", redactString(input.uri ?? chooseAlias<string>(input, "artifactPath", "artifact_path") ?? ""), 2048, true);
  setText(evidence, "signature", input.signature, 4096);

  const artifactTypes = chooseAlias<string[]>(input, "artifactTypes", "artifact_types");
  if (artifactTypes?.length) {
    if (artifactTypes.length > 20) {
      throw new Error("evidence.artifactTypes must contain at most 20 entries.");
    }
    evidence.artifact_types = artifactTypes.map((type) => validateText("evidence.artifactTypes", type, 128));
  }

  if (input.artifact !== undefined) {
    const redactedArtifact = redactEvidenceArtifact(input.artifact, {
      redactionStatus: redactionStatus ?? "hash_only"
    });
    const generatedHash = hashEvidenceArtifact(redactedArtifact);
    if (input.hash !== undefined && input.hash !== generatedHash) {
      throw new Error("evidence.hash does not match the hash of the redacted evidence artifact.");
    }
    evidence.hash = generatedHash;
  } else if (input.hash !== undefined) {
    evidence.hash = validateText("evidence.hash", input.hash, 128);
  }

  return Object.keys(evidence).length ? evidence : undefined;
}

function mapReporter(input: ReporterMetadataInput | undefined): RunReportPayload["reporter"] | undefined {
  if (!input) {
    return undefined;
  }

  const reporter: NonNullable<RunReportPayload["reporter"]> = {};
  setText(reporter, "id", input.id, 128);
  setText(reporter, "public_key_id", chooseAlias<string>(input, "publicKeyId", "public_key_id"), 128);
  setText(reporter, "signature", input.signature, 4096);
  const attestationType = chooseAlias<NonNullable<RunReportPayload["reporter"]>["attestation_type"]>(input, "attestationType", "attestation_type");
  if (attestationType !== undefined) {
    reporter.attestation_type = validateEnum("reporter.attestationType", attestationType, ["none", "api_key", "signed_report", "local_operator", "canary_worker"] as const);
  }

  return Object.keys(reporter).length ? reporter : undefined;
}

function verdictFromPreflightResponse(response: PreflightResponse): PreflightVerdict {
  const verdict = response.decision?.recommendation ?? "unknown";
  const outcomeRate = typeof response.score?.outcome_rate === "number" ? response.score.outcome_rate : null;
  const blockers = Array.isArray(response.score?.known_blockers) ? response.score.known_blockers : [];
  const freshness = response.freshness ?? response.score?.freshness ?? unknownFreshness();
  const handoffLikelihood = inferHandoffLikelihood(verdict, blockers, response.decision?.should_attempt_autonomously ?? false);
  const shouldAttempt = response.decision?.should_attempt_autonomously ?? false;
  const riskLevel = response.decision?.risk_level ?? "unknown";

  return {
    verdict,
    outcome_rate: outcomeRate,
    outcomeRate,
    blockers,
    handoff_likelihood: handoffLikelihood,
    handoffLikelihood,
    freshness,
    should_attempt_autonomously: shouldAttempt,
    shouldAttemptAutonomously: shouldAttempt,
    risk_level: riskLevel,
    riskLevel,
    response
  };
}

export function trustRecordFromResponse(body: unknown): TrustRecord {
  if (!isRecord(body)) {
    throw new Error("trust record response must be an object.");
  }
  return {
    atr_version: literalField(body, "atr_version", "0.1"),
    site: stringField(body, "site"),
    task: nullableStringField(body, "task"),
    issued_at: stringField(body, "issued_at"),
    record_id: stringField(body, "record_id"),
    verdict: enumField(body, "verdict", ["proceed", "proceed_with_guardrails", "handoff_required", "user_needed", "avoid", "unknown"] as const),
    confidence: ratioField(body, "confidence"),
    accessibility: objectField(body, "accessibility", (value) => ({
      reachable: booleanOrUnknownField(value, "reachable"),
      agent_hostility: enumField(value, "agent_hostility", ["none", "low", "medium", "high", "wall", "unknown"] as const),
      success_rate: ratioOrUnknownField(value, "success_rate"),
      handoff_rate: ratioOrUnknownField(value, "handoff_rate"),
      blocked_rate: ratioOrUnknownField(value, "blocked_rate"),
      n: nonNegativeIntegerField(value, "n"),
      last_verified: nullableStringField(value, "last_verified")
    })),
    safety: objectField(body, "safety", (value) => ({
      canonical: booleanOrUnknownField(value, "canonical"),
      canonical_alternative: nullableStringField(value, "canonical_alternative"),
      domain_risk: enumField(value, "domain_risk", ["none", "caution", "risk", "unknown"] as const),
      notes: stringArrayField(value, "notes")
    })),
    freshness: objectField(body, "freshness", (value) => ({
      median_evidence_age_days: nullableNonNegativeIntegerField(value, "median_evidence_age_days"),
      surface_last_changed: nullableStringField(value, "surface_last_changed"),
      stale: booleanOrUnknownField(value, "stale")
    })),
    task_compatibility: objectField(body, "task_compatibility", (value) => ({
      supported: booleanOrUnknownField(value, "supported"),
      expected_steps: integerOrUnknownField(value, "expected_steps"),
      recipe_available: booleanField(value, "recipe_available"),
      alternatives: stringArrayField(value, "alternatives")
    })),
    known_blockers: arrayField(body, "known_blockers", (value) => objectField({ value }, "value", (blocker) => ({
      kind: stringField(blocker, "kind"),
      since: stringOrUnknownField(blocker, "since"),
      n: integerOrUnknownField(blocker, "n"),
      persistent: booleanOrUnknownField(blocker, "persistent")
    }))),
    user_present: objectField(body, "user_present", (value) => ({
      required: booleanOrUnknownField(value, "required"),
      reasons: stringArrayField(value, "reasons"),
      irreversible_action: booleanOrUnknownField(value, "irreversible_action")
    })),
    agent_instruction: stringField(body, "agent_instruction"),
    evidence: objectField(body, "evidence", (value) => ({
      sources: numberMapField(value, "sources"),
      canonical_url: stringField(value, "canonical_url"),
      dispute_url: stringField(value, "dispute_url")
    })),
    publisher: objectField(body, "publisher", (value) => ({
      claimed: booleanField(value, "claimed"),
      statement: nullableStringField(value, "statement")
    })),
    how_to_improve: nullableStringField(body, "how_to_improve")
  };
}

function inferHandoffLikelihood(verdict: RecommendationCode | "unknown", blockers: string[], shouldAttemptAutonomously: boolean): HandoffLikelihood {
  if (verdict === "use_browser_with_user_present") {
    return "high";
  }
  if (blockers.some((blocker) => /(?:auth|login|mfa|2fa|payment|identity|user_present|handoff|final_confirmation)/i.test(blocker))) {
    return "medium";
  }
  if (shouldAttemptAutonomously) {
    return "low";
  }
  return "unknown";
}

function failOpenTrustRecord(site: string, task: string | null, warning: string, logger: Pick<Console, "warn">): FailOpenTrustRecord {
  logger.warn(warning);
  return {
    atr_version: "0.1",
    site,
    task,
    issued_at: null,
    record_id: null,
    verdict: "unknown",
    confidence: 0,
    accessibility: {
      reachable: "unknown",
      agent_hostility: "unknown",
      success_rate: "unknown",
      handoff_rate: "unknown",
      blocked_rate: "unknown",
      n: 0,
      last_verified: null
    },
    safety: {
      canonical: "unknown",
      canonical_alternative: null,
      domain_risk: "unknown",
      notes: []
    },
    freshness: {
      median_evidence_age_days: null,
      surface_last_changed: null,
      stale: "unknown"
    },
    task_compatibility: {
      supported: "unknown",
      expected_steps: "unknown",
      recipe_available: false,
      alternatives: []
    },
    known_blockers: [],
    user_present: {
      required: "unknown",
      reasons: [],
      irreversible_action: "unknown"
    },
    agent_instruction: "CrawlDex trust record unavailable. Fail open for caller control, but treat the site-task as unknown and use caution before acting.",
    evidence: {
      sources: {},
      canonical_url: "",
      dispute_url: ""
    },
    publisher: {
      claimed: false,
      statement: null
    },
    how_to_improve: null,
    failOpen: true,
    warning
  };
}

function failOpenPreflight(warning: string, response: PreflightResponse | undefined, logger: Pick<Console, "warn">): PreflightVerdict {
  logger.warn(warning);
  return {
    verdict: "unknown",
    outcome_rate: null,
    outcomeRate: null,
    blockers: [],
    handoff_likelihood: "unknown",
    handoffLikelihood: "unknown",
    freshness: unknownFreshness(),
    should_attempt_autonomously: false,
    shouldAttemptAutonomously: false,
    risk_level: "unknown",
    riskLevel: "unknown",
    response,
    warning
  };
}

function failOpenReport(warning: string, endpoint: string, payload: RunReportPayload, logger: Pick<Console, "warn">): FailOpenSubmissionReceipt {
  logger.warn(warning);
  return {
    accepted: false,
    failOpen: true,
    endpoint,
    warning,
    payload
  };
}

function unknownFreshness(): FreshnessSummary {
  return {
    updated_at: null,
    age_days: null,
    status: "unknown",
    rationale: "Preflight freshness was unavailable."
  };
}

function canonicalizeObjectLike(value: object, path: string, seen: WeakSet<object>): string {
  if (value instanceof Date) {
    throw new Error(`Cannot canonicalize Date at ${path}; pass an ISO string instead.`);
  }
  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) {
    throw new Error(`Cannot canonicalize binary data at ${path}; hash bytes directly instead.`);
  }
  if (seen.has(value)) {
    throw new Error(`Cannot canonicalize circular reference at ${path}.`);
  }

  seen.add(value);
  try {
    if (Array.isArray(value)) {
      const entries: string[] = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!(index in value)) {
          throw new Error(`Cannot canonicalize sparse array hole at ${path}[${index}].`);
        }
        entries.push(serializeJsonValue(value[index], `${path}[${index}]`, seen));
      }
      return `[${entries.join(",")}]`;
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error(`Cannot canonicalize non-plain object at ${path}.`);
    }

    const entries = Object.keys(value as Record<string, unknown>)
      .sort()
      .map((key) => {
        const child = (value as Record<string, unknown>)[key];
        if (child === undefined) {
          throw new Error(`Cannot canonicalize undefined at ${path}.${key}.`);
        }
        return `${JSON.stringify(key)}:${serializeJsonValue(child, `${path}.${key}`, seen)}`;
      });
    return `{${entries.join(",")}}`;
  } finally {
    seen.delete(value);
  }
}

function serializeJsonValue(value: unknown, path: string, seen: WeakSet<object>): string {
  if (value === null) {
    return "null";
  }
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) {
        throw new Error(`Cannot canonicalize non-finite number at ${path}.`);
      }
      return JSON.stringify(value);
    case "string":
      return JSON.stringify(value);
    case "object":
      return canonicalizeObjectLike(value, path, seen);
    case "undefined":
      throw new Error(`Cannot canonicalize undefined at ${path}.`);
    case "bigint":
      throw new Error(`Cannot canonicalize bigint at ${path}.`);
    case "function":
      throw new Error(`Cannot canonicalize function at ${path}.`);
    case "symbol":
      throw new Error(`Cannot canonicalize symbol at ${path}.`);
    default:
      throw new Error(`Cannot canonicalize value at ${path}.`);
  }
}

function redactValue(value: unknown, path: string, removed: Set<string>, sensitiveKeys: RegExp): unknown {
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    return value;
  }
  if (typeof value === "string") {
    return redactString(value);
  }
  if (Array.isArray(value)) {
    return value.map((item, index) => redactValue(item, `${path}[${index}]`, removed, sensitiveKeys));
  }
  if (typeof value === "object") {
    const output: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      const childPath = `${path}.${key}`;
      sensitiveKeys.lastIndex = 0;
      if (sensitiveKeys.test(key)) {
        removed.add(childPath);
        output[key] = "[redacted]";
      } else {
        output[key] = redactValue(child, childPath, removed, sensitiveKeys);
      }
    }
    return output;
  }
  removed.add(path);
  return "[redacted]";
}

function redactString(value: string): string {
  let redacted = value.replace(URL_WITH_QUERY, (url) => stripUrlQuery(url));
  redacted = redacted.replace(EMAIL_PATTERN, "[redacted-email]");
  for (const pattern of SECRET_STRING_PATTERNS) {
    redacted = redacted.replace(pattern, "[redacted]");
  }
  return stripControlChars(redacted);
}

function redactOptional(value: string | undefined): string | undefined {
  return value === undefined ? undefined : redactString(value);
}

function chooseAlias<T>(input: object, camel: string, snake: string): T | undefined {
  const record = input as Record<string, unknown>;
  const camelValue = record[camel];
  const snakeValue = record[snake];
  if (camelValue !== undefined && snakeValue !== undefined && JSON.stringify(camelValue) !== JSON.stringify(snakeValue)) {
    throw new Error(`Conflicting values supplied for ${camel} and ${snake}.`);
  }
  return (camelValue ?? snakeValue) as T | undefined;
}

function setText<T extends Record<string, unknown>>(target: T, key: string, value: string | undefined, max: number, optionalEmpty = false): void {
  if (value === undefined || (optionalEmpty && value === "")) {
    return;
  }
  target[key as keyof T] = validateText(key, value, max) as T[keyof T];
}

function setNumber(
  target: RunReportPayload,
  key: "steps" | "duration_sec" | "token_cost_usd" | "access_fee_usd",
  value: number | undefined,
  options: { integer?: boolean } = {}
): void {
  if (value !== undefined) {
    validateFiniteNonNegative(key, value, options.integer ?? false);
    target[key] = value;
  }
}

function validateText(name: string, value: string, max: number): string {
  const clean = stripControlChars(value).trim();
  if (clean.length < 1 || clean.length > max) {
    throw new Error(`${name} must be 1 to ${max} characters after control-character stripping.`);
  }
  return clean;
}

function validateFiniteNonNegative(name: string, value: number, integer: boolean): void {
  if (!Number.isFinite(value) || value < 0 || (integer && !Number.isInteger(value))) {
    throw new Error(`${name} must be a ${integer ? "non-negative integer" : "non-negative number"}.`);
  }
}

function validateEnum<T extends readonly string[]>(name: string, value: unknown, values: T): T[number] {
  if (typeof value === "string" && values.includes(value)) {
    return value as T[number];
  }
  throw new Error(`${name} must be one of: ${values.join(", ")}.`);
}

function validateIsoDateTime(name: string, value: string): void {
  if (Number.isNaN(Date.parse(value)) || !/(Z|[+-]\d{2}:\d{2})$/.test(value)) {
    throw new Error(`${name} must be an ISO 8601 datetime string with timezone offset.`);
  }
}

function stripControlChars(value: string): string {
  return value.replace(CONTROL_CHARS, "");
}

function buildHeaders(agentKey: string | undefined, ingestToken: string | undefined): HeadersInit {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    ...crawldexClientHeaders()
  };
  if (agentKey) {
    headers["x-crawldex-agent-key"] = agentKey;
  } else if (ingestToken) {
    headers["x-crawldex-ingest-token"] = ingestToken;
  }
  return headers;
}

async function fetchWithFallback(
  fetchImpl: typeof fetch,
  endpoints: string[],
  init: RequestInit,
  timeoutMs: number
): Promise<{ response: Response; endpoint: string }> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown;

  for (let index = 0; index < endpoints.length; index += 1) {
    const endpoint = endpoints[index];
    const remainingMs = timeoutMs > 0 ? deadline - Date.now() : timeoutMs;
    if (timeoutMs > 0 && remainingMs <= 0) {
      throw timeoutErrorForRequest(timeoutMs);
    }

    try {
      const response = await fetchWithTimeout(fetchImpl, endpoint, init, remainingMs);
      if (await isChallengeResponse(response) && index < endpoints.length - 1) {
        continue;
      }
      return { response, endpoint };
    } catch (error) {
      lastError = error;
      if (isTimeoutError(error) || index === endpoints.length - 1) {
        throw error;
      }
    }
  }

  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

async function fetchWithTimeout(fetchImpl: typeof fetch, endpoint: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  if (timeoutMs <= 0) {
    return fetchImpl(endpoint, init);
  }

  const controller = new AbortController();
  let timedOut = false;
  let timeoutError: Error | undefined;
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const timeoutPromise = new Promise<Response>((_resolve, reject) => {
    timeout = setTimeout(() => {
      timedOut = true;
      timeoutError = timeoutErrorForRequest(timeoutMs);
      controller.abort(timeoutError);
      reject(timeoutError);
    }, timeoutMs);
  });
  timeout?.unref?.();

  try {
    return await Promise.race([
      fetchImpl(endpoint, {
        ...init,
        signal: controller.signal
      }).catch((error: unknown) => {
        if (timedOut && timeoutError) {
          throw timeoutError;
        }
        throw error;
      }),
      timeoutPromise
    ]);
  } finally {
    if (timeout) {
      clearTimeout(timeout);
    }
  }
}

async function isChallengeResponse(response: Response): Promise<boolean> {
  if (response.status !== 403) {
    return false;
  }
  const mitigated = response.headers.get("x-vercel-mitigated")?.trim();
  if (mitigated && mitigated !== "none") {
    return true;
  }
  try {
    const body = await response.clone().text();
    return /vercel/i.test(body) && /(security checkpoint|challenge|bot protection)/i.test(body);
  } catch {
    return false;
  }
}

function timeoutErrorForRequest(timeoutMs: number): Error {
  const error = new Error(`CrawlDex request timed out after ${timeoutMs}ms.`);
  error.name = "AbortError";
  return error;
}

function isTimeoutError(error: unknown): boolean {
  return error instanceof Error
    && (error.name === "AbortError" || /timed out|aborted/i.test(error.message));
}

async function readJsonResponse(response: Response, endpoint: string): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? "";
  const text = await response.text();
  if (!isJsonContentType(contentType)) {
    throw new Error(`HTTP ${response.status} non-JSON response from ${endpoint} (${contentType || "missing content-type"}): ${truncateBody(text)}`);
  }
  if (!text) {
    throw new Error(`HTTP ${response.status} empty JSON response from ${endpoint}.`);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`HTTP ${response.status} invalid JSON response from ${endpoint}: ${truncateBody(text)}`);
  }
}

async function readRawBodyPreview(response: Response): Promise<string> {
  try {
    return truncateBody(await response.text());
  } catch {
    return "response body unavailable";
  }
}

function isJsonContentType(contentType: string): boolean {
  const normalized = contentType.toLowerCase();
  return normalized.includes("application/json") || normalized.includes("+json");
}

function truncateBody(text: string): string {
  const clean = stripControlChars(text).trim();
  if (!clean) {
    return "empty response body";
  }
  return clean.length > RESPONSE_BODY_PREVIEW_CHARS ? `${clean.slice(0, RESPONSE_BODY_PREVIEW_CHARS)}...` : clean;
}

function receiptFromResponse(endpoint: string, payload: RunReportPayload, body: unknown): SubmissionReceipt {
  const response = body as {
    run?: {
      id?: string;
      source_tier?: string;
      reporter?: { id?: string };
      trust?: { level?: string };
    };
    updated_status?: { aes?: number | null };
  };
  const sourceTier = response.run?.source_tier ?? null;
  return {
    accepted: true,
    acceptance: sourceTier === "attested_sdk" || sourceTier === "synthetic_canary" ? "trusted" : "anonymous",
    endpoint,
    runId: response.run?.id ?? null,
    sourceTier,
    reporterId: response.run?.reporter?.id ?? null,
    trustLevel: response.run?.trust?.level ?? null,
    updatedAes: response.updated_status?.aes ?? null,
    payload
  };
}

function dryRunReceipt(payload: RunReportPayload, endpoint: string): SubmissionReceipt {
  return {
    accepted: true,
    acceptance: "dry_run",
    endpoint,
    runId: null,
    sourceTier: payload.source_tier ?? null,
    reporterId: null,
    trustLevel: null,
    updatedAes: null,
    payload,
    warning: "Dry run enabled; no report was submitted."
  };
}

function buildEchoPayload(recordId: string, action: CrawlDexEchoAction, taskAttempted: boolean): DecisionEchoPayload {
  const cleanRecordId = validateText("recordId", recordId, 128);
  if (!ECHO_RECORD_ID_PATTERN.test(cleanRecordId)) {
    throw new Error("recordId must be an Agent Trust Record id like atr_0123456789abcdef.");
  }
  return {
    record_id: cleanRecordId,
    action_taken: validateEnum("action", action, CRAWLDEX_ECHO_ACTIONS),
    task_attempted: Boolean(taskAttempted)
  };
}

function skippedEcho(warning: string, endpoint: string, payload: DecisionEchoPayload | null): SkippedEchoReceipt {
  return {
    accepted: false,
    skipped: true,
    endpoint,
    warning,
    payload
  };
}

function failOpenEcho(
  warning: string,
  endpoint: string,
  payload: DecisionEchoPayload,
  logger: Pick<Console, "warn">
): FailOpenEchoReceipt {
  logger.warn(warning);
  return {
    accepted: false,
    failOpen: true,
    endpoint,
    warning,
    payload
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function objectField<T>(record: Record<string, unknown>, key: string, map: (value: Record<string, unknown>) => T): T {
  const value = record[key];
  if (!isRecord(value)) {
    throw new Error(`${key} must be an object.`);
  }
  return map(value);
}

function arrayField<T>(record: Record<string, unknown>, key: string, map: (value: unknown) => T): T[] {
  const value = record[key];
  if (!Array.isArray(value)) {
    throw new Error(`${key} must be an array.`);
  }
  return value.map(map);
}

function stringField(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== "string") {
    throw new Error(`${key} must be a string.`);
  }
  return value;
}

function nullableStringField(record: Record<string, unknown>, key: string): string | null {
  const value = record[key];
  if (value === null) {
    return null;
  }
  if (typeof value !== "string") {
    throw new Error(`${key} must be a string or null.`);
  }
  return value;
}

function literalField<T extends string>(record: Record<string, unknown>, key: string, expected: T): T {
  const value = record[key];
  if (value !== expected) {
    throw new Error(`${key} must be ${expected}.`);
  }
  return expected;
}

function enumField<T extends readonly string[]>(record: Record<string, unknown>, key: string, values: T): T[number] {
  return validateEnum(key, record[key], values);
}

function booleanField(record: Record<string, unknown>, key: string): boolean {
  const value = record[key];
  if (typeof value !== "boolean") {
    throw new Error(`${key} must be a boolean.`);
  }
  return value;
}

function booleanOrUnknownField(record: Record<string, unknown>, key: string): boolean | "unknown" {
  const value = record[key];
  if (typeof value === "boolean" || value === "unknown") {
    return value;
  }
  throw new Error(`${key} must be a boolean or unknown.`);
}

function stringOrUnknownField(record: Record<string, unknown>, key: string): string | "unknown" {
  const value = record[key];
  if (typeof value === "string") {
    return value;
  }
  throw new Error(`${key} must be a string.`);
}

function ratioField(record: Record<string, unknown>, key: string): number {
  const value = record[key];
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) {
    throw new Error(`${key} must be a number from 0 to 1.`);
  }
  return value;
}

function ratioOrUnknownField(record: Record<string, unknown>, key: string): number | "unknown" {
  const value = record[key];
  if (value === "unknown") {
    return value;
  }
  return ratioField(record, key);
}

function nonNegativeIntegerField(record: Record<string, unknown>, key: string): number {
  const value = record[key];
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new Error(`${key} must be a non-negative integer.`);
  }
  return value;
}

function nullableNonNegativeIntegerField(record: Record<string, unknown>, key: string): number | null {
  const value = record[key];
  if (value === null) {
    return null;
  }
  return nonNegativeIntegerField(record, key);
}

function integerOrUnknownField(record: Record<string, unknown>, key: string): number | "unknown" {
  const value = record[key];
  if (value === "unknown") {
    return value;
  }
  return nonNegativeIntegerField(record, key);
}

function stringArrayField(record: Record<string, unknown>, key: string): string[] {
  return arrayField(record, key, (value) => {
    if (typeof value !== "string") {
      throw new Error(`${key} entries must be strings.`);
    }
    return value;
  });
}

function numberMapField(record: Record<string, unknown>, key: string): Record<string, number> {
  const value = record[key];
  if (!isRecord(value)) {
    throw new Error(`${key} must be an object.`);
  }
  const output: Record<string, number> = {};
  for (const [entryKey, entryValue] of Object.entries(value)) {
    if (typeof entryValue !== "number" || !Number.isInteger(entryValue) || entryValue < 0) {
      throw new Error(`${key}.${entryKey} must be a non-negative integer.`);
    }
    output[entryKey] = entryValue;
  }
  return output;
}

function resolvePreflightEndpoints(
  reportEndpoint: string | undefined,
  explicitPreflightEndpoint: string | undefined,
  apiOrigins: string[]
): string[] {
  if (explicitPreflightEndpoint) {
    return [explicitPreflightEndpoint];
  }
  if (reportEndpoint) {
    try {
      const url = new URL(reportEndpoint);
      if (url.pathname.endsWith("/api/v1/runs")) {
        url.pathname = url.pathname.replace(/\/api\/v1\/runs$/, "/api/v1/preflight");
        url.search = "";
        url.hash = "";
        return [url.toString()];
      }
      return [new URL("/api/v1/preflight", url.origin).toString()];
    } catch {
      return [];
    }
  }

  return endpointCandidates(apiOrigins, "/api/v1/preflight");
}

function resolveTrustRecordEndpoints(input: {
  explicitTrustRecordEndpoint: string | undefined;
  apiOriginCandidates: string[];
  site: string;
  task: string | null;
}): string[] {
  const encodedSite = encodeURIComponent(input.site);
  const encodedTask = input.task ? `/${encodeURIComponent(input.task)}` : "";
  const suffix = `${encodedSite}${encodedTask}`;

  if (input.explicitTrustRecordEndpoint) {
    const endpoint = normalizeTrustRecordEndpoint(input.explicitTrustRecordEndpoint, suffix);
    return endpoint ? [endpoint] : [];
  }

  return endpointCandidates(input.apiOriginCandidates, `/api/v1/trust-record/${suffix}`);
}

function resolveEchoEndpoints(input: {
  explicitEchoEndpoint: string | undefined;
  apiOriginCandidates: string[];
  reportEndpoint: string | undefined;
}): string[] {
  if (input.explicitEchoEndpoint) {
    try {
      const url = new URL(input.explicitEchoEndpoint);
      url.search = "";
      url.hash = "";
      url.pathname = "/api/v1/echo";
      return [url.toString()];
    } catch {
      return [];
    }
  }

  if (input.reportEndpoint && input.apiOriginCandidates.length === 0) {
    const origin = originFromEndpoint(input.reportEndpoint);
    return origin ? endpointCandidates([origin], "/api/v1/echo") : [];
  }

  return endpointCandidates(input.apiOriginCandidates, "/api/v1/echo");
}

function normalizeTrustRecordEndpoint(endpoint: string, suffix: string): string | null {
  try {
    const url = new URL(endpoint);
    url.search = "";
    url.hash = "";
    const normalized = url.pathname.replace(/\/+$/, "");
    if (/\/api\/v1\/trust-record(?:\/.*)?$/.test(normalized)) {
      url.pathname = normalized.endsWith("/trust-record") ? `${normalized}/${suffix}` : normalized;
    } else {
      url.pathname = `/api/v1/trust-record/${suffix}`;
    }
    return url.toString();
  } catch {
    return null;
  }
}

function resolveApiOrigins(explicitApiOrigin: string | undefined, reportEndpoint: string | undefined): string[] {
  const configured = normalizeOrigin(explicitApiOrigin) ?? originFromEndpoint(reportEndpoint);
  const defaults = DEFAULT_API_ORIGINS.map((origin) => normalizeOrigin(origin)).filter((origin): origin is string => Boolean(origin));
  return configured ? [configured, ...defaults.filter((origin) => origin !== configured)] : defaults;
}

function endpointCandidates(origins: string[], path: string): string[] {
  return origins
    .map((origin) => {
      try {
        const url = new URL(origin);
        url.pathname = path;
        url.search = "";
        url.hash = "";
        return url.toString();
      } catch {
        return null;
      }
    })
    .filter((endpoint): endpoint is string => endpoint !== null);
}

function normalizeOrigin(value: string | undefined): string | null {
  if (!value) {
    return null;
  }
  try {
    const url = new URL(value);
    url.pathname = "";
    url.search = "";
    url.hash = "";
    return url.origin;
  } catch {
    return null;
  }
}

function originFromEndpoint(endpoint: string | undefined): string | undefined {
  if (!endpoint) {
    return undefined;
  }
  try {
    return new URL(endpoint).origin;
  } catch {
    return undefined;
  }
}


function getEnv(): Record<string, string | undefined> {
  return typeof process === "undefined" ? {} : process.env;
}

function errorSummary(error: unknown): string {
  if (error instanceof Error && error.message) {
    return error.message;
  }
  return "network error";
}

export { reportStagehandRun } from "./adapters/stagehand.js";
export { withPlaywright } from "./adapters/playwright.js";
