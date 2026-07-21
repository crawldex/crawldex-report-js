import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  canonicalJson,
  createReporter,
  echo,
  hashEvidenceArtifact,
  mapToRunReport,
  redactEvidenceArtifact,
  trustRecord,
  trustRecordFromResponse
} from "./index.js";
import { buildOpenApiDocument } from "../../../src/server/openapi.js";

let testHome: string | null = null;

beforeEach(() => {
  testHome = mkdtempSync(join(tmpdir(), "crawldex-report-js-test-"));
  vi.stubEnv("HOME", testHome);
  vi.stubEnv("XDG_CONFIG_HOME", join(testHome, ".config"));
  vi.stubEnv("APPDATA", join(testHome, "AppData", "Roaming"));
});

afterEach(() => {
  vi.unstubAllEnvs();
  if (testHome) {
    rmSync(testHome, { recursive: true, force: true });
    testHome = null;
  }
});

describe("crawldex-report JavaScript SDK", () => {
  it("maps reportOutcome input to exact /api/v1/runs fields", () => {
    const payload = mapToRunReport({
      site: "demo-shop.crawldex.com",
      task: "commerce.checkout",
      recordId: "atr_0123456789abcdef",
      agentProfile: {
        stack: "playwright",
        browserRuntime: "chromium",
        identityClass: "anonymous"
      },
      outcome: "success_with_handoff",
      friction: ["login_required"],
      steps: 12,
      durationSec: 94,
      tokenCostUsd: 0.04,
      accessFeeUsd: 0,
      sourceTier: "anonymous_report",
      evidence: {
        id: "ev-demo",
        artifact: {
          signal: "checkout_loaded",
          url: "https://demo-shop.crawldex.com/checkout?token=secret",
          note: "Contact jane@example.com with token=secret"
        },
        artifactTypes: ["redacted_trace"],
        redactionStatus: "redacted"
      },
      occurredAt: "2026-06-08T16:05:12Z"
    });

    expect(payload).toMatchObject({
      site: "demo-shop.crawldex.com",
      task: "commerce.checkout",
      record_id: "atr_0123456789abcdef",
      agent_profile: {
        stack: "playwright",
        browser_runtime: "chromium",
        identity_class: "anonymous",
        capabilities: {
          evidence_redaction: "redacted"
        }
      },
      outcome: "success_with_handoff",
      friction: ["login_required"],
      steps: 12,
      duration_sec: 94,
      token_cost_usd: 0.04,
      access_fee_usd: 0,
      source_tier: "anonymous_report",
      evidence: {
        id: "ev-demo",
        hash: payload.evidence?.hash,
        artifact_types: ["redacted_trace"]
      },
      occurred_at: "2026-06-08T16:05:12Z"
    });
    expect(payload.evidence?.hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(JSON.stringify(payload)).not.toContain("durationSec");
    expect(JSON.stringify(payload)).not.toContain("checkout_loaded");
    expect(JSON.stringify(payload)).not.toContain("secret");
    expect(JSON.stringify(payload)).not.toContain("jane@example.com");
  });

  it("rejects invalid or conflicting ATR record IDs before submission", () => {
    expect(() => mapToRunReport({
      site: "example.com",
      task: "subscriptions.cancel",
      outcome: "blocked",
      record_id: "private-account-reference"
    })).toThrow("recordId must be an Agent Trust Record id");

    expect(() => mapToRunReport({
      site: "example.com",
      task: "subscriptions.cancel",
      outcome: "blocked",
      recordId: "atr_0123456789abcdef",
      record_id: "atr_fedcba9876543210"
    })).toThrow("Conflicting values supplied for recordId and record_id");
  });

  it("fails open for preflight and report network errors", async () => {
    const warnings: string[] = [];
    const fetchMock = vi.fn(async () => {
      throw new Error("connection refused");
    });
    const reporter = createReporter({
      reportUrl: "https://crawldex.test/api/v1/runs",
      fetch: fetchMock as never,
      logger: { warn: (message) => warnings.push(message) }
    });

    const verdict = await reporter.preflight("example.com", "subscriptions.cancel");
    const receipt = await reporter.reportOutcome({
      site: "example.com",
      task: "subscriptions.cancel",
      outcome: "blocked"
    });

    expect(verdict).toMatchObject({
      verdict: "unknown",
      outcome_rate: null,
      handoff_likelihood: "unknown"
    });
    expect(verdict.warning).toContain("connection refused");
    expect(receipt).toMatchObject({
      accepted: false,
      failOpen: true
    });
    expect("warning" in receipt ? receipt.warning : "").toContain("connection refused");
    expect(warnings).toHaveLength(2);
  });

  it("fails open for a 200 non-JSON report response", async () => {
    const warnings: string[] = [];
    const reporter = createReporter({
      reportUrl: "https://crawldex.test/api/v1/runs",
      fetch: vi.fn(async () => new Response("<html>not json</html>", {
        status: 200,
        headers: { "content-type": "text/html; charset=utf-8" }
      })) as never,
      logger: { warn: (message) => warnings.push(message) }
    });

    const receipt = await reporter.reportOutcome({
      site: "example.com",
      task: "subscriptions.cancel",
      outcome: "blocked"
    });

    expect(receipt).toMatchObject({
      accepted: false,
      failOpen: true
    });
    expect("warning" in receipt ? receipt.warning : "").toContain("non-JSON response");
    expect("warning" in receipt ? receipt.warning : "").toContain("<html>not json</html>");
    expect(warnings).toHaveLength(1);
  });

  it("fails open when a report request times out", async () => {
    const warnings: string[] = [];
    const reporter = createReporter({
      reportUrl: "https://crawldex.test/api/v1/runs",
      timeoutMs: 1,
      fetch: vi.fn((_url: string, init: RequestInit) => new Promise<Response>((_resolve, reject) => {
        init.signal?.addEventListener("abort", () => reject(new Error("request aborted by test timeout")));
      })) as never,
      logger: { warn: (message) => warnings.push(message) }
    });

    const receipt = await reporter.reportOutcome({
      site: "example.com",
      task: "subscriptions.cancel",
      outcome: "blocked"
    });

    expect(receipt).toMatchObject({
      accepted: false,
      failOpen: true
    });
    expect("warning" in receipt ? receipt.warning : "").toContain("timed out after 1ms");
    expect(warnings).toHaveLength(1);
  });

  it("redacts query strings, emails, and tokens before deterministic canonical hashing", () => {
    const raw = {
      b: "Visit https://example.com/account?session=secret#frag",
      a: {
        note: "Email jane@example.com Authorization: Bearer secret-token",
        token: "secret"
      }
    };
    const rawReordered = {
      a: {
        token: "secret",
        note: "Email jane@example.com Authorization: Bearer secret-token"
      },
      b: "Visit https://example.com/account?session=secret#frag"
    };

    const redacted = redactEvidenceArtifact(raw, { redactionStatus: "redacted" });
    const redactedReordered = redactEvidenceArtifact(rawReordered, { redactionStatus: "redacted" });
    const serialized = canonicalJson(redacted);

    expect(serialized).toContain("https://example.com/account");
    expect(serialized).not.toContain("session=secret");
    expect(serialized).not.toContain("jane@example.com");
    expect(serialized).not.toContain("secret-token");
    expect(serialized).not.toContain("\"secret\"");
    expect(redacted.removed_fields).toContain("$.a.token");
    expect(hashEvidenceArtifact(redacted)).toBe(hashEvidenceArtifact(redactedReordered));
  });

  it("maps successful preflight responses into a typed verdict", async () => {
    const reporter = createReporter({
      reportUrl: "https://crawldex.test/api/v1/runs",
      fetch: vi.fn(async (url: string, init: RequestInit) => {
        expect(url).toBe("https://crawldex.test/api/v1/preflight");
        expect(JSON.parse(init.body as string)).toMatchObject({
          site: "demo-shop.crawldex.com",
          task: "commerce.checkout"
        });
        return new Response(JSON.stringify({
          site: "demo-shop.crawldex.com",
          task: "commerce.checkout",
          decision: {
            recommendation: "use_browser_with_user_present",
            risk_level: "medium",
            should_attempt_autonomously: false,
            rationale: "Login is expected."
          },
          score: {
            outcome_rate: 0.82,
            known_blockers: ["login_required"]
          },
          freshness: {
            updated_at: "2026-06-08T16:05:12Z",
            age_days: 4,
            status: "fresh"
          }
        }), { status: 200, headers: { "content-type": "application/json" } });
      }) as never,
      logger: { warn: vi.fn() }
    });

    await expect(reporter.preflight("demo-shop.crawldex.com", "commerce.checkout")).resolves.toMatchObject({
      verdict: "use_browser_with_user_present",
      outcome_rate: 0.82,
      blockers: ["login_required"],
      handoff_likelihood: "high",
      freshness: {
        status: "fresh"
      }
    });
  });

  it("fetches an Agent Trust Record through the fail-open reporter client", async () => {
    const reporter = createReporter({
      apiOrigin: "https://crawldex.test",
      fetch: vi.fn(async (url: string, init: RequestInit) => {
        expect(url).toBe("https://crawldex.test/api/v1/trust-record/netflix.com/subscriptions.cancel");
        expect(init.method).toBe("GET");
        return jsonResponse(trustRecordFixture());
      }) as never,
      logger: { warn: vi.fn() }
    });

    await expect(reporter.trustRecord("netflix.com", "subscriptions.cancel")).resolves.toMatchObject({
      atr_version: "0.1",
      site: "netflix.com",
      task: "subscriptions.cancel",
      record_id: "atr_0123456789abcdef",
      verdict: "user_needed",
      confidence: 0.63
    });
  });

  it("falls back to the Plan B origin chain when a trustRecord origin is unreachable", async () => {
    const fetchMock = vi.fn(async (url: string, init: RequestInit) => {
      expect(init.method).toBe("GET");
      if (url === "https://first.test/api/v1/trust-record/netflix.com/subscriptions.cancel") {
        throw new Error("getaddrinfo ENOTFOUND first.test");
      }
      if (url === "https://api.crawldex.com/api/v1/trust-record/netflix.com/subscriptions.cancel") {
        return jsonResponse(trustRecordFixture());
      }
      throw new Error(`unexpected URL ${url}`);
    });
    const reporter = createReporter({
      apiOrigin: "https://first.test",
      fetch: fetchMock as never,
      logger: { warn: vi.fn() }
    });

    await expect(reporter.trustRecord("netflix.com", "subscriptions.cancel")).resolves.toMatchObject({
      record_id: "atr_0123456789abcdef"
    });
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "https://first.test/api/v1/trust-record/netflix.com/subscriptions.cancel",
      "https://api.crawldex.com/api/v1/trust-record/netflix.com/subscriptions.cancel"
    ]);
  });

  it("uses CRAWLDEX_API_ORIGIN as the head of the default origin chain", async () => {
    vi.stubEnv("CRAWLDEX_API_ORIGIN", "https://env-origin.test");
    const fetchMock = vi.fn(async (url: string) => {
      expect(url).toBe("https://env-origin.test/api/v1/trust-record/netflix.com/subscriptions.cancel");
      return jsonResponse(trustRecordFixture());
    });

    await expect(trustRecord("netflix.com", "subscriptions.cancel", {
      fetch: fetchMock as never,
      logger: { warn: vi.fn() }
    })).resolves.toMatchObject({
      record_id: "atr_0123456789abcdef"
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("posts a direct decision echo payload", async () => {
    vi.stubEnv("CRAWLDEX_CHANNEL", "Adapter-Playwright");
    const fetchMock = vi.fn(async (url: string, init: RequestInit) => {
      expect(url).toBe("https://crawldex.test/api/v1/echo");
      expect(init.method).toBe("POST");
      expect(init.headers).toMatchObject({
        "x-crawldex-instance": expect.stringMatching(/^[0-9a-f-]{36}$/),
        "x-crawldex-channel": "adapter-playwright"
      });
      expect(JSON.parse(init.body as string)).toEqual({
        record_id: "atr_0123456789abcdef",
        action_taken: "overrode",
        task_attempted: false,
        removed_in_batch: true
      });
      return jsonResponse({ status: "accepted" }, 202);
    });

    await expect(echo("atr_0123456789abcdef", "overrode", {
      apiOrigin: "https://crawldex.test",
      taskAttempted: false,
      removedInBatch: true,
      fetch: fetchMock as never,
      logger: { warn: vi.fn() }
    })).resolves.toMatchObject({
      accepted: true,
      endpoint: "https://crawldex.test/api/v1/echo"
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("rejects a non-boolean batch-removal signal before sending", async () => {
    const fetchMock = vi.fn();

    await expect(echo("atr_0123456789abcdef", "followed", {
      apiOrigin: "https://crawldex.test",
      removedInBatch: "private reason" as unknown as boolean,
      fetch: fetchMock as never,
      logger: { warn: vi.fn() }
    })).rejects.toThrow("removedInBatch must be a boolean");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("persists anonymous instance IDs across SDK calls", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({
      site: "netflix.com",
      task: "subscriptions.cancel",
      decision: {
        recommendation: "collect_evidence_first",
        risk_level: "unknown",
        should_attempt_autonomously: false,
        rationale: "fixture"
      }
    }));
    const reporter = createReporter({
      apiOrigin: "https://crawldex.test",
      fetch: fetchMock as never,
      logger: { warn: vi.fn() }
    });

    await reporter.preflight("netflix.com", "subscriptions.cancel");
    await reporter.preflight("netflix.com", "subscriptions.cancel");

    const headers = fetchMock.mock.calls.map(([, init]) => init?.headers as Record<string, string>);
    expect(headers[0]?.["x-crawldex-instance"]).toMatch(/^[0-9a-f-]{36}$/);
    expect(headers[1]?.["x-crawldex-instance"]).toBe(headers[0]?.["x-crawldex-instance"]);
    expect(existsSync(join(testHome ?? "", ".config", "crawldex", "instance-id"))).toBe(true);
  });

  it("falls back after a Vercel challenge for direct echo writes", async () => {
    const fetchMock = vi.fn(async (url: string) => {
      if (url === "https://first.test/api/v1/echo") {
        return new Response("<html>Vercel Security Checkpoint challenge</html>", {
          status: 403,
          headers: {
            "content-type": "text/html",
            "x-vercel-mitigated": "challenge"
          }
        });
      }
      if (url === "https://api.crawldex.com/api/v1/echo") {
        return jsonResponse({ status: "accepted" }, 202);
      }
      throw new Error(`unexpected URL ${url}`);
    });

    await expect(echo("atr_0123456789abcdef", "followed", {
      apiOrigin: "https://first.test",
      fetch: fetchMock as never,
      logger: { warn: vi.fn() }
    })).resolves.toMatchObject({
      accepted: true,
      endpoint: "https://api.crawldex.com/api/v1/echo"
    });
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "https://first.test/api/v1/echo",
      "https://api.crawldex.com/api/v1/echo"
    ]);
  });

  it("does not fail over direct echo writes after an ordinary HTTP error", async () => {
    const warnings: string[] = [];
    const fetchMock = vi.fn(async () => jsonResponse({ error: "server_error" }, 500));

    await expect(echo("atr_0123456789abcdef", "followed", {
      apiOrigin: "https://first.test",
      fetch: fetchMock as never,
      logger: { warn: (message) => warnings.push(message) }
    })).resolves.toMatchObject({
      accepted: false,
      failOpen: true,
      endpoint: "https://first.test/api/v1/echo"
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(warnings[0]).toContain("HTTP 500");
  });

  it("keeps autoReport off by default and makes no extra echo request", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({
      run: { id: "run_default", source_tier: "anonymous_report" }
    }));
    const reporter = createReporter({
      reportUrl: "https://crawldex.test/api/v1/runs",
      fetch: fetchMock as never,
      logger: { warn: vi.fn() }
    });

    await reporter.reportOutcome({
      site: "example.com",
      task: "subscriptions.cancel",
      outcome: "blocked",
      recordId: "atr_0123456789abcdef"
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("https://crawldex.test/api/v1/runs");
    expect(JSON.parse(fetchMock.mock.calls[0]?.[1]?.body as string)).toMatchObject({
      record_id: "atr_0123456789abcdef"
    });
  });

  it("autoReport emits echo after submitting a redacted outcome report", async () => {
    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith("/api/v1/echo")) {
        return jsonResponse({ status: "accepted" }, 202);
      }
      return jsonResponse({
        run: { id: "run_auto", source_tier: "anonymous_report" }
      });
    });
    const reporter = createReporter({
      reportUrl: "https://crawldex.test/api/v1/runs",
      autoReport: true,
      fetch: fetchMock as never,
      logger: { warn: vi.fn() }
    });

    await reporter.reportOutcome({
      site: "example.com",
      task: "subscriptions.cancel",
      outcome: "success_with_handoff",
      record_id: "atr_0123456789abcdef",
      removedInBatch: true,
      evidence: {
        artifact: {
          url: "https://example.com/account?token=secret",
          email: "jane@example.com",
          authorization: "Bearer secret-token"
        },
        redactionStatus: "redacted"
      }
    });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const reportBody = JSON.parse(fetchMock.mock.calls[0]?.[1]?.body as string) as Record<string, unknown>;
    const echoBody = JSON.parse(fetchMock.mock.calls[1]?.[1]?.body as string);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("https://crawldex.test/api/v1/runs");
    expect(fetchMock.mock.calls[1]?.[0]).toBe("https://crawldex.test/api/v1/echo");
    expect(reportBody.record_id).toBe("atr_0123456789abcdef");
    expect(JSON.stringify(reportBody)).toContain("sha256:");
    expect(JSON.stringify(reportBody)).not.toContain("jane@example.com");
    expect(JSON.stringify(reportBody)).not.toContain("secret-token");
    expect(JSON.stringify(reportBody)).not.toContain("token=secret");
    expect(echoBody).toEqual({
      record_id: "atr_0123456789abcdef",
      action_taken: "followed",
      task_attempted: true,
      removed_in_batch: true
    });
  });

  it("honors CRAWLDEX_NO_INSTANCE_ID by omitting instance headers without suppressing autoReport echo", async () => {
    vi.stubEnv("CRAWLDEX_NO_INSTANCE_ID", "1");
    const fetchMock = vi.fn(async () => jsonResponse({
      run: { id: "run_opt_out", source_tier: "anonymous_report" }
    }));
    const reporter = createReporter({
      reportUrl: "https://crawldex.test/api/v1/runs",
      autoReport: true,
      fetch: fetchMock as never,
      logger: { warn: vi.fn() }
    });

    await reporter.reportOutcome({
      site: "example.com",
      task: "subscriptions.cancel",
      outcome: "blocked",
      recordId: "atr_0123456789abcdef"
    });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("https://crawldex.test/api/v1/runs");
    expect(fetchMock.mock.calls[1]?.[0]).toBe("https://crawldex.test/api/v1/echo");
    expect(fetchMock.mock.calls[0]?.[1]?.headers).not.toHaveProperty("x-crawldex-instance");
    expect(fetchMock.mock.calls[1]?.[1]?.headers).not.toHaveProperty("x-crawldex-instance");
    expect(existsSync(join(testHome ?? "", ".config", "crawldex", "instance-id"))).toBe(false);
  });

  it("honors CRAWLDEX_NO_INSTANCE_ID by omitting instance headers without suppressing direct echo", async () => {
    vi.stubEnv("CRAWLDEX_NO_INSTANCE_ID", "1");
    const fetchMock = vi.fn(async () => jsonResponse({ status: "accepted" }, 202));

    await expect(echo("atr_0123456789abcdef", "followed", {
      apiOrigin: "https://crawldex.test",
      fetch: fetchMock as never,
      logger: { warn: vi.fn() }
    })).resolves.toMatchObject({
      accepted: true,
      endpoint: "https://crawldex.test/api/v1/echo"
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[1]?.headers).not.toHaveProperty("x-crawldex-instance");
  });

  it("degrades silently when the instance config path is unavailable", async () => {
    if (!testHome) {
      throw new Error("test home was not initialized");
    }
    const blockedConfigPath = join(testHome, "not-a-directory");
    writeFileSync(blockedConfigPath, "");
    vi.stubEnv("XDG_CONFIG_HOME", blockedConfigPath);
    const fetchMock = vi.fn(async () => jsonResponse({
      site: "netflix.com",
      task: "subscriptions.cancel",
      decision: {
        recommendation: "collect_evidence_first",
        risk_level: "unknown",
        should_attempt_autonomously: false,
        rationale: "fixture"
      }
    }));
    const reporter = createReporter({
      apiOrigin: "https://crawldex.test",
      fetch: fetchMock as never,
      logger: { warn: vi.fn() }
    });

    await reporter.preflight("netflix.com", "subscriptions.cancel");

    expect(fetchMock.mock.calls[0]?.[1]?.headers).not.toHaveProperty("x-crawldex-instance");
  });

  it("caps trustRecord at 5s and fails open instead of throwing", async () => {
    vi.useFakeTimers();
    const warnings: string[] = [];
    const reporter = createReporter({
      apiOrigin: "https://crawldex.test",
      timeoutMs: 10_000,
      fetch: vi.fn((_url: string, init: RequestInit) => new Promise<Response>((_resolve, reject) => {
        init.signal?.addEventListener("abort", () => reject(new Error("request aborted by test timeout")));
      })) as never,
      logger: { warn: (message) => warnings.push(message) }
    });

    try {
      const pending = reporter.trustRecord("netflix.com", "subscriptions.cancel");
      await vi.advanceTimersByTimeAsync(5_000);
      const record = await pending;

      expect(record).toMatchObject({
        failOpen: true,
        verdict: "unknown",
        confidence: 0,
        record_id: null
      });
      expect(record.warning).toContain("5000ms");
      expect(warnings).toHaveLength(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("fails open for malformed trustRecord payloads", async () => {
    const warnings: string[] = [];
    const result = await trustRecord("netflix.com", "subscriptions.cancel", {
      apiOrigin: "https://crawldex.test",
      fetch: vi.fn(async () => jsonResponse({ atr_version: "0.1", record_id: "atr_0123456789abcdef" })) as never,
      logger: { warn: (message) => warnings.push(message) }
    });

    expect(result).toMatchObject({
      failOpen: true,
      verdict: "unknown",
      confidence: 0,
      site: "netflix.com",
      task: "subscriptions.cancel"
    });
    expect(result.warning).toContain("site must be a string");
    expect(warnings).toHaveLength(1);
  });

  it("keeps the trustRecord parser aligned with the OpenAPI TrustRecord required fields", () => {
    const document = buildOpenApiDocument({
      baseUrl: "https://crawldex.test",
      generatedAt: "2026-07-02T00:00:00.000Z"
    });
    const schema = document.components.schemas.TrustRecord as {
      required: string[];
      properties: Record<string, unknown>;
    };
    const parsed = trustRecordFromResponse(trustRecordFixture());

    expect(Object.keys(parsed).sort()).toEqual([...schema.required].sort());
    for (const field of schema.required) {
      expect(schema.properties[field], field).toBeDefined();
      expect(parsed[field as keyof typeof parsed], field).not.toBeUndefined();
    }
  });
});

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" }
  });
}

function trustRecordFixture(): unknown {
  return {
    atr_version: "0.1",
    site: "netflix.com",
    task: "subscriptions.cancel",
    issued_at: "2026-07-02T12:00:00.000Z",
    record_id: "atr_0123456789abcdef",
    verdict: "user_needed",
    confidence: 0.63,
    accessibility: {
      reachable: true,
      agent_hostility: "low",
      success_rate: 0.78,
      handoff_rate: "unknown",
      blocked_rate: "unknown",
      n: 2,
      last_verified: "2026-07-02"
    },
    safety: {
      canonical: "unknown",
      canonical_alternative: null,
      domain_risk: "unknown",
      notes: ["Canonicality and domain-risk heuristics are not available until WP-8B."]
    },
    freshness: {
      median_evidence_age_days: 2,
      surface_last_changed: null,
      stale: false
    },
    task_compatibility: {
      supported: true,
      expected_steps: 4,
      recipe_available: true,
      alternatives: ["spotify.com", "hulu.com"]
    },
    known_blockers: [
      { kind: "login_required", since: "unknown", n: "unknown", persistent: "unknown" }
    ],
    user_present: {
      required: true,
      reasons: ["login_required"],
      irreversible_action: true
    },
    agent_instruction: "Keep the user present for authentication and final confirmation.",
    evidence: {
      sources: {
        seeded_example: 2
      },
      canonical_url: "https://crawldex.com/sites/netflix.com/subscriptions.cancel",
      dispute_url: "https://crawldex.com/disputes?record=atr_0123456789abcdef"
    },
    publisher: {
      claimed: false,
      statement: null
    },
    how_to_improve: null
  };
}
