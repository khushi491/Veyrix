import fs from "node:fs";
import path from "node:path";
import committedJson from "../demo/kit-scan.json";
import type { TraceEvent } from "../app/execution-trace";

export const KIT_SCAN_URL =
  "https://raw.githubusercontent.com/khushi491/Veyrix/kit-scans/latest.json";

const WORKFLOW_URL =
  "https://github.com/khushi491/Veyrix/actions/workflows/veyrix-scan.yml";
const CODE_SCANNING_URL =
  "https://github.com/khushi491/Veyrix/security/code-scanning";
const ACTION_DOCS_URL =
  "https://github.com/khushi491/Veyrix/blob/main/docs/github-action.md";
const SARIF_DOCS_URL =
  "https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning";
const DEFAULT_NOTE =
  "The vulnerable document assistant is a deliberately vulnerable local fixture. It is a sample target for the scanner. It is not a finding against the Veyrix product source, and it is not a production agent.";
const MAX_BYTES = 2_000_000;
const RUN_URL =
  /^https:\/\/github\.com\/khushi491\/Veyrix\/actions\/runs\/\d+$/;
const SHA = /^[0-9a-f]{40}$/;

export type KitSource = "github-actions" | "build" | "committed-snapshot";

export type KitFinding = {
  scenario_id: string;
  title: string;
  severity: string;
  outcome?: string | null;
  category?: string;
  actual_behavior?: string;
  expected_behavior?: string;
  remediation?: string;
  evidence_sequences?: number[];
  observed_at?: string | null;
  result?: { events?: TraceEvent[]; evaluation?: { evidence_sequences?: number[] } };
};

export type KitResult = {
  scenario_id: string;
  title?: string;
  severity?: string;
  evaluation?: { status?: string; evidence_sequences?: number[] };
  events: TraceEvent[];
};

export type KitScenario = {
  id: string;
  title?: string;
  severity?: string;
  verdict?: { status?: string };
};

export type KitReport = {
  engine_version: string;
  scoring_version: string;
  generated_at: string;
  target: { name: string; adapter: string; variant: string; suite?: string };
  findings: KitFinding[];
  results: KitResult[];
  scenarios?: KitScenario[];
  score: {
    score: number;
    label?: string;
    methodology_version?: string;
    counts?: Record<string, number>;
    coverage_percent?: number;
    determinate_tests?: number;
    catalog_count?: number;
    severity_distribution?: Record<string, number>;
    outcomes?: Record<string, number>;
  };
  limitations?: string[];
};

export type KitBundle = {
  format_version: 1;
  source: KitSource;
  published_at: string;
  run_url: string | null;
  run_id: string | null;
  sha: string | null;
  ref: string | null;
  fixture_note: string;
  workflow_url: string;
  code_scanning_url: string;
  sarif_docs_url: string;
  action_docs_url: string;
  scans: { vulnerable: KitReport; hardened: KitReport };
};

export type LoadedKit = {
  bundle: KitBundle;
  reason: string;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stamp(value: unknown) {
  return typeof value === "string" ? Date.parse(value) : Number.NaN;
}

function safeHttps(value: unknown, fallback: string) {
  if (typeof value !== "string") return fallback;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return fallback;
  }
  if (url.protocol !== "https:" || url.username || url.password) return fallback;
  const repoDoc =
    url.hostname === "github.com" &&
    url.pathname.startsWith("/khushi491/Veyrix/");
  const sarifDoc =
    url.hostname === "docs.github.com" &&
    url.pathname.startsWith("/en/code-security/");
  if (!repoDoc && !sarifDoc) return fallback;
  return url.toString();
}

function validEvents(value: unknown): value is TraceEvent[] {
  if (!Array.isArray(value) || value.length === 0) return false;
  return value.every((event, index) => {
    if (!isRecord(event) || !isRecord(event.data)) return false;
    return (
      event.sequence === index + 1 &&
      typeof event.kind === "string" &&
      typeof event.trust === "string"
    );
  });
}

function validReport(value: unknown, variant: "vulnerable" | "hardened"): KitReport | null {
  if (!isRecord(value) || !isRecord(value.target) || !isRecord(value.score)) return null;
  if (value.target.variant !== variant || value.target.adapter !== "local") return null;
  if (typeof value.target.name !== "string") return null;
  const score = value.score.score;
  if (typeof score !== "number" || !Number.isInteger(score) || score < 0 || score > 100) {
    return null;
  }
  for (const key of ["engine_version", "scoring_version", "generated_at"] as const) {
    if (typeof value[key] !== "string" || !value[key]) return null;
  }
  if (Number.isNaN(stamp(value.generated_at))) return null;
  if (!Array.isArray(value.findings) || !Array.isArray(value.results) || value.results.length === 0) {
    return null;
  }
  for (const finding of value.findings) {
    if (!isRecord(finding)) return null;
    if (typeof finding.scenario_id !== "string" || typeof finding.title !== "string") return null;
    if (typeof finding.severity !== "string") return null;
  }
  for (const result of value.results) {
    if (!isRecord(result) || typeof result.scenario_id !== "string") return null;
    if (!validEvents(result.events)) return null;
  }
  return value as unknown as KitReport;
}

export function validateBundle(value: unknown): KitBundle | null {
  if (!isRecord(value) || value.format_version !== 1) return null;
  if (
    value.source !== "github-actions" &&
    value.source !== "build" &&
    value.source !== "committed-snapshot"
  ) {
    return null;
  }
  if (typeof value.published_at !== "string" || Number.isNaN(stamp(value.published_at))) {
    return null;
  }
  if (!isRecord(value.scans)) return null;
  const vulnerable = validReport(value.scans.vulnerable, "vulnerable");
  const hardened = validReport(value.scans.hardened, "hardened");
  if (!vulnerable || !hardened) return null;
  const runUrl = typeof value.run_url === "string" && RUN_URL.test(value.run_url) ? value.run_url : null;
  const sha = typeof value.sha === "string" && SHA.test(value.sha) ? value.sha : null;
  return {
    format_version: 1,
    source: value.source,
    published_at: value.published_at,
    run_url: runUrl,
    run_id: typeof value.run_id === "string" ? value.run_id : null,
    sha,
    ref: typeof value.ref === "string" ? value.ref : null,
    fixture_note: typeof value.fixture_note === "string" ? value.fixture_note : DEFAULT_NOTE,
    workflow_url: safeHttps(value.workflow_url, WORKFLOW_URL),
    code_scanning_url: safeHttps(value.code_scanning_url, CODE_SCANNING_URL),
    sarif_docs_url: safeHttps(value.sarif_docs_url, SARIF_DOCS_URL),
    action_docs_url: safeHttps(value.action_docs_url, ACTION_DOCS_URL),
    scans: { vulnerable, hardened },
  };
}

function readGenerated(): unknown {
  try {
    const file = path.join(process.cwd(), "demo", "kit-scan.generated.json");
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}

function sameEngine(remote: KitBundle, local: KitBundle) {
  return (["vulnerable", "hardened"] as const).every(
    (variant) =>
      remote.scans[variant].engine_version === local.scans[variant].engine_version &&
      remote.scans[variant].scoring_version === local.scans[variant].scoring_version,
  );
}

async function fetchRemote(): Promise<KitBundle | null> {
  const configured = process.env.VEYRIX_KIT_SCAN_URL;
  if (configured === "off" || configured === "") return null;
  const url = configured || KIT_SCAN_URL;
  try {
    const response = await fetch(url, {
      next: { revalidate: 900 },
      signal: AbortSignal.timeout(8000),
      headers: { accept: "application/json" },
    });
    if (!response.ok) return null;
    if (!configured) {
      const finalHost = new URL(response.url).hostname;
      if (finalHost !== "raw.githubusercontent.com") return null;
    }
    const text = await response.text();
    if (text.length > MAX_BYTES) return null;
    return validateBundle(JSON.parse(text) as unknown);
  } catch {
    return null;
  }
}

export async function loadKitScan(): Promise<LoadedKit> {
  const committed = validateBundle(committedJson);
  if (!committed) {
    throw new Error("Committed kit scan failed validation.");
  }
  const generated = validateBundle(readGenerated());
  const local =
    generated && stamp(generated.published_at) >= stamp(committed.published_at)
      ? generated
      : committed;
  const remote = await fetchRemote();
  const deploymentSha = process.env.VERCEL_GIT_COMMIT_SHA || null;
  if (
    remote?.source === "github-actions" &&
    deploymentSha !== null &&
    remote.sha === deploymentSha
  ) {
    return {
      bundle: remote,
      reason:
        "This deployment was built from the same commit the scheduled scan ran.",
    };
  }
  if (
    remote &&
    sameEngine(remote, local) &&
    stamp(remote.published_at) >= stamp(local.published_at)
  ) {
    return {
      bundle: remote,
      reason:
        "The scheduled publication is newer than the scan shipped with this deployment.",
    };
  }
  if (local.source === "build") {
    return {
      bundle: local,
      reason:
        "Showing the scan generated while this site was built. The scheduled publication is not newer.",
    };
  }
  return {
    bundle: local,
    reason:
      "Showing the scan committed with this deployment. The scheduled publication is not available yet, or it is older or from a different engine.",
  };
}
