import rawSnapshot from "../demo/snapshot.json";

const READ_ONLY =
  "This public demo is a read-only snapshot. Run Veyrix locally to create projects, register agents, start scans, or triage findings.";

type JsonRecord = Record<string, unknown>;

type Project = {
  id: string;
  name: string;
  description: string;
  created_at: string;
};

type Agent = Project & {
  project_id: string;
  adapter: string;
  variant: string;
  server_variant: string;
  policy: JsonRecord;
};

type Run = {
  id: string;
  agent_id: string;
  created_at: string;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  configuration: JsonRecord;
  results: JsonRecord[];
};

type ScoreEntry = {
  run_id: string;
  agent_id: string;
  created_at: string;
  run_status: string;
  snapshot_persisted: boolean;
  assessment: {
    methodology_version: string;
    scope_fingerprint: string | null;
    score: number | null;
  } & JsonRecord;
};

type Finding = {
  id: string;
  run_id: string;
  agent_id: string;
  agent_name: string;
  scenario_id: string;
  scenario_version: string;
  engine_version: string;
  title: string;
  category: string;
  severity: string;
  status: string;
  observed_at: string;
  created_at: string;
  attempted: boolean;
  executed: boolean;
  result: JsonRecord;
  configuration: JsonRecord;
  history: JsonRecord[];
  reproduction_steps: string[];
};

type Snapshot = {
  format_version: number;
  methodology: JsonRecord;
  projects: Project[];
  agents: Agent[];
  runs: Run[];
  score_entries: Record<string, ScoreEntry>;
  findings: Finding[];
  suites: JsonRecord;
  reports: Record<string, JsonRecord>;
  scoring_version: string;
};

const snapshot = rawSnapshot as Snapshot;
const SUMMARY_KEYS = [
  "id",
  "run_id",
  "agent_id",
  "agent_name",
  "scenario_id",
  "scenario_version",
  "engine_version",
  "title",
  "category",
  "severity",
  "status",
  "observed_at",
  "created_at",
  "attempted",
  "executed",
] as const;

function fail(detail: string): never {
  throw new Error(detail);
}

function parsePath(path: string) {
  const url = new URL(path, "https://demo.veyrix.local");
  return { pathname: url.pathname.replace(/\/$/, "") || "/", query: url.searchParams };
}

function time(value: string) {
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? 0 : parsed;
}

function requireProject(projectId: string) {
  const project = snapshot.projects.find((item) => item.id === projectId);
  if (!project) fail("Project not found");
  return project;
}

function summary(finding: Finding) {
  return Object.fromEntries(SUMMARY_KEYS.map((key) => [key, finding[key]]));
}

function boundedInteger(
  value: string | null,
  fallback: number,
  min: number,
  max: number,
) {
  if (value === null || value === "") return fallback;
  if (!/^\d+$/.test(value)) fail("Request failed (422).");
  const parsed = Number(value);
  if (parsed < min || parsed > max) fail("Request failed (422).");
  return parsed;
}

function filteredFindings(projectId: string, query: URLSearchParams) {
  requireProject(projectId);
  const severity = query.get("severity") || "";
  const status = query.get("status") || "";
  const agentId = query.get("agent_id") || "";
  const category = query.get("category") || "";
  const q = (query.get("q") || "").trim();
  if (q.length > 200) fail("Request failed (422).");
  const observedFrom = parseBound(query.get("observed_from"));
  const observedBefore = parseBound(query.get("observed_before"));
  if (
    observedFrom !== null &&
    observedBefore !== null &&
    observedFrom >= observedBefore
  ) {
    fail("Date range must have a start before its end");
  }
  const needle = q.toLowerCase();
  return snapshot.findings
    .filter((finding) => {
      const agent = snapshot.agents.find((item) => item.id === finding.agent_id);
      if (!agent || agent.project_id !== projectId) return false;
      if (severity && finding.severity !== severity) return false;
      if (status && finding.status !== status) return false;
      if (agentId && finding.agent_id !== agentId) return false;
      if (category && finding.category !== category) return false;
      if (needle) {
        const haystack = `${finding.title}\n${finding.scenario_id}\n${finding.agent_name}`.toLowerCase();
        if (!haystack.includes(needle)) return false;
      }
      const observed = time(finding.observed_at);
      if (observedFrom !== null && observed < observedFrom) return false;
      if (observedBefore !== null && observed >= observedBefore) return false;
      return true;
    })
    .sort((a, b) => time(b.observed_at) - time(a.observed_at) || (a.id < b.id ? 1 : a.id > b.id ? -1 : 0));
}

function parseBound(value: string | null) {
  if (!value) return null;
  if (!/(?:Z|[+-]\d{2}:\d{2})$/.test(value) || Number.isNaN(Date.parse(value))) {
    fail("Date filters must include a timezone");
  }
  return Date.parse(value);
}

function listFindings(projectId: string, query: URLSearchParams) {
  const offset = boundedInteger(query.get("offset"), 0, 0, 100000);
  const limit = boundedInteger(query.get("limit"), 25, 1, 100);
  const matched = filteredFindings(projectId, query);
  const distribution: Record<string, number> = {};
  for (const finding of matched) {
    distribution[finding.severity] = (distribution[finding.severity] ?? 0) + 1;
  }
  return {
    items: matched.slice(offset, offset + limit).map(summary),
    total: matched.length,
    offset,
    limit,
    severity_distribution: distribution,
  };
}

function findingDetail(projectId: string, findingId: string) {
  requireProject(projectId);
  const finding = snapshot.findings.find((item) => item.id === findingId);
  const agent = finding
    ? snapshot.agents.find((item) => item.id === finding.agent_id)
    : undefined;
  if (!finding || !agent || agent.project_id !== projectId) {
    fail("Finding not found in this project");
  }
  return finding;
}

function agentScores(projectId: string, agentId: string) {
  const agent = snapshot.agents.find(
    (item) => item.id === agentId && item.project_id === projectId,
  );
  if (!agent) fail("Agent not found in this project");
  const runs = snapshot.runs
    .filter((run) => run.agent_id === agent.id)
    .sort(
      (a, b) =>
        time(b.created_at) - time(a.created_at) || (a.id < b.id ? 1 : -1),
    );
  const latestRun = runs[0];
  if (!latestRun) {
    return {
      agent_id: agent.id,
      agent_name: agent.name,
      latest: null,
      history: [],
      methodology: snapshot.methodology,
    };
  }
  const latest = snapshot.score_entries[latestRun.id];
  if (!latest) fail("Run not found");
  const fingerprint = latest.assessment.scope_fingerprint;
  const history = [latest];
  if (fingerprint) {
    for (const run of runs) {
      if (run.id === latestRun.id) continue;
      const entry = snapshot.score_entries[run.id];
      if (
        entry &&
        entry.assessment.scope_fingerprint === fingerprint &&
        entry.assessment.methodology_version === snapshot.scoring_version
      ) {
        history.push(entry);
      }
    }
  }
  history.sort(
    (a, b) =>
      time(a.created_at) - time(b.created_at) || (a.run_id < b.run_id ? -1 : 1),
  );
  return {
    agent_id: agent.id,
    agent_name: agent.name,
    latest,
    history: history.slice(-20),
    methodology: snapshot.methodology,
  };
}

export async function demoRequest<T>(
  path: string,
  method: string,
  _body?: unknown,
): Promise<T> {
  if (snapshot.format_version !== 1) fail("Demo snapshot format is unsupported.");
  if (method !== "GET") fail(READ_ONLY);
  const { pathname, query } = parsePath(path);
  if (pathname === "/projects") return snapshot.projects as T;
  if (pathname === "/suites") return snapshot.suites as T;

  const agents = pathname.match(/^\/projects\/([^/]+)\/agents$/);
  if (agents) {
    requireProject(agents[1]);
    return snapshot.agents
      .filter((agent) => agent.project_id === agents[1])
      .slice(0, 100) as T;
  }
  const finding = pathname.match(/^\/projects\/([^/]+)\/findings\/([^/]+)$/);
  if (finding) return findingDetail(finding[1], finding[2]) as T;
  const findings = pathname.match(/^\/projects\/([^/]+)\/findings$/);
  if (findings) return listFindings(findings[1], query) as T;
  const scores = pathname.match(/^\/projects\/([^/]+)\/scores$/);
  if (scores) {
    const agentId = query.get("agent_id");
    if (!agentId) fail("Agent not found in this project");
    return agentScores(scores[1], agentId) as T;
  }
  const runs = pathname.match(/^\/agents\/([^/]+)\/runs$/);
  if (runs) {
    if (!snapshot.agents.some((agent) => agent.id === runs[1])) {
      fail("Agent not found");
    }
    return snapshot.runs
      .filter((run) => run.agent_id === runs[1])
      .sort((a, b) => time(b.created_at) - time(a.created_at))
      .slice(0, 100) as T;
  }
  const score = pathname.match(/^\/runs\/([^/]+)\/score$/);
  if (score) {
    const entry = snapshot.score_entries[score[1]];
    if (!entry) fail("Run not found");
    return entry as T;
  }
  fail(`Request failed (404).`);
}

export function downloadReport(runId: string) {
  const report = snapshot.reports[runId];
  if (!report) throw new Error("Report not found");
  const blob = new Blob([`${JSON.stringify(report, null, 2)}\n`], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `veyrix-${runId}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
