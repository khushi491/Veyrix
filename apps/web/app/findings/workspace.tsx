"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft,
  ArrowRight,
  Bug,
  ChevronRight,
  Filter,
  RefreshCw,
} from "lucide-react";
import { Sidebar } from "../sidebar";
import { ExecutionTrace, type TraceEvent } from "../execution-trace";

type Project = { id: string; name: string };
type Agent = { id: string; name: string };
type FindingStatus = "open" | "resolved" | "accepted_risk";
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
  status: FindingStatus;
  observed_at: string;
  created_at: string;
  attempted: boolean;
  executed: boolean;
};
type FindingDetail = Finding & {
  result: {
    events: TraceEvent[];
    evaluation: { evidence_sequences: number[]; reason: string };
    expected_behavior?: string;
    actual_behavior?: string;
    root_cause_hypothesis?: string;
    remediation?: string;
  };
  configuration: Record<string, unknown>;
  history: {
    id: string;
    status: FindingStatus;
    previous_status: FindingStatus;
    note: string;
    actor: string;
    created_at: string;
  }[];
  reproduction_steps: string[];
};
type FindingPage = {
  items: Finding[];
  total: number;
  limit: number;
  offset: number;
  severity_distribution: Record<string, number>;
};
const emptyFilters = {
  q: "",
  severity: "",
  status: "",
  category: "",
  agent_id: "",
  from: "",
  to: "",
};
const categories = [
  "prompt-injection",
  "unsafe-tool-execution",
  "authorization-boundary",
  "data-exfiltration",
  "multi-step-manipulation",
  "mcp-security",
];
const label = (value: string) =>
  value.replaceAll("_", " ").replaceAll("-", " ");
async function request<T>(
  path: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  const response = await fetch(`/api${path}`, {
    method,
    ...(body
      ? {
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }
      : {}),
  });
  if (!response.ok) {
    const error = await response.json().catch(() => null);
    throw new Error(
      typeof error?.detail === "string"
        ? error.detail
        : `Request failed (${response.status}). Check the API and migrations.`,
    );
  }
  return response.json() as Promise<T>;
}

export function FindingsWorkspace({
  initialProjectId,
  initialFindingId,
}: {
  initialProjectId?: string;
  initialFindingId?: string;
}) {
  const [selectedProject, setSelectedProject] = useState(
    initialProjectId || "",
  );
  const projects = useQuery({
    queryKey: ["projects"],
    queryFn: () => request<Project[]>("/projects"),
  });
  const projectId = selectedProject || projects.data?.[0]?.id || "";
  return (
    <div className="workspace">
      <Sidebar active="findings" projectId={projectId} />
      <main>
        <header>
          <span>
            Workspace <ChevronRight size={13} /> Findings
          </span>
          <span className="dev">
            <i />
            Local development
          </span>
        </header>
        <section className="content">
          <div className="eyebrow">OBSERVABLE SECURITY EVIDENCE</div>
          <div className="heading">
            <div>
              <h1>Follow the evidence.</h1>
              <p>
                Inspect verified policy violations, reproduce failures, and
                track remediation.
              </p>
            </div>
            <a href="/#tests" className="button-link">
              Run security tests ↗
            </a>
          </div>
          <label htmlFor="finding-project">Project</label>
          <select
            id="finding-project"
            className="project-select"
            value={projectId}
            onChange={(e) => setSelectedProject(e.target.value)}
            disabled={projects.isPending}
          >
            {!projects.data?.length && (
              <option value="">
                {projects.isPending ? "Loading projects…" : "No projects yet"}
              </option>
            )}
            {projects.data?.map((p) => (
              <option value={p.id} key={p.id}>
                {p.name}
              </option>
            ))}
          </select>
          {projects.error && (
            <p className="error" role="alert">
              {projects.error.message}
              <button
                className="secondary"
                onClick={() => void projects.refetch()}
              >
                Retry
              </button>
            </p>
          )}
          {projectId ? (
            <Explorer
              key={projectId}
              projectId={projectId}
              initialFindingId={
                projectId === initialProjectId ? initialFindingId : undefined
              }
            />
          ) : (
            !projects.isPending && (
              <div className="panel empty">
                <Bug size={28} />
                <h3>Create a project to begin</h3>
                <p>
                  Run a synthetic assessment to generate findings from observed
                  tool requests.
                </p>
                <a className="export-link" href="/">
                  Open workspace ↗
                </a>
              </div>
            )
          )}
          <footer>
            <span>Security for Autonomous Intelligence.</span>
            <span>
              Synthetic fixture assessments · Original evidence preserved
            </span>
          </footer>
        </section>
      </main>
    </div>
  );
}

function Explorer({
  projectId,
  initialFindingId,
}: {
  projectId: string;
  initialFindingId?: string;
}) {
  const [filters, setFilters] = useState(emptyFilters);
  const [draftSearch, setDraftSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [selectedId, setSelectedId] = useState(initialFindingId || "");
  const agents = useQuery({
    queryKey: ["agents", projectId],
    queryFn: () => request<Agent[]>(`/projects/${projectId}/agents`),
  });
  const params = new URLSearchParams({ limit: "20", offset: String(offset) });
  for (const key of [
    "q",
    "severity",
    "status",
    "category",
    "agent_id",
  ] as const) {
    if (filters[key]) params.set(key, filters[key]);
  }
  if (filters.from) params.set("observed_from", `${filters.from}T00:00:00Z`);
  if (filters.to)
    params.set(
      "observed_before",
      new Date(
        new Date(`${filters.to}T00:00:00Z`).getTime() + 86400000,
      ).toISOString(),
    );
  const findings = useQuery({
    queryKey: ["findings", projectId, filters, offset],
    queryFn: () =>
      request<FindingPage>(`/projects/${projectId}/findings?${params}`),
    refetchInterval: 5000,
  });
  const detail = useQuery({
    queryKey: ["finding", projectId, selectedId],
    queryFn: () =>
      request<FindingDetail>(`/projects/${projectId}/findings/${selectedId}`),
    enabled: !!selectedId,
  });
  const setFilter = (key: keyof typeof emptyFilters, value: string) => {
    setFilters({ ...filters, [key]: value });
    setOffset(0);
  };
  const distribution = findings.data?.severity_distribution;
  return (
    <>
      <div className="metrics findings-metrics">
        <article>
          <span>Matching verified findings</span>
          <strong>{findings.data?.total ?? "—"}</strong>
          <small>All runs in the selected project</small>
        </article>
        <article>
          <span>Critical / High</span>
          <strong>
            {distribution
              ? `${distribution.critical ?? 0} / ${distribution.high ?? 0}`
              : "—"}
          </strong>
          <small>Distribution within current filters</small>
        </article>
        <article>
          <span>Evidence standard</span>
          <strong className="unscored">Observed requests</strong>
          <small>Attempt and execution tracked separately</small>
        </article>
      </div>
      <section className="panel">
        <div className="panel-heading">
          <h2>
            <Filter size={15} /> Findings explorer
          </h2>
          <button
            className="secondary"
            onClick={() => void findings.refetch()}
            disabled={findings.isFetching}
          >
            <RefreshCw size={13} />
            Refresh
          </button>
        </div>
        <form
          className="finding-filters"
          onSubmit={(e) => {
            e.preventDefault();
            setFilter("q", draftSearch);
          }}
        >
          <div className="finding-search">
            <label htmlFor="finding-search">
              Search title, scenario, or agent
            </label>
            <div className="form-row">
              <input
                id="finding-search"
                value={draftSearch}
                onChange={(e) => setDraftSearch(e.target.value)}
                maxLength={200}
                placeholder="Search execution-backed findings…"
              />
              <button className="secondary" type="submit">
                Search
              </button>
            </div>
          </div>
          <div>
            <label htmlFor="severity-filter">Severity</label>
            <select
              id="severity-filter"
              value={filters.severity}
              onChange={(e) => setFilter("severity", e.target.value)}
            >
              <option value="">All severities</option>
              {["critical", "high", "medium", "low", "info"].map((s) => (
                <option key={s} value={s}>
                  {label(s)}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="status-filter">Triage status</label>
            <select
              id="status-filter"
              value={filters.status}
              onChange={(e) => setFilter("status", e.target.value)}
            >
              <option value="">All statuses</option>
              {["open", "resolved", "accepted_risk"].map((s) => (
                <option key={s} value={s}>
                  {label(s)}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="agent-filter">Affected agent</label>
            <select
              id="agent-filter"
              value={filters.agent_id}
              onChange={(e) => setFilter("agent_id", e.target.value)}
              disabled={agents.isPending || agents.isError}
            >
              <option value="">All agents</option>
              {agents.data?.map((a) => (
                <option value={a.id} key={a.id}>
                  {a.name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="category-filter">Category</label>
            <select
              id="category-filter"
              value={filters.category}
              onChange={(e) => setFilter("category", e.target.value)}
            >
              <option value="">All categories</option>
              {categories.map((c) => (
                <option key={c} value={c}>
                  {label(c)}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="date-from">From (UTC)</label>
            <input
              id="date-from"
              type="date"
              value={filters.from}
              onChange={(e) => setFilter("from", e.target.value)}
            />
          </div>
          <div>
            <label htmlFor="date-to">Through (UTC)</label>
            <input
              id="date-to"
              type="date"
              value={filters.to}
              onChange={(e) => setFilter("to", e.target.value)}
            />
          </div>
          <button
            className="secondary clear-filters"
            type="button"
            onClick={() => {
              setFilters(emptyFilters);
              setDraftSearch("");
              setOffset(0);
            }}
          >
            Clear filters
          </button>
        </form>
        {agents.error && (
          <p className="error" role="alert">
            Agent filter unavailable: {agents.error.message}
          </p>
        )}
        {findings.error && (
          <p className="error" role="alert">
            {findings.error.message}
          </p>
        )}
        {findings.isPending ? (
          <p className="empty">Loading verified findings…</p>
        ) : findings.data?.items.length ? (
          <>
            <div className="table-scroll">
              <table className="findings-table">
                <caption className="sr-only">
                  Verified findings in this project, filtered and ordered by
                  observation date
                </caption>
                <thead>
                  <tr>
                    <th scope="col">Severity</th>
                    <th scope="col">Finding / Agent</th>
                    <th scope="col">Observed outcome</th>
                    <th scope="col">Status</th>
                    <th scope="col">Observed (UTC)</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.data.items.map((f) => (
                    <tr
                      key={f.id}
                      className={selectedId === f.id ? "selected-finding" : ""}
                    >
                      <td>
                        <span className={`severity severity-${f.severity}`}>
                          {f.severity}
                        </span>
                      </td>
                      <td>
                        <a
                          href="#finding-detail"
                          onClick={() => setSelectedId(f.id)}
                        >
                          {f.title}
                        </a>
                        <small>
                          {f.agent_name} · {label(f.category)}
                        </small>
                      </td>
                      <td>
                        <span
                          className={
                            f.executed ? "outcome fail" : "outcome neutral"
                          }
                        >
                          {f.executed ? "Mock executed" : "Attempt only"}
                        </span>
                      </td>
                      <td>
                        <span className="finding-status">
                          {label(f.status)}
                        </span>
                      </td>
                      <td>
                        <time dateTime={f.observed_at}>
                          {new Date(f.observed_at)
                            .toISOString()
                            .slice(0, 16)
                            .replace("T", " ")}
                        </time>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="pagination">
              <span>
                {offset + 1}–{offset + findings.data.items.length} of{" "}
                {findings.data.total}
              </span>
              <div>
                <button
                  className="secondary"
                  disabled={offset === 0}
                  onClick={() => setOffset(Math.max(0, offset - 20))}
                >
                  <ArrowLeft size={13} />
                  Previous
                </button>
                <button
                  className="secondary"
                  disabled={offset + 20 >= findings.data.total}
                  onClick={() => setOffset(offset + 20)}
                >
                  Next
                  <ArrowRight size={13} />
                </button>
              </div>
            </div>
          </>
        ) : (
          !findings.error && (
            <div className="empty">
              <Bug size={26} />
              <h3>No findings match this view</h3>
              <p>
                Run an assessment or clear the filters. An empty view does not
                establish that an agent is secure.
              </p>
              {offset > 0 && (
                <button className="secondary" onClick={() => setOffset(0)}>
                  Return to first page
                </button>
              )}
            </div>
          )
        )}
      </section>
      <section id="finding-detail" className="panel finding-detail">
        <div className="panel-heading">
          <h2>Finding evidence</h2>
          <span>IMMUTABLE EXECUTION RECORD</span>
        </div>
        {!selectedId ? (
          <div className="empty">
            <h3>Select a finding</h3>
            <p>
              Inspect policy evidence, the complete trace, reproduction details,
              and triage history.
            </p>
          </div>
        ) : detail.isPending ? (
          <p className="empty">Loading execution evidence…</p>
        ) : detail.error ? (
          <p className="error" role="alert">
            {detail.error.message}
            <button className="secondary" onClick={() => void detail.refetch()}>
              Retry
            </button>
          </p>
        ) : (
          detail.data && (
            <Detail
              key={detail.data.id}
              projectId={projectId}
              finding={detail.data}
            />
          )
        )}
      </section>
    </>
  );
}

function Detail({
  projectId,
  finding,
}: {
  projectId: string;
  finding: FindingDetail;
}) {
  const result = finding.result;
  return (
    <div className="finding-body">
      <div className="finding-title">
        <div>
          <span className={`severity severity-${finding.severity}`}>
            {finding.severity}
          </span>
          <h2>{finding.title}</h2>
          <p>
            {finding.agent_name} · {finding.scenario_id} v
            {finding.scenario_version}
          </p>
        </div>
        <a
          className="export-link"
          href={`/findings?project=${projectId}&finding=${finding.id}`}
        >
          Permanent link ↗
        </a>
      </div>
      <div className="finding-outcome">
        <strong>
          {finding.executed
            ? "Verified prohibited mock execution"
            : "Verified prohibited attempt"}
        </strong>
        <p>
          {finding.executed
            ? "The linked mock tool response confirms execution."
            : "No execution of the prohibited action is confirmed. Inspect the response to distinguish a blocked request from missing execution evidence."}
        </p>
      </div>
      <div className="finding-detail-grid">
        <div>
          <dl className="finding-facts">
            <dt>Finding ID</dt>
            <dd>{finding.id}</dd>
            <dt>Source run</dt>
            <dd>{finding.run_id}</dd>
            <dt>Observed</dt>
            <dd>{new Date(finding.observed_at).toLocaleString()}</dd>
            <dt>Engine</dt>
            <dd>{finding.engine_version}</dd>
            <dt>Expected behavior</dt>
            <dd>
              {result.expected_behavior ?? "Respect the snapshotted policy."}
            </dd>
            <dt>Observed behavior</dt>
            <dd>{result.actual_behavior ?? result.evaluation.reason}</dd>
            <dt>Root-cause hypothesis</dt>
            <dd>
              {result.root_cause_hypothesis ??
                "Untrusted content influenced tool selection; inspect the source events."}
            </dd>
            <dt>Recommended remediation</dt>
            <dd>
              {result.remediation ??
                "Preserve trust boundaries and enforce policy before tool execution."}
            </dd>
          </dl>
          <h3>Reproduce this assessment</h3>
          <ol className="reproduction">
            {finding.reproduction_steps.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ol>
          <details className="configuration">
            <summary>Saved agent configuration and policy</summary>
            <pre>{JSON.stringify(finding.configuration, null, 2)}</pre>
          </details>
          <Triage key={finding.id} projectId={projectId} finding={finding} />
        </div>
        <div>
          <div className="trace-intro">
            <h3>Execution timeline</h3>
            <p>
              Observable events only. No hidden model reasoning is displayed.
              Highlighted requests are linked policy evidence.
            </p>
          </div>
          <ExecutionTrace
            events={result.events}
            evidenceSequences={result.evaluation.evidence_sequences}
            idPrefix={finding.id}
          />
        </div>
      </div>
    </div>
  );
}

function Triage({
  projectId,
  finding,
}: {
  projectId: string;
  finding: FindingDetail;
}) {
  const [status, setStatus] = useState<FindingStatus>(finding.status);
  const [note, setNote] = useState("");
  const [saved, setSaved] = useState(false);
  const cache = useQueryClient();
  const mutation = useMutation({
    mutationFn: () =>
      request<FindingDetail>(
        `/projects/${projectId}/findings/${finding.id}`,
        "PATCH",
        { status, expected_status: finding.status, note },
      ),
    onSuccess: async (updated) => {
      cache.setQueryData(["finding", projectId, finding.id], updated);
      await cache.invalidateQueries({ queryKey: ["findings", projectId] });
      setNote("");
      setSaved(true);
    },
  });
  return (
    <section className="triage">
      <h3>Triage</h3>
      <p>
        Changing status records a review decision. It does not alter evidence or
        verify that a fix works.
      </p>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setSaved(false);
          mutation.mutate();
        }}
      >
        <label htmlFor="triage-status">Status</label>
        <select
          id="triage-status"
          value={status}
          onChange={(e) => {
            setStatus(e.target.value as FindingStatus);
            setSaved(false);
          }}
        >
          <option value="open">Open</option>
          <option value="resolved">Resolved</option>
          <option value="accepted_risk">Accepted risk</option>
        </select>
        <label htmlFor="triage-note">Review note</label>
        <textarea
          id="triage-note"
          value={note}
          onChange={(e) => {
            setNote(e.target.value);
            setSaved(false);
          }}
          required
          maxLength={2000}
          placeholder="Record the remediation or reason for this decision."
        />
        <button
          disabled={
            mutation.isPending || status === finding.status || !note.trim()
          }
        >
          {mutation.isPending ? "Saving…" : "Save triage decision"}
        </button>
        {mutation.error && (
          <p className="error" role="alert">
            {mutation.error.message}
            <button
              type="button"
              className="secondary"
              onClick={() =>
                void cache.invalidateQueries({
                  queryKey: ["finding", projectId, finding.id],
                })
              }
            >
              Refresh finding
            </button>
          </p>
        )}
        {saved && (
          <p className="success-message" role="status">
            Status saved. Original evidence preserved.
          </p>
        )}
      </form>
      <h3>Review history</h3>
      {finding.history.length ? (
        <ol className="review-history">
          {finding.history.map((change) => (
            <li key={change.id}>
              <strong>
                {label(change.previous_status)} → {label(change.status)}
              </strong>
              <p>{change.note}</p>
              <small>
                {change.actor} · {new Date(change.created_at).toLocaleString()}
              </small>
            </li>
          ))}
        </ol>
      ) : (
        <p>
          No triage changes. Finding created from verified execution evidence.
        </p>
      )}
    </section>
  );
}
