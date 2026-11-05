"use client";

import { RunScore } from "./security-score";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

type Agent = { id: string; name: string; variant: string; adapter: string };
type Result = {
  title: string;
  scenario_id: string;
  severity: string;
  expected_behavior?: string;
  actual_behavior?: string;
  root_cause_hypothesis?: string;
  remediation?: string;
  evaluation: {
    status: string;
    reason: string;
    attempted: boolean;
    executed: boolean;
  };
  events: {
    sequence: number;
    kind: string;
    trust: string;
    data: Record<string, unknown>;
  }[];
};
type Run = {
  id: string;
  created_at: string;
  status: string;
  error: string | null;
  results: Result[];
  configuration: Record<string, unknown>;
};
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
  if (!response.ok)
    throw new Error(
      `Request failed (${response.status}). Check the API and migrations.`,
    );
  return response.json() as Promise<T>;
}
export function RunPanel({
  agents,
  projectId,
}: {
  agents: Agent[];
  projectId: string;
}) {
  const [suite, setSuite] = useState("all");
  const catalog = useQuery({
    queryKey: ["suites"],
    queryFn: () =>
      request<{
        scenarios: { id: string; category: string; adapter: string }[];
      }>("/suites"),
  });
  const [chosen, setChosen] = useState("");
  const agentId = agents.some((a) => a.id === chosen)
    ? chosen
    : agents[0]?.id || "";
  const currentAdapter =
    agents.find((a) => a.id === agentId)?.adapter || "local";
  const availableScenarios =
    catalog.data?.scenarios.filter((s) => s.adapter === currentAdapter) || [];
  const categories = [...new Set(availableScenarios.map((s) => s.category))];
  const [runId, setRunId] = useState("");
  const cache = useQueryClient();
  const runs = useQuery({
    queryKey: ["runs", agentId],
    queryFn: () => request<Run[]>(`/agents/${agentId}/runs`),
    enabled: !!agentId,
    refetchInterval: (query) =>
      query.state.data?.some((r) =>
        ["queued", "running", "cancelling"].includes(r.status),
      )
        ? 1000
        : false,
  });
  const execute = useMutation({
    mutationFn: () =>
      request<Run>(`/agents/${agentId}/runs`, "POST", { suite }),
    onSuccess: async (run) => {
      setRunId(run.id);
      await cache.invalidateQueries({ queryKey: ["runs", agentId] });
    },
  });
  const cancel = useMutation({
    mutationFn: (id: string) => request<Run>(`/runs/${id}/cancel`, "POST"),
    onSuccess: async () => {
      await cache.invalidateQueries({ queryKey: ["runs", agentId] });
    },
  });
  const run = runs.data?.find((r) => r.id === runId) || runs.data?.[0];
  return (
    <section className="panel run-panel" id="tests">
      <div className="panel-heading">
        <h2>Security assessment</h2>
        <span>03 / OBSERVE</span>
      </div>
      <div className="run-content">
        <p>
          Versioned attacks against in-memory tools for payments, files,
          records, email, and outbound requests. Deterministic fixtures; no
          external model or real service.
        </p>
        <div className="run-controls">
          <select
            aria-label="Agent to test"
            value={agentId}
            onChange={(e) => {
              setChosen(e.target.value);
              setSuite("all");
              setRunId("");
            }}
          >
            {agents.length ? (
              agents.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name} · {a.variant}
                </option>
              ))
            ) : (
              <option value="">Register an agent first</option>
            )}
          </select>
          <select
            aria-label="Security test suite"
            value={suite}
            onChange={(e) => setSuite(e.target.value)}
          >
            <option value="all">
              All scenarios ({availableScenarios.length ?? "…"})
            </option>
            {categories.map((category) => (
              <option key={category} value={category}>
                {category} (
                {
                  availableScenarios.filter((s) => s.category === category)
                    .length
                }
                )
              </option>
            ))}
          </select>
          <button
            disabled={
              !agentId ||
              execute.isPending ||
              catalog.isPending ||
              catalog.isError
            }
            onClick={() => execute.mutate()}
          >
            {execute.isPending ? "Queuing…" : "Run security tests"}
          </button>
        </div>
        {(runs.error || execute.error || cancel.error || catalog.error) && (
          <p className="error" role="alert">
            {runs.error?.message ||
              execute.error?.message ||
              cancel.error?.message ||
              catalog.error?.message}
          </p>
        )}
        {runs.isFetching && <p>Loading run history…</p>}
        {runs.data?.length ? (
          <>
            <label htmlFor="run-history">Persisted test runs</label>
            <select
              id="run-history"
              value={run?.id || ""}
              onChange={(e) => setRunId(e.target.value)}
            >
              {runs.data.map((r) => (
                <option key={r.id} value={r.id}>
                  {new Date(r.created_at).toLocaleString()} · {r.id.slice(0, 8)}{" "}
                  · {r.status}
                </option>
              ))}
            </select>
            {run && (
              <div className="run-progress" aria-live="polite">
                <p>
                  Run status: <strong>{run.status}</strong> ·{" "}
                  {run.results.length} /{" "}
                  {Array.isArray(run.configuration.scenarios)
                    ? run.configuration.scenarios.length
                    : 1}{" "}
                  scenarios complete
                </p>
                {["queued", "running"].includes(run.status) && (
                  <button
                    className="secondary"
                    disabled={cancel.isPending}
                    onClick={() => cancel.mutate(run.id)}
                  >
                    Cancel run
                  </button>
                )}
                {run.status === "queued" && (
                  <p className="form-hint">
                    Waiting for a worker. Start it with python -m
                    veyrix_api.worker.
                  </p>
                )}
                {run.error && (
                  <p className="error" role="alert">
                    {run.error}
                  </p>
                )}
              </div>
            )}
            {run && <RunScore runId={run.id} status={run.status} />}
            {run?.results.map((result) => (
              <article
                className="result"
                key={result.scenario_id}
                id={`result-${run.id}-${result.scenario_id}`}
              >
                <div className="result-heading">
                  <h3>{result.title}</h3>
                  <span
                    className={
                      result.evaluation.status === "FAIL"
                        ? "outcome fail"
                        : result.evaluation.status === "PASS"
                          ? "outcome pass"
                          : "outcome neutral"
                    }
                  >
                    {result.evaluation.status}
                  </span>
                </div>
                <p>{result.evaluation.reason}</p>
                <p className="form-hint">
                  Prohibited attempt:{" "}
                  {result.evaluation.attempted ? "observed" : "not observed"} ·
                  Prohibited mock execution:{" "}
                  {result.evaluation.executed ? "observed" : "not observed"} ·
                  Severity if violated: {result.severity}
                </p>
                {result.evaluation.status === "FAIL" && (
                  <div className="finding">
                    <strong>Verified policy violation</strong>
                    <p>
                      Expected:{" "}
                      {result.expected_behavior ??
                        "Respect the configured policy."}
                      Observed:{" "}
                      {result.actual_behavior ?? result.evaluation.reason}
                    </p>
                    <p>
                      Root-cause hypothesis:{" "}
                      {result.root_cause_hypothesis ??
                        "Untrusted content was treated as instructions."}
                      Remediation:{" "}
                      {result.remediation ??
                        "Enforce policy before tool execution."}
                    </p>
                  </div>
                )}
                <details>
                  <summary>
                    Inspect execution trace · {result.events.length} events
                  </summary>
                  <ol className="trace">
                    {result.events.map((event) => (
                      <li key={event.sequence}>
                        <div>
                          <span>
                            {event.sequence.toString().padStart(2, "0")} /{" "}
                            {event.kind}
                          </span>
                          <small>{event.trust}</small>
                        </div>
                        <pre>{JSON.stringify(event.data, null, 2)}</pre>
                      </li>
                    ))}
                  </ol>
                </details>
              </article>
            ))}
            {run &&
              run.results.some(
                (result) => result.evaluation.status === "FAIL",
              ) && (
                <p className="finding-explorer-link">
                  <a
                    className="export-link"
                    href={`/findings?project=${projectId}`}
                  >
                    Open project findings and evidence ↗
                  </a>
                </p>
              )}
            {run &&
              !["queued", "running", "cancelling"].includes(run.status) && (
                <a
                  className="export-link"
                  href={`/api/runs/${run?.id}/report`}
                  download
                >
                  Download JSON assessment ↗
                </a>
              )}
          </>
        ) : (
          !runs.isFetching && (
            <p className="empty-run">
              No runs yet. Execute the scenario to generate observable evidence.
            </p>
          )
        )}
      </div>
    </section>
  );
}
