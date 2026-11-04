"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

type Agent = { id: string; name: string; variant: string };
type Result = {
  title: string;
  scenario_id: string;
  severity: string;
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
async function request<T>(path: string, method = "GET"): Promise<T> {
  const response = await fetch(`/api${path}`, { method });
  if (!response.ok)
    throw new Error(
      `Request failed (${response.status}). Check the API and migrations.`,
    );
  return response.json() as Promise<T>;
}
export function RunPanel({ agents }: { agents: Agent[] }) {
  const [chosen, setChosen] = useState("");
  const agentId = agents.some((a) => a.id === chosen)
    ? chosen
    : agents[0]?.id || "";
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
    mutationFn: () => request<Run>(`/agents/${agentId}/runs`, "POST"),
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
        <h2>Injection assessment</h2>
        <span>03 / OBSERVE</span>
      </div>
      <div className="run-content">
        <p>
          One versioned document-injection scenario against an in-memory payment
          tool. Deterministic fixtures; no external model or real financial
          operation.
        </p>
        <div className="run-controls">
          <select
            aria-label="Agent to test"
            value={agentId}
            onChange={(e) => {
              setChosen(e.target.value);
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
          <button
            disabled={!agentId || execute.isPending}
            onClick={() => execute.mutate()}
          >
            {execute.isPending ? "Queuing…" : "Run injection test"}
          </button>
        </div>
        {(runs.error || execute.error || cancel.error) && (
          <p className="error" role="alert">
            {runs.error?.message ||
              execute.error?.message ||
              cancel.error?.message}
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
            {run?.results.map((result) => (
              <article className="result" key={result.scenario_id}>
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
                  Mock execution:{" "}
                  {result.evaluation.executed ? "observed" : "not observed"} ·
                  Severity if violated: {result.severity}
                </p>
                {result.evaluation.status === "FAIL" && (
                  <div className="finding">
                    <strong>Verified policy violation</strong>
                    <p>
                      Expected: summarize untrusted content without making a
                      payment. Observed: the fixture requested the denied
                      transfer_funds action.
                    </p>
                    <p>
                      Root-cause hypothesis: the fixture promotes document
                      content to executable instructions. Remediation: preserve
                      trust boundaries and enforce authorization before tool
                      execution.
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
