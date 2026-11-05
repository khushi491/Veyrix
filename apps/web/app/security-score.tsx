"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

type Counts = Record<
  "PASS" | "FAIL" | "INCONCLUSIVE" | "ERROR" | "NOT_TESTED",
  number
>;
type ScoreCase = {
  scenario_id: string;
  scenario_version: string;
  status: string;
  severity: string;
  outcome: string | null;
  weight: number;
  loss_weight: number;
  evidence_sequences: number[];
};
export type SecurityAssessment = {
  methodology_version: string;
  score: number | null;
  label: string;
  eligible: boolean;
  reasons: string[];
  integrity_issues: string[];
  catalog_count: number;
  selected_tests: number;
  completed_tests: number;
  determinate_tests: number;
  counts: Counts;
  coverage_percent: number;
  severity_distribution: Record<string, number>;
  authorization_violations: number;
  successful_adversarial_scenarios: number;
  outcomes: Record<string, number>;
  scope_fingerprint: string | null;
  breakdown: {
    coverage_points: number;
    coverage_penalty: number;
    catalog_weight: number;
    loss_weight: number;
    risk_penalty: number;
    raw_score: number;
    cap: number;
    cap_reasons: string[];
    cases: ScoreCase[];
  };
  methodology: {
    minimum_determinate_tests: number;
    minimum_coverage_percent: number;
    severity_weights: Record<string, number>;
    authorization_weight: number;
    formula: string;
    caps: Record<string, number>;
    limitations: string[];
  };
};
type Entry = {
  run_id: string;
  agent_id: string;
  created_at: string;
  run_status: string;
  snapshot_persisted: boolean;
  assessment: SecurityAssessment;
};
type Agent = { id: string; name: string };
async function request<T>(path: string): Promise<T> {
  const response = await fetch(`/api${path}`);
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(
      typeof body?.detail === "string"
        ? body.detail
        : `Assessment request failed (${response.status}). Check the API and migrations.`,
    );
  }
  return response.json() as Promise<T>;
}
const words = (value: string) => value.toLowerCase().replaceAll("_", " ");
const points = (value: number) => value.toFixed(2).replace(/\.00$/, "");

export function ScoreCard({
  entry,
  linkToResults = false,
}: {
  entry: Entry;
  linkToResults?: boolean;
}) {
  const score = entry.assessment;
  return (
    <div className="score-card">
      <div className="score-card-heading">
        <div>
          <span className="eyebrow">SCOPED SECURITY ASSESSMENT</span>
          <h3>Veyrix Security Score</h3>
        </div>
        <span className="method-badge">Method {score.methodology_version}</span>
      </div>
      <div className="score-summary">
        <div
          className={
            score.score === null ? "score-unavailable" : "score-number"
          }
        >
          {score.score === null ? (
            "Insufficient coverage"
          ) : (
            <>
              {score.score}
              <span>/ 100</span>
            </>
          )}
          <p>
            {score.catalog_count
              ? `${score.coverage_percent}% evidence-backed coverage · ${score.determinate_tests}/${score.catalog_count} catalog cases`
              : "Full scoring catalog was not recorded"}
          </p>
        </div>
        <div className="score-scope">
          <span>
            {entry.snapshot_persisted
              ? "Saved assessment"
              : "Assessment preview"}
          </span>
          <p>
            {entry.run_status} · {new Date(entry.created_at).toLocaleString()}
          </p>
          <small>
            Run {entry.run_id.slice(0, 8)}
            {score.scope_fingerprint
              ? ` · Scope ${score.scope_fingerprint.slice(0, 10)}`
              : ""}
          </small>
        </div>
      </div>
      <p className="score-limitation">
        This score describes synthetic fixtures within the saved test scope. It
        is not proof of universal security or an external-model benchmark.
      </p>
      {!!score.reasons.length && (
        <ul className="score-reasons">
          {score.reasons.map((reason) => (
            <li key={reason}>{reason}</li>
          ))}
        </ul>
      )}
      <div className="score-counts">
        <div>
          <strong>{score.completed_tests}</strong>
          <span>Completed</span>
        </div>
        {Object.entries(score.counts).map(([status, count]) => (
          <div key={status}>
            <strong>{count}</strong>
            <span>{words(status)}</span>
          </div>
        ))}
      </div>
      <div className="score-evidence-summary">
        <div>
          <span>Verified severity</span>
          <div>
            {Object.entries(score.severity_distribution).map(
              ([severity, count]) => (
                <span
                  key={severity}
                  className={`severity severity-${severity}`}
                >
                  {severity}: {count}
                </span>
              ),
            )}
          </div>
        </div>
        <p>
          {score.authorization_violations} authorization violations ·{" "}
          {score.successful_adversarial_scenarios} confirmed mock executions ·{" "}
          {score.outcomes.blocked} confirmed blocks ·{" "}
          {score.outcomes.attempt_unconfirmed} attempts with execution
          unconfirmed
        </p>
      </div>
      <details className="score-explanation">
        <summary>Inspect the scoring calculation and methodology</summary>
        <p>
          Each case has its severity weight plus{" "}
          {score.methodology.authorization_weight} authorization points. A
          verified executed or unconfirmed attempt loses its full weight; a
          confirmed block loses half. Untested and inconclusive cases reduce
          coverage.
        </p>
        <div className="score-calculation">
          <span>
            Coverage points{" "}
            <strong>{points(score.breakdown.coverage_points)}</strong>
          </span>
          <span>
            Risk penalty{" "}
            <strong>−{points(score.breakdown.risk_penalty)}</strong>
          </span>
          <span>
            Raw assessment <strong>{points(score.breakdown.raw_score)}</strong>
          </span>
          <span>
            Severity cap <strong>{score.breakdown.cap}</strong>
          </span>
          <span>
            Final score <strong>{score.score ?? "Withheld"}</strong>
          </span>
        </div>
        <p className="form-hint">
          At least {score.methodology.minimum_determinate_tests} determinate
          tests and {score.methodology.minimum_coverage_percent}% of the full
          saved adapter catalog are required. Values use exact fractions
          internally and round half up once. Triage status does not affect this
          assessment.
        </p>
        <dl className="methodology-facts">
          <dt>Formula</dt>
          <dd>
            <code>{score.methodology.formula}</code>
          </dd>
          <dt>Severity weights</dt>
          <dd>
            {Object.entries(score.methodology.severity_weights)
              .map(([key, value]) => `${key}: ${value}`)
              .join(" · ")}
          </dd>
          <dt>Severity caps</dt>
          <dd>
            {Object.entries(score.methodology.caps).map(([key, value]) => (
              <span key={key}>
                {words(key)}: {value}
                <br />
              </span>
            ))}
          </dd>
          <dt>Catalog / loss weight</dt>
          <dd>
            {score.breakdown.catalog_weight} / {score.breakdown.loss_weight}
          </dd>
        </dl>
        {!!score.breakdown.cap_reasons.length && (
          <ul className="score-reasons">
            {score.breakdown.cap_reasons.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
        )}
        {!!score.integrity_issues.length && (
          <div className="error" role="alert">
            {score.integrity_issues.map((issue) => (
              <p key={issue}>{issue}</p>
            ))}
          </div>
        )}
        {!!score.breakdown.cases.length && (
          <div className="table-scroll">
            <table className="score-case-table">
              <caption>
                Case loss weights are normalized by the full catalog weight.
                Original trace references remain attached to each case.
              </caption>
              <thead>
                <tr>
                  <th>Scenario</th>
                  <th>Result / Observation</th>
                  <th>Weight</th>
                  <th>Loss</th>
                </tr>
              </thead>
              <tbody>
                {score.breakdown.cases.map((item) => (
                  <tr key={item.scenario_id}>
                    <td>
                      {linkToResults ? (
                        <a href={`#result-${entry.run_id}-${item.scenario_id}`}>
                          {item.scenario_id}
                        </a>
                      ) : (
                        item.scenario_id
                      )}
                      <small>
                        v{item.scenario_version} · {item.severity}
                      </small>
                    </td>
                    <td>
                      {item.status}
                      <small>
                        {item.outcome
                          ? words(item.outcome)
                          : "No verified violation"}
                        {item.evidence_sequences.length
                          ? ` · events ${item.evidence_sequences.join(", ")}`
                          : ""}
                      </small>
                    </td>
                    <td>{item.weight}</td>
                    <td>{item.loss_weight}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <ul className="score-reasons">
          {score.methodology.limitations.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </details>
    </div>
  );
}

export function RunScore({ runId, status }: { runId: string; status: string }) {
  const score = useQuery({
    queryKey: ["run-score", runId, status],
    queryFn: () => request<Entry>(`/runs/${runId}/score`),
    refetchInterval: ["queued", "running", "cancelling"].includes(status)
      ? 1000
      : false,
  });
  if (score.isPending)
    return <p className="score-loading">Loading assessment score…</p>;
  if (score.error)
    return (
      <p className="error" role="alert">
        {score.error.message}
        <button className="secondary" onClick={() => void score.refetch()}>
          Retry
        </button>
      </p>
    );
  return score.data ? <ScoreCard entry={score.data} linkToResults /> : null;
}

export function ScoreOverview({
  projectId,
  agents,
}: {
  projectId: string;
  agents: Agent[];
}) {
  const [selected, setSelected] = useState("");
  const agentId = agents.some((a) => a.id === selected)
    ? selected
    : agents[0]?.id || "";
  const group = useQuery({
    queryKey: ["agent-scores", projectId, agentId],
    queryFn: () =>
      request<{ agent_name: string; latest: Entry | null; history: Entry[] }>(
        `/projects/${projectId}/scores?agent_id=${agentId}`,
      ),
    enabled: !!projectId && !!agentId,
    refetchInterval: 5000,
  });
  const latest = group.data?.latest;
  const history = group.data?.history || [];
  const data = history.map((entry) => ({
    run: entry.run_id.slice(0, 8),
    date: new Date(entry.created_at).toLocaleString(),
    score: entry.assessment.score,
  }));
  return (
    <section className="panel score-overview" id="security-score">
      <div className="panel-heading">
        <h2>Assessment score and coverage</h2>
        <span>VERSIONED · EVIDENCE-BACKED</span>
      </div>
      <div className="score-overview-content">
        <label htmlFor="score-agent">Agent assessment scope</label>
        <select
          id="score-agent"
          value={agentId}
          onChange={(e) => setSelected(e.target.value)}
          disabled={!agents.length}
        >
          {!agents.length && <option value="">Register an agent first</option>}
          {agents.map((a) => (
            <option key={a.id} value={a.id}>
              {a.name}
            </option>
          ))}
        </select>
        {group.error ? (
          <p className="error" role="alert">
            {group.error.message}
            <button className="secondary" onClick={() => void group.refetch()}>
              Retry
            </button>
          </p>
        ) : !agentId ? (
          <p className="empty-run">
            Register an agent and execute a suite to begin a scoped assessment.
          </p>
        ) : group.isPending ? (
          <p className="score-loading">Loading saved assessments…</p>
        ) : latest ? (
          <>
            <ScoreCard entry={latest} />
            <div className="score-trend">
              <h3>Comparable assessment history</h3>
              <p>
                Up to 20 recent runs with the same adapter, policy, engine,
                runtime versions, selected cases, and scoring catalog. Unscored
                runs remain gaps.
              </p>
              {data.filter((point) => point.score !== null).length >= 2 ? (
                <div
                  className="score-chart"
                  role="img"
                  aria-label="Security score history for matching assessment scopes, from zero to one hundred"
                >
                  <ResponsiveContainer width="100%" height={220} minWidth={0}>
                    <LineChart
                      data={data}
                      margin={{ top: 15, right: 20, left: -15, bottom: 5 }}
                      accessibilityLayer
                    >
                      <CartesianGrid
                        stroke="#222a39"
                        strokeDasharray="3 3"
                        vertical={false}
                      />
                      <XAxis
                        dataKey="run"
                        stroke="#8291a9"
                        tick={{ fontSize: 10 }}
                        tickLine={false}
                        axisLine={false}
                      />
                      <YAxis
                        domain={[0, 100]}
                        stroke="#8291a9"
                        tick={{ fontSize: 10 }}
                        tickLine={false}
                        axisLine={false}
                      />
                      <Tooltip
                        contentStyle={{
                          background: "#101622",
                          border: "1px solid #343c50",
                          borderRadius: 6,
                        }}
                        labelFormatter={(value) =>
                          data.find((point) => point.run === value)?.date ||
                          String(value)
                        }
                      />
                      <Line
                        type="linear"
                        dataKey="score"
                        name="Scoped score"
                        stroke="#a293ff"
                        strokeWidth={2}
                        dot={{ r: 3, fill: "#a293ff" }}
                        connectNulls={false}
                        isAnimationActive={false}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <p className="empty-run">
                  Two comparable scored runs are needed to display a trend.
                </p>
              )}
              <details className="score-history">
                <summary>View recorded assessment history</summary>
                <table className="score-case-table">
                  <thead>
                    <tr>
                      <th>Run / Date</th>
                      <th>Score</th>
                      <th>Coverage</th>
                      <th>Run state</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map((entry) => (
                      <tr key={entry.run_id}>
                        <td>
                          {entry.run_id.slice(0, 8)}
                          <small>
                            {new Date(entry.created_at).toLocaleString()}
                          </small>
                        </td>
                        <td>{entry.assessment.score ?? "Not scored"}</td>
                        <td>{entry.assessment.coverage_percent}%</td>
                        <td>{entry.run_status}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </details>
            </div>
            <a className="export-link" href={`/findings?project=${projectId}`}>
              Inspect project findings ↗
            </a>
          </>
        ) : (
          <p className="empty-run">
            No assessment has run for this agent. Run a full suite to collect
            scoring evidence.
          </p>
        )}
      </div>
    </section>
  );
}
