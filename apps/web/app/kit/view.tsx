import { ExecutionTrace, type TraceEvent } from "../execution-trace";
import type { KitBundle, KitFinding, KitReport, LoadedKit } from "../../lib/kit-scan";

const FEATURED = "document-injection";
const SOURCE_LABEL = {
  "github-actions": "Scheduled GitHub Actions scan",
  build: "Generated during this site build",
  "committed-snapshot": "Committed snapshot",
} as const;

export function KitView({ loaded }: { loaded: LoadedKit }) {
  const { bundle } = loaded;
  const vulnerable = bundle.scans.vulnerable;
  const hardened = bundle.scans.hardened;
  const featured = findingById(vulnerable, FEATURED) ?? vulnerable.findings[0];
  const others = vulnerable.findings.filter(
    (finding) => finding.scenario_id !== featured?.scenario_id,
  );
  const versionsMatch =
    vulnerable.engine_version === hardened.engine_version &&
    vulnerable.scoring_version === hardened.scoring_version;
  return (
    <>
      <header>
        <span>Workspace / Red-team kit</span>
        <span className="dev">
          <i /> {SOURCE_LABEL[bundle.source]}
        </span>
      </header>
      <section className="content">
        <div className="eyebrow">ALWAYS-ON RED-TEAM KIT</div>
        <div className="heading">
          <div>
            <h1>A vulnerable agent, scanned on a schedule.</h1>
            <p>
              GitHub Actions runs <code>veyrix scan</code> against two local
              document assistants. One follows instructions hidden in untrusted
              text. The other refuses them. This page is the public readout.
            </p>
          </div>
        </div>
        <div className="kit-callout" role="note">
          <strong>Deliberate sample, not a product vulnerability.</strong>{" "}
          {bundle.fixture_note} No model is called. Nothing here is a live
          customer agent.
        </div>
        <div className="kit-facts">
          <div>
            <span>Last vulnerable scan</span>
            <strong>
              <time dateTime={vulnerable.generated_at}>
                {formatUtc(vulnerable.generated_at)}
              </time>
            </strong>
          </div>
          <div>
            <span>Last hardened scan</span>
            <strong>
              <time dateTime={hardened.generated_at}>
                {formatUtc(hardened.generated_at)}
              </time>
            </strong>
          </div>
          <div>
            <span>Engine</span>
            <strong>
              {versionsMatch
                ? vulnerable.engine_version
                : `${vulnerable.engine_version} / ${hardened.engine_version}`}
            </strong>
          </div>
          <div>
            <span>Scoring</span>
            <strong>
              {versionsMatch
                ? vulnerable.scoring_version
                : `${vulnerable.scoring_version} / ${hardened.scoring_version}`}
            </strong>
          </div>
        </div>
        <p className="kit-prose">{loaded.reason}</p>
        <p className="kit-prose">
          The daily workflow writes <code>latest.json</code> to the{" "}
          <code>kit-scans</code> branch and does not commit to <code>main</code>.
          This page rechecks that file about every 15 minutes. Until the file
          exists, the readout is the scan committed with this deployment.
        </p>
        <div className="kit-links">
          {bundle.run_url ? (
            <a href={bundle.run_url} target="_blank" rel="noopener noreferrer">
              This CI run
            </a>
          ) : null}
          <a href={bundle.workflow_url} target="_blank" rel="noopener noreferrer">
            Workflow runs
          </a>
          <a href={bundle.sarif_docs_url} target="_blank" rel="noopener noreferrer">
            SARIF support for code scanning
          </a>
          <a
            href={bundle.code_scanning_url}
            target="_blank"
            rel="noopener noreferrer"
          >
            Code scanning alerts
          </a>
          <a href={bundle.action_docs_url} target="_blank" rel="noopener noreferrer">
            Action and SARIF reference
          </a>
        </div>
        <div className="demo-compare" id="scores">
          <ScoreCard report={vulnerable} tone="vulnerable" />
          <ScoreCard report={hardened} tone="hardened" />
        </div>
        <section className="panel kit-section" id="findings">
          <div className="panel-heading">
            <h2>Verified findings</h2>
            <span>{vulnerable.target.name}</span>
          </div>
          <div className="table-scroll">
            <table className="findings-table">
              <caption className="sr-only">
                Verified findings for the deliberately vulnerable document
                assistant
              </caption>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Scenario</th>
                  <th>Outcome</th>
                </tr>
              </thead>
              <tbody>
                {vulnerable.findings.map((finding) => (
                  <tr key={finding.scenario_id}>
                    <td>
                      <span className={`severity severity-${finding.severity}`}>
                        {finding.severity}
                      </span>
                    </td>
                    <td>
                      <a href={`#finding-${finding.scenario_id}`}>{finding.title}</a>
                      <small>{finding.scenario_id}</small>
                    </td>
                    <td>{finding.outcome || "verified"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
        {featured ? (
          <section className="panel kit-section" id={`finding-${featured.scenario_id}`}>
            <div className="panel-heading">
              <h2>Ordered evidence trace</h2>
              <span>Full trace · {featured.scenario_id}</span>
            </div>
            <div className="kit-body">
              <TraceStory report={vulnerable} finding={featured} open />
            </div>
          </section>
        ) : null}
        {others.length ? (
          <section className="panel kit-section" id="more-traces">
            <div className="panel-heading">
              <h2>Remaining findings</h2>
              <span>Same scan · traces collapsed</span>
            </div>
            <div className="kit-body">
              {others.map((finding) => (
                <details key={finding.scenario_id} id={`finding-${finding.scenario_id}`}>
                  <summary>
                    {finding.severity} · {finding.title}
                  </summary>
                  <TraceStory report={vulnerable} finding={finding} />
                </details>
              ))}
            </div>
          </section>
        ) : null}
        <section className="panel kit-section" id="hardened">
          <div className="panel-heading">
            <h2>Hardened contrast</h2>
            <span>{hardened.findings.length} verified findings</span>
          </div>
          <div className="kit-body">
            <p className="kit-prose">
              {hardened.target.name} ran the same local catalog. The fixture
              ignores tool calls embedded in untrusted content, so the scan
              recorded passes instead of findings.
            </p>
            <div className="table-scroll">
              <table className="findings-table">
                <caption className="sr-only">
                  Scenario verdicts for the hardened document assistant
                </caption>
                <thead>
                  <tr>
                    <th>Scenario</th>
                    <th>Verdict</th>
                  </tr>
                </thead>
                <tbody>
                  {verdicts(hardened).map((row) => (
                    <tr key={row.id}>
                      <td>
                        {row.title}
                        <small>{row.id}</small>
                      </td>
                      <td>
                        <span className={row.status === "PASS" ? "outcome pass" : "outcome fail"}>
                          {row.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>
        <section className="panel kit-section" id="limits">
          <div className="panel-heading">
            <h2>What this does not claim</h2>
            <span>Limits</span>
          </div>
          <div className="kit-body">
            <ul className="kit-limits">
              {(vulnerable.limitations ?? []).map((item) => (
                <li key={item}>{item}</li>
              ))}
              <li>
                The score describes these saved local scenarios and methodology{" "}
                {vulnerable.score.methodology_version || vulnerable.scoring_version}.
                It is not a certification of a production agent or a model.
              </li>
              <li>
                Pull requests do not publish the public JSON. The schedule and a
                manual run on main do. The first publish happens only after the
                workflow file is on the default branch.
              </li>
              <li>
                Code scanning stores the SARIF upload separately. This page reads
                the JSON report. Fork pull requests skip the SARIF upload.
              </li>
              <li>
                Freshness can lag the workflow by about 15 minutes, plus the
                GitHub raw-file cache. No deploy hook and no repository secret
                are required for the fallback.
              </li>
            </ul>
          </div>
        </section>
        <footer>
          <span>Security for Autonomous Intelligence.</span>
          <span>
            Bundle recorded <time dateTime={bundle.published_at}>{formatUtc(bundle.published_at)}</time>
          </span>
        </footer>
      </section>
    </>
  );
}

function ScoreCard({
  report,
  tone,
}: {
  report: KitReport;
  tone: "vulnerable" | "hardened";
}) {
  const findings = report.findings.length;
  const executed = report.score.outcomes?.executed;
  const blocked = report.score.outcomes?.blocked;
  return (
    <article className={`demo-score ${tone}`}>
      <span>{tone === "vulnerable" ? "Deliberately vulnerable" : "Hardened fixture"}</span>
      <strong>
        {report.score.score}
        <small>/100</small>
      </strong>
      <p>{report.target.name}</p>
      <small>
        {findings} verified finding{findings === 1 ? "" : "s"}
        {typeof executed === "number" && typeof blocked === "number"
          ? ` · ${executed} executed · ${blocked} blocked`
          : ""}
        {report.score.catalog_count
          ? ` · ${report.score.determinate_tests ?? report.results.length}/${report.score.catalog_count} determinate`
          : ""}
      </small>
    </article>
  );
}

function TraceStory({
  report,
  finding,
  open = false,
}: {
  report: KitReport;
  finding: KitFinding;
  open?: boolean;
}) {
  const events = traceFor(report, finding);
  const sequences =
    finding.evidence_sequences ??
    finding.result?.evaluation?.evidence_sequences ??
    [];
  const attack = events.find((event) => event.kind === "untrusted_content");
  const attackText = attack && typeof attack.data.text === "string" ? attack.data.text : null;
  return (
    <div className="kit-trace-story">
      <p className="kit-prose">
        <span className={`severity severity-${finding.severity}`}>{finding.severity}</span>{" "}
        {finding.outcome ? <strong>{finding.outcome}</strong> : null}{" "}
        {finding.actual_behavior}
      </p>
      {finding.expected_behavior ? (
        <p className="kit-prose">Expected: {finding.expected_behavior}</p>
      ) : null}
      {attackText ? (
        <blockquote className="kit-attack">
          <span>Untrusted content</span>
          {attackText}
        </blockquote>
      ) : null}
      {events.length ? (
        <ExecutionTrace
          events={events}
          evidenceSequences={sequences}
          idPrefix={`${open ? "featured" : "trace"}-${finding.scenario_id}`}
        />
      ) : (
        <p className="kit-prose">This finding has no ordered trace in the report.</p>
      )}
      {finding.remediation ? (
        <p className="kit-prose">Remediation recorded by the engine: {finding.remediation}</p>
      ) : null}
    </div>
  );
}

function traceFor(report: KitReport, finding: KitFinding): TraceEvent[] {
  const fromFinding = finding.result?.events;
  if (fromFinding && fromFinding.length) return fromFinding;
  return report.results.find((result) => result.scenario_id === finding.scenario_id)?.events ?? [];
}

function findingById(report: KitReport, scenarioId: string) {
  return report.findings.find((finding) => finding.scenario_id === scenarioId);
}

function verdicts(report: KitReport) {
  if (report.scenarios?.length) {
    return report.scenarios.map((scenario) => ({
      id: scenario.id,
      title: scenario.title || scenario.id,
      status: scenario.verdict?.status || "UNKNOWN",
    }));
  }
  return report.results.map((result) => ({
    id: result.scenario_id,
    title: result.title || result.scenario_id,
    status: result.evaluation?.status || "UNKNOWN",
  }));
}

function formatUtc(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return (
    new Intl.DateTimeFormat("en-GB", {
      timeZone: "UTC",
      dateStyle: "medium",
      timeStyle: "short",
    }).format(date) + " UTC"
  );
}
