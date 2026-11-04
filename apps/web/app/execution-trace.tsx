export type TraceEvent = {
  sequence: number;
  kind: string;
  trust: string;
  timestamp?: string;
  data: Record<string, unknown>;
};

export function ExecutionTrace({
  events,
  evidenceSequences = [],
  idPrefix = "trace",
}: {
  events: TraceEvent[];
  evidenceSequences?: number[];
  idPrefix?: string;
}) {
  return (
    <ol className="trace">
      {events.map((event) => (
        <li
          key={event.sequence}
          id={`${idPrefix}-${event.sequence}`}
          className={
            evidenceSequences.includes(event.sequence) ? "evidence-event" : ""
          }
        >
          <details
            open={
              evidenceSequences.includes(event.sequence) ||
              event.kind === "untrusted_content" ||
              event.kind === "policy_decision"
            }
          >
            <summary>
              <span>
                {String(event.sequence).padStart(2, "0")} /{" "}
                {event.kind.replaceAll("_", " ")}
              </span>
              <small>
                {event.trust === "trusted"
                  ? "Trusted user"
                  : event.trust === "untrusted"
                    ? "Untrusted source"
                    : "Engine / adapter"}
              </small>
            </summary>
            {evidenceSequences.includes(event.sequence) && (
              <span className="evidence-label">Policy violation evidence</span>
            )}
            <pre>{JSON.stringify(event.data, null, 2)}</pre>
            <time className="event-time" dateTime={event.timestamp}>
              {event.timestamp
                ? new Date(event.timestamp).toLocaleString()
                : "Timestamp unavailable in legacy trace"}
            </time>
          </details>
        </li>
      ))}
    </ol>
  );
}
