import { repositoryUrl } from "./demo-mode";

export function DemoBanner() {
  return (
    <div className="demo-banner" role="note">
      <p>
        Read-only static snapshot of the Veyrix engine. No live scans, database,
        or worker are connected.
      </p>
      <a href={repositoryUrl}>View the repository</a>
    </div>
  );
}
