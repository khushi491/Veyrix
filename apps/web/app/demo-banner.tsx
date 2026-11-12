import { repositoryUrl } from "./demo-mode";

export function DemoBanner() {
  return (
    <div className="demo-banner" role="note">
      <p>
        Read-only demo. The workspace is a static snapshot: no database, worker,
        or model calls. The red-team kit shows the scheduled scan of the sample
        fixtures.
      </p>
      <span className="demo-banner-links">
        <a href="/kit">Red-team kit</a>
        <a href={repositoryUrl}>Repository</a>
      </span>
    </div>
  );
}
