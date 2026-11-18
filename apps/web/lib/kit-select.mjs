export const SAME_COMMIT_REASON =
  "This deployment was built from the same commit the scheduled scan ran.";
export const NEWER_REMOTE_REASON =
  "The scheduled publication is newer than the scan shipped with this deployment.";
export const BUILD_FALLBACK_REASON =
  "Showing the scan generated while this site was built. The scheduled publication is not newer.";
export const COMMITTED_FALLBACK_REASON =
  "Showing the scan committed with this deployment. The scheduled publication is not available yet, or it is older or from a different engine.";

function versionsMatch(remote, local) {
  return ["vulnerable", "hardened"].every(
    (variant) =>
      remote.scans[variant].engine_version === local.scans[variant].engine_version &&
      remote.scans[variant].scoring_version === local.scans[variant].scoring_version,
  );
}

// Prefer the scheduled publication when it is valid for this deployment.
// A matching commit wins even if a build-time scan is newer, because that
// publication is the daily run of this exact tree. Any other publication is
// used only when it is at least as new as the scan shipped with the deployment
// and the engine and scoring versions match. Otherwise the shipped scan is shown.
export function selectKit(input) {
  const { remote, local, deploymentSha } = input;
  if (remote && versionsMatch(remote, local)) {
    if (
      remote.source === "github-actions" &&
      deploymentSha !== null &&
      remote.sha === deploymentSha
    ) {
      return { bundle: remote, reason: SAME_COMMIT_REASON };
    }
    if (Date.parse(remote.published_at) >= Date.parse(local.published_at)) {
      return { bundle: remote, reason: NEWER_REMOTE_REASON };
    }
  }
  if (local.source === "build") {
    return { bundle: local, reason: BUILD_FALLBACK_REASON };
  }
  return { bundle: local, reason: COMMITTED_FALLBACK_REASON };
}
