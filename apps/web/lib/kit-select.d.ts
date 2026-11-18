export const SAME_COMMIT_REASON: string;
export const NEWER_REMOTE_REASON: string;
export const BUILD_FALLBACK_REASON: string;
export const COMMITTED_FALLBACK_REASON: string;

export type KitSelectable = {
  source: "github-actions" | "build" | "committed-snapshot";
  published_at: string;
  sha: string | null;
  scans: {
    vulnerable: { engine_version: string; scoring_version: string };
    hardened: { engine_version: string; scoring_version: string };
  };
};

export function selectKit<T extends KitSelectable>(input: {
  remote: T | null;
  local: T;
  deploymentSha: string | null;
}): { bundle: T; reason: string };
