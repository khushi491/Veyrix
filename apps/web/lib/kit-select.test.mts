import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { validateBundle } from "./kit-scan.ts";
import {
  BUILD_FALLBACK_REASON,
  COMMITTED_FALLBACK_REASON,
  NEWER_REMOTE_REASON,
  SAME_COMMIT_REASON,
  selectKit,
} from "./kit-select.mjs";

const DEPLOY_SHA = "dc59dc144d83dcd44d8bc0d731ffbc4fab5062df";
const OTHER_SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

function candidate(overrides) {
  return {
    source: "github-actions",
    published_at: "2026-11-18T15:48:04.230895Z",
    sha: DEPLOY_SHA,
    scans: {
      vulnerable: { engine_version: "0.3.0", scoring_version: "1.0.0" },
      hardened: { engine_version: "0.3.0", scoring_version: "1.0.0" },
    },
    ...overrides,
    scans: {
      vulnerable: { engine_version: "0.3.0", scoring_version: "1.0.0" },
      hardened: { engine_version: "0.3.0", scoring_version: "1.0.0" },
      ...(overrides.scans ?? {}),
    },
  };
}

function localSnapshot(overrides = {}) {
  return candidate({
    source: "committed-snapshot",
    published_at: "2026-11-12T19:55:52.233920Z",
    sha: null,
    ...overrides,
  });
}

describe("selectKit", () => {
  it("uses a newer publication when the commit sha differs", () => {
    const local = localSnapshot();
    const remote = candidate({
      published_at: "2026-11-18T15:48:04.230895Z",
      sha: OTHER_SHA,
    });
    const chosen = selectKit({
      remote,
      local,
      deploymentSha: DEPLOY_SHA,
    });
    assert.equal(chosen.bundle, remote);
    assert.equal(chosen.reason, NEWER_REMOTE_REASON);
  });

  it("uses a newer publication for the same commit as this deployment", () => {
    const local = localSnapshot({ source: "build", published_at: "2026-11-13T14:42:32.000000Z" });
    const remote = candidate({
      published_at: "2026-11-18T15:48:04.230895Z",
      sha: DEPLOY_SHA,
    });
    const chosen = selectKit({
      remote,
      local,
      deploymentSha: DEPLOY_SHA,
    });
    assert.equal(chosen.bundle, remote);
    assert.equal(chosen.bundle.published_at, "2026-11-18T15:48:04.230895Z");
    assert.equal(chosen.reason, SAME_COMMIT_REASON);
  });

  it("falls back when the publication is missing", () => {
    const local = localSnapshot();
    const chosen = selectKit({
      remote: null,
      local,
      deploymentSha: DEPLOY_SHA,
    });
    assert.equal(chosen.bundle, local);
    assert.equal(chosen.reason, COMMITTED_FALLBACK_REASON);
  });

  it("falls back when a malformed publication is rejected", () => {
    const local = localSnapshot();
    const remote = validateBundle({ format_version: 1, source: "github-actions" });
    assert.equal(remote, null);
    const chosen = selectKit({
      remote,
      local,
      deploymentSha: DEPLOY_SHA,
    });
    assert.equal(chosen.bundle, local);
    assert.equal(chosen.reason, COMMITTED_FALLBACK_REASON);
  });

  it("falls back when the engine or scoring version does not match, even for the same commit", () => {
    const local = localSnapshot();
    const engineMismatch = candidate({
      sha: DEPLOY_SHA,
      scans: {
        vulnerable: { engine_version: "0.9.0", scoring_version: "1.0.0" },
        hardened: { engine_version: "0.3.0", scoring_version: "1.0.0" },
      },
    });
    const scoringMismatch = candidate({
      sha: DEPLOY_SHA,
      scans: {
        vulnerable: { engine_version: "0.3.0", scoring_version: "9.0.0" },
        hardened: { engine_version: "0.3.0", scoring_version: "1.0.0" },
      },
    });
    for (const remote of [engineMismatch, scoringMismatch]) {
      const chosen = selectKit({
        remote,
        local,
        deploymentSha: DEPLOY_SHA,
      });
      assert.equal(chosen.bundle, local);
      assert.equal(chosen.reason, COMMITTED_FALLBACK_REASON);
    }
  });

  it("keeps a newer shipped scan when the publication is older and from another commit", () => {
    const local = localSnapshot({
      source: "build",
      published_at: "2026-11-18T20:00:00.000Z",
    });
    const remote = candidate({
      published_at: "2026-11-13T14:43:05.000Z",
      sha: OTHER_SHA,
    });
    const chosen = selectKit({
      remote,
      local,
      deploymentSha: DEPLOY_SHA,
    });
    assert.equal(chosen.bundle, local);
    assert.equal(chosen.reason, BUILD_FALLBACK_REASON);
  });
});
