"""The public kit bundle is engine output, and the publisher cannot update main."""

import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from veyrix.adapters import SYNTHETIC_SECRET
from veyrix.kit_snapshot import (
    PUBLICATION_URL,
    SNAPSHOT_PATH,
    assemble_publication,
    build_bundle,
    load_report,
    main,
    write_bundle,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "veyrix-action" / "publish_kit_branch.sh"
SKIP_CONFIG = ROOT / ".github" / "veyrix-action" / "kit-scans.vercel.json"
PUBLISH_MESSAGE = "Publish scheduled scan of the local fixtures."
DROP = {
    "timestamp",
    "created_at",
    "observed_at",
    "generated_at",
    "published_at",
    "started_at",
    "finished_at",
    "python_version",
    "scope_fingerprint",
    "run_url",
    "run_id",
    "sha",
    "ref",
}


def scrub(value):
    if isinstance(value, dict):
        return {key: scrub(item) for key, item in value.items() if key not in DROP}
    if isinstance(value, list):
        items = [scrub(item) for item in value]
        if items and all(isinstance(item, dict) and "scenario_id" in item for item in items):
            return sorted(items, key=lambda item: item["scenario_id"])
        return items
    return value


def canonical(document):
    return scrub(json.loads(json.dumps(document)))


def git_text(remote, *args):
    return subprocess.check_output(["git", "--git-dir", str(remote), *args], text=True)


def publish_env(remote):
    env = os.environ.copy()
    env.pop("GITHUB_ACTIONS", None)
    env.pop("GITHUB_TOKEN", None)
    env["VEYRIX_KIT_PUSH_REMOTE"] = str(remote)
    return env


def run_publish(remote, payload):
    return subprocess.run(
        ["bash", str(SCRIPT), str(payload)],
        check=False,
        env=publish_env(remote),
        text=True,
        capture_output=True,
    )


def seed_main(tmp_path):
    remote = tmp_path / "remote.git"
    seed = tmp_path / "seed"
    subprocess.run(["git", "init", "--bare", "-b", "main", str(remote)], check=True)
    subprocess.run(["git", "init", "-b", "main", str(seed)], check=True)
    subprocess.run(
        ["git", "-C", str(seed), "config", "user.email", "tester@example.com"],
        check=True,
    )
    subprocess.run(["git", "-C", str(seed), "config", "user.name", "Tester"], check=True)
    (seed / "README").write_text("main stays untouched\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(seed), "add", "README"], check=True)
    subprocess.run(["git", "-C", str(seed), "commit", "-m", "seed main"], check=True)
    subprocess.run(["git", "-C", str(seed), "push", str(remote), "HEAD:refs/heads/main"], check=True)
    return remote


def assert_kit_scans_tree(remote, payload):
    tree = git_text(remote, "ls-tree", "-r", "--name-only", "kit-scans").splitlines()
    assert tree == ["apps/web/vercel.json", "latest.json"]
    assert git_text(remote, "show", "kit-scans:latest.json") == payload.read_text(encoding="utf-8")
    assert git_text(remote, "show", "kit-scans:apps/web/vercel.json") == SKIP_CONFIG.read_text(
        encoding="utf-8"
    )
    assert git_text(remote, "log", "-1", "--format=%s", "kit-scans").strip() == PUBLISH_MESSAGE
    config = json.loads(SKIP_CONFIG.read_text(encoding="utf-8"))
    assert config["git"]["deploymentEnabled"] == {"kit-scans": False}
    assert config["ignoreCommand"] == "exit 0"


def load_snapshot():
    assert SNAPSHOT_PATH.is_file(), "Run python -m veyrix.kit_snapshot before testing the kit file"
    return json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))


def test_committed_kit_scan_matches_a_fresh_export():
    fresh = build_bundle("committed-snapshot", datetime.now(UTC))
    assert canonical(load_snapshot()) == canonical(fresh)


def test_kit_scan_scores_are_the_local_fixtures():
    bundle = load_snapshot()
    vulnerable = bundle["scans"]["vulnerable"]
    hardened = bundle["scans"]["hardened"]
    assert bundle["format_version"] == 1
    assert bundle["generator"] == "veyrix.kit_snapshot"
    assert bundle["source"] == "committed-snapshot"
    assert bundle["publication_url"] == PUBLICATION_URL
    assert "deliberately vulnerable" in bundle["fixture_note"]
    assert vulnerable["score"]["score"] == 4
    assert vulnerable["target"]["variant"] == "vulnerable"
    assert len(vulnerable["findings"]) == 12
    assert hardened["score"]["score"] == 100
    assert hardened["findings"] == []
    assert hardened["score"]["counts"]["PASS"] == 12
    finding = next(
        item for item in vulnerable["findings"] if item["scenario_id"] == "document-injection"
    )
    events = finding["result"]["events"]
    assert [event["sequence"] for event in events] == list(range(1, len(events) + 1))
    assert any(event["kind"] == "untrusted_content" for event in events)
    assert events[-1]["kind"] == "policy_decision"
    assert SYNTHETIC_SECRET not in SNAPSHOT_PATH.read_text(encoding="utf-8")


def test_assemble_rejects_a_mismatched_or_unordered_report():
    bundle = load_snapshot()
    vulnerable = bundle["scans"]["vulnerable"]
    hardened = bundle["scans"]["hardened"]
    try:
        assemble_publication(
            hardened,
            vulnerable,
            source="github-actions",
            published_at=datetime.now(UTC),
        )
    except ValueError as exc:
        assert "vulnerable" in str(exc)
    else:
        raise AssertionError("swapped fixtures were accepted")
    broken = json.loads(json.dumps(vulnerable))
    broken["results"][0]["events"] = list(reversed(broken["results"][0]["events"]))
    try:
        assemble_publication(
            broken,
            hardened,
            source="committed-snapshot",
            published_at=datetime.now(UTC),
        )
    except ValueError as exc:
        assert "not ordered" in str(exc)
    else:
        raise AssertionError("unordered trace was accepted")


def test_build_source_cannot_replace_the_committed_file(tmp_path):
    assert write_bundle("build", tmp_path / "kit-scan.generated.json").is_file()
    try:
        write_bundle("build", SNAPSHOT_PATH)
    except ValueError as exc:
        assert "committed snapshot" in str(exc)
    else:
        raise AssertionError("build output was allowed to replace the committed snapshot")


def test_publish_command_wraps_reports_without_a_new_scan(tmp_path, monkeypatch):
    bundle = load_snapshot()
    vulnerable = tmp_path / "nested" / "vulnerable.json"
    hardened = tmp_path / "other" / "hardened.json"
    vulnerable.parent.mkdir()
    hardened.parent.mkdir()
    vulnerable.write_text(json.dumps(bundle["scans"]["vulnerable"]), encoding="utf-8")
    hardened.write_text(json.dumps(bundle["scans"]["hardened"]), encoding="utf-8")
    output = tmp_path / "latest.json"
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
    monkeypatch.setenv("GITHUB_REPOSITORY", "khushi491/Veyrix")
    monkeypatch.setenv("GITHUB_RUN_ID", "4242")
    monkeypatch.setenv("GITHUB_SHA", "abc123")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    code = main(
        [
            "publish",
            "--artifacts",
            str(tmp_path),
            "--output",
            str(output),
        ]
    )
    assert code == 0
    published = json.loads(output.read_text(encoding="utf-8"))
    assert published["source"] == "github-actions"
    assert published["run_url"] == "https://github.com/khushi491/Veyrix/actions/runs/4242"
    assert published["run_id"] == "4242"
    assert published["sha"] == "abc123"
    assert load_report(output)["scans"]["vulnerable"]["score"]["score"] == 4


def test_publish_branch_script_does_not_update_main(tmp_path):
    remote = seed_main(tmp_path)
    main_before = git_text(remote, "rev-parse", "refs/heads/main").strip()
    payload = tmp_path / "latest.json"
    payload.write_text('{"format_version": 1}\n', encoding="utf-8")
    first = run_publish(remote, payload)
    assert first.returncode == 0, first.stderr
    assert "Published kit-scans" in first.stdout
    assert git_text(remote, "rev-parse", "refs/heads/main").strip() == main_before
    assert_kit_scans_tree(remote, payload)
    branches = git_text(remote, "branch")
    assert "main" in branches
    assert "kit-scans" in branches
    payload.write_text('{"format_version": 1, "source": "github-actions"}\n', encoding="utf-8")
    second = run_publish(remote, payload)
    assert second.returncode == 0, second.stderr
    assert_kit_scans_tree(remote, payload)
    assert git_text(remote, "rev-parse", "refs/heads/main").strip() == main_before


def test_publish_adds_vercel_skip_when_the_scan_json_is_unchanged(tmp_path):
    remote = seed_main(tmp_path)
    main_before = git_text(remote, "rev-parse", "refs/heads/main").strip()
    payload = tmp_path / "latest.json"
    payload.write_text('{"format_version": 1}\n', encoding="utf-8")
    orphan = tmp_path / "orphan"
    subprocess.run(["git", "init", "-b", "kit-scans", str(orphan)], check=True)
    subprocess.run(
        ["git", "-C", str(orphan), "config", "user.email", "tester@example.com"],
        check=True,
    )
    subprocess.run(["git", "-C", str(orphan), "config", "user.name", "Tester"], check=True)
    (orphan / "latest.json").write_text(payload.read_text(encoding="utf-8"), encoding="utf-8")
    subprocess.run(["git", "-C", str(orphan), "add", "latest.json"], check=True)
    subprocess.run(["git", "-C", str(orphan), "commit", "-m", "existing scan"], check=True)
    subprocess.run(
        ["git", "-C", str(orphan), "push", str(remote), "HEAD:refs/heads/kit-scans"],
        check=True,
    )
    before = git_text(remote, "rev-parse", "refs/heads/kit-scans").strip()
    assert git_text(remote, "ls-tree", "-r", "--name-only", "kit-scans").splitlines() == [
        "latest.json"
    ]
    first = run_publish(remote, payload)
    assert first.returncode == 0, first.stderr
    assert "Published kit-scans" in first.stdout
    after = git_text(remote, "rev-parse", "refs/heads/kit-scans").strip()
    assert after != before
    assert_kit_scans_tree(remote, payload)
    assert git_text(remote, "rev-parse", "refs/heads/main").strip() == main_before
    second = run_publish(remote, payload)
    assert second.returncode == 0, second.stderr
    assert "already matches this scan JSON and Vercel skip config" in second.stdout
    assert git_text(remote, "rev-parse", "refs/heads/kit-scans").strip() == after
    assert git_text(remote, "rev-parse", "refs/heads/main").strip() == main_before


def test_kit_page_reads_the_publication_on_each_request():
    loader = (ROOT / "apps" / "web" / "lib" / "kit-scan.ts").read_text(encoding="utf-8")
    page = (ROOT / "apps" / "web" / "app" / "kit" / "page.tsx").read_text(encoding="utf-8")
    assert 'cache: "no-store"' in loader
    assert "revalidate: 900" not in loader
    assert "revalidate: 900" not in page
    assert 'export const dynamic = "force-dynamic"' in page
    assert "export const revalidate" not in page


def test_workflow_publishes_off_main_and_skips_pull_requests():
    workflow = (ROOT / ".github" / "workflows" / "veyrix-scan.yml").read_text(encoding="utf-8")
    script = SCRIPT.read_text(encoding="utf-8")
    loader = (ROOT / "apps" / "web" / "lib" / "kit-scan.ts").read_text(encoding="utf-8")
    block = workflow.split("publish-kit-scan:", 1)[1]
    assert "github.event_name != 'pull_request'" in block
    assert "github.ref == 'refs/heads/main'" in block
    assert "contents: write" in block
    assert "continue-on-error: true" in block
    assert "secrets." not in block
    assert "publish_kit_branch.sh" in block
    assert "apps/web/vercel.json" in workflow
    assert "HEAD:refs/heads/${branch}" in script
    assert "HEAD:refs/heads/main" not in script
    assert "HEAD:main" not in script
    assert "apps/web/vercel.json" in script
    assert "kit-scans.vercel.json" in script
    config = json.loads(SKIP_CONFIG.read_text(encoding="utf-8"))
    assert config["git"]["deploymentEnabled"]["kit-scans"] is False
    assert config["ignoreCommand"] == "exit 0"
    assert "deploymentEnabled" not in (ROOT / "apps" / "web" / "vercel.json").read_text(
        encoding="utf-8"
    )
    assert PUBLICATION_URL in loader
