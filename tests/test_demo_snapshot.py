"""The committed demo snapshot must be regenerated engine output, not hand-written."""

import json

from veyrix.adapters import SYNTHETIC_SECRET
from veyrix.demo_snapshot import SNAPSHOT_PATH, build_snapshot
from veyrix.engine import SCENARIOS, run_scenario
from veyrix.findings import verified_result
from veyrix.scoring import calculate_score

DROP = {
    "timestamp",
    "created_at",
    "observed_at",
    "generated_at",
    "started_at",
    "finished_at",
    "python_version",
    "scope_fingerprint",
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


def canonical(snapshot):
    return scrub(json.loads(json.dumps(snapshot)))


def load_snapshot():
    assert SNAPSHOT_PATH.is_file(), "Run make demo-snapshot before testing the demo file"
    return json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))


def test_committed_snapshot_matches_a_fresh_engine_export():
    assert canonical(load_snapshot()) == canonical(build_snapshot())


def test_snapshot_scores_and_findings_are_engine_results():
    snapshot = load_snapshot()
    scores = {}
    assert snapshot["format_version"] == 1
    assert snapshot["generator"] == "veyrix.demo_snapshot"
    assert [agent["variant"] for agent in snapshot["agents"]] == ["vulnerable", "hardened"]
    assert len(snapshot["runs"]) == 2
    for run in snapshot["runs"]:
        variant = run["configuration"]["variant"]
        policy = run["configuration"]["policy"]
        assert run["status"] == "completed"
        assert [item["id"] for item in run["configuration"]["scenarios"]] == [
            scenario.id for scenario in SCENARIOS
        ]
        for result in run["results"]:
            scenario = next(item for item in SCENARIOS if item.id == result["scenario_id"])
            live = run_scenario(variant, policy, scenario)
            assert scrub(live) == scrub(result)
            evidence = verified_result(result, policy)
            finding = next(
                (
                    item
                    for item in snapshot["findings"]
                    if item["run_id"] == run["id"] and item["scenario_id"] == result["scenario_id"]
                ),
                None,
            )
            if result["evaluation"]["status"] == "FAIL":
                assert finding is not None
                assert scrub(finding["result"]) == scrub(evidence)
                assert finding["status"] == "open"
                assert finding["history"] == []
            else:
                assert evidence is None
                assert finding is None
        stored = snapshot["score_entries"][run["id"]]["assessment"]
        assert stored == calculate_score(run["configuration"], run["results"], run["status"])
        scores[variant] = stored["score"]
    assert scores == {"vulnerable": 4, "hardened": 100}
    assert sum(1 for finding in snapshot["findings"] if finding["executed"]) == 11
    assert sum(1 for finding in snapshot["findings"] if not finding["executed"]) == 1


def test_snapshot_redacts_the_synthetic_secret_and_has_no_dev_credentials():
    raw = SNAPSHOT_PATH.read_text(encoding="utf-8")
    assert SYNTHETIC_SECRET not in raw
    assert "[REDACTED_SYNTHETIC_SECRET]" in raw
    lowered = raw.lower()
    assert "veyrix_dev_mode" not in lowered
    assert "database_url" not in lowered
    assert "redis_url" not in lowered
