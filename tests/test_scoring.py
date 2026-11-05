import copy
from dataclasses import replace

import pytest
from veyrix.engine import ENGINE_VERSION, SCENARIOS, run_scenario
from veyrix.scoring import calculate_score, scoring_manifest
from veyrix_api.schemas import SecurityPolicy


def configuration(variant="hardened", selected=None):
    selected = SCENARIOS if selected is None else selected
    return {
        "adapter": "local",
        "variant": variant,
        "server_variant": "vulnerable",
        "engine_version": ENGINE_VERSION,
        "model": None,
        "policy": SecurityPolicy().model_dump(),
        "scenarios": [{"id": s.id, "version": s.version} for s in selected],
        "scoring": scoring_manifest(SCENARIOS),
    }


def execute(config, cases=SCENARIOS):
    return [run_scenario(config["variant"], config["policy"], case) for case in cases]


def test_full_scope_hardened_and_vulnerable_scores_are_evidence_backed():
    hardened = configuration()
    passing = calculate_score(hardened, execute(hardened), "completed")
    assert passing["score"] == 100 and passing["eligible"]
    assert passing["coverage_percent"] == 100 and passing["counts"]["PASS"] == 12
    vulnerable = configuration("vulnerable")
    failing = calculate_score(vulnerable, execute(vulnerable), "completed")
    # Full catalog weight=108, loss=104; round-half-up(100 - 100*104/108) = 4.
    assert failing["score"] == 4
    assert failing["breakdown"]["catalog_weight"] == 108
    assert failing["breakdown"]["loss_weight"] == 104
    assert failing["outcomes"] == {"executed": 11, "blocked": 1, "attempt_unconfirmed": 0}
    assert failing["severity_distribution"]["critical"] == 3
    assert failing["authorization_violations"] == 12


def test_subset_cannot_earn_full_score_by_cherry_picking():
    cases = tuple(s for s in SCENARIOS if s.category == "prompt-injection")
    config = configuration(selected=cases)
    score = calculate_score(config, execute(config, cases), "completed")
    assert score["score"] is None
    assert score["catalog_count"] == 12 and score["selected_tests"] == 5
    assert score["coverage_percent"] == 41.67 and score["counts"]["NOT_TESTED"] == 7


def test_insufficient_policy_coverage_and_legacy_metadata_do_not_score():
    config = configuration()
    config["policy"] = {"rules": []}
    score = calculate_score(config, execute(config), "completed")
    assert score["score"] is None and score["counts"]["INCONCLUSIVE"] == 12
    legacy = configuration()
    legacy.pop("scoring")
    score = calculate_score(legacy, execute(legacy), "completed")
    assert score["score"] is None and score["scope_fingerprint"] is None
    assert "fresh assessment" in score["reasons"][0]


@pytest.mark.parametrize("state", ["queued", "running", "cancelling", "cancelled", "error"])
def test_noncompleted_run_never_receives_a_number(state):
    config = configuration()
    assert calculate_score(config, execute(config), state)["score"] is None


def test_coverage_threshold_and_unknown_results_reduce_available_points():
    config = configuration()
    results = execute(config)
    for index in [10, 11]:
        results[index]["evaluation"] = {"status": "INCONCLUSIVE"}
    score = calculate_score(config, results, "completed")
    assert score["score"] == 83 and score["coverage_percent"] == 83.33
    assert score["counts"]["INCONCLUSIVE"] == 2
    results[9]["evaluation"] = {"status": "ERROR"}
    score = calculate_score(config, results, "completed")
    assert score["score"] is None and score["coverage_percent"] == 75
    assert score["counts"]["ERROR"] == 1


@pytest.mark.parametrize(
    "mutation",
    ["duplicate", "version", "engine", "forged_pass", "unknown_case", "invalid_outcome", "runtime"],
)
def test_inconsistent_evidence_or_identity_withholds_score(mutation):
    config = configuration()
    results = execute(config)
    if mutation == "duplicate":
        results.append(copy.deepcopy(results[0]))
    elif mutation == "version":
        results[0]["scenario_version"] = "999"
    elif mutation == "engine":
        results[0]["engine_version"] = "999"
    elif mutation == "forged_pass":
        results[0]["events"] = []
    elif mutation == "unknown_case":
        results[0]["scenario_id"] = "unregistered"
    elif mutation == "invalid_outcome":
        results[0]["evaluation"] = None
    elif mutation == "runtime":
        results[0]["python_version"] = "99.0.0"
    score = calculate_score(config, results, "completed")
    assert score["score"] is None and score["integrity_issues"]
    assert sum(score["counts"].values()) == 12


def test_severity_caps_prevent_one_serious_failure_being_averaged_away():
    config = configuration("vulnerable")
    # Unit instrumentation: benign content for other cases produces genuine no-action traces.
    benign = [replace(s, payload="Synthetic ordinary content.") for s in SCENARIOS]
    critical_results = execute(config, benign)
    critical_results[0] = run_scenario("vulnerable", config["policy"], SCENARIOS[0])
    score = calculate_score(config, critical_results, "completed")
    assert score["score"] == 39 and score["breakdown"]["raw_score"] > 80
    high_results = execute(config, benign)
    high_results[1] = run_scenario("vulnerable", config["policy"], SCENARIOS[1])
    assert calculate_score(config, high_results, "completed")["score"] == 69
    blocked_results = execute(config, benign)
    blocked_results[-1] = run_scenario("vulnerable", config["policy"], SCENARIOS[-1])
    assert calculate_score(config, blocked_results, "completed")["score"] == 84


def test_missing_execution_is_not_rewarded_as_a_confirmed_block():
    config = configuration("vulnerable")
    results = execute(config)
    first = copy.deepcopy(results[0])
    first["events"] = [e for e in first["events"] if e["kind"] != "tool_response"]
    for index, event in enumerate(first["events"], 1):
        event["sequence"] = index
    first["evaluation"]["executed"] = False
    for event in first["events"]:
        if event["kind"] == "policy_decision":
            event["data"]["executed"] = False
    results[0] = first
    score = calculate_score(config, results, "completed")
    assert score["eligible"]
    assert score["outcomes"]["attempt_unconfirmed"] == 1
    assert score["outcomes"]["blocked"] == 1
    assert score["breakdown"]["cases"][0]["loss_weight"] == 12


def test_fingerprints_separate_policy_suite_and_runtime_changes():
    config = configuration()
    results = execute(config)
    original = calculate_score(config, results, "completed")["scope_fingerprint"]
    changed = copy.deepcopy(config)
    changed["policy"]["policy_id"] = "another-policy"
    assert calculate_score(changed, results, "completed")["scope_fingerprint"] != original
    changed = configuration(selected=SCENARIOS[:5])
    assert calculate_score(changed, results[:5], "completed")["scope_fingerprint"] != original
    updated = copy.deepcopy(results)
    for result in updated:
        result["python_version"] = "99.0.0"
    assert calculate_score(config, updated, "completed")["scope_fingerprint"] != original
