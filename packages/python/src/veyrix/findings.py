"""Verify finding evidence without trusting a result's declared FAIL status alone."""

from dataclasses import asdict

from veyrix.engine import Evaluation, Event, evaluate, redact


def observed_evaluation(result: dict, policy: dict) -> Evaluation | None:
    claimed = result.get("evaluation", {})
    if not isinstance(claimed, dict) or claimed.get("status") not in {"PASS", "FAIL"}:
        return None
    claimed_sequences = claimed.get("evidence_sequences", [])
    if not isinstance(claimed_sequences, list) or not all(
        type(s) is int for s in claimed_sequences
    ):
        return None
    raw_events = result.get("events", [])
    if not isinstance(raw_events, list) or not all(
        isinstance(e, dict)
        and isinstance(e.get("data"), dict)
        and type(e.get("sequence")) is int
        and isinstance(e.get("kind"), str)
        for e in raw_events
    ):
        return None
    if not raw_events or [e.get("sequence") for e in raw_events] != list(
        range(1, len(raw_events) + 1)
    ):
        return None
    if not any(
        e.get("kind") == "untrusted_content" and e.get("trust") == "untrusted" for e in raw_events
    ):
        return None
    if not any(
        e.get("kind") == "user_instruction" and e.get("trust") == "trusted" for e in raw_events
    ):
        return None
    for event in raw_events:
        if event.get("trust") not in {"trusted", "untrusted", "system"}:
            return None
        if event.get("kind") == "tool_response":
            sequence = event.get("data", {}).get("request_sequence")
            if not isinstance(sequence, int) or not 1 <= sequence < event["sequence"]:
                return None
            if raw_events[sequence - 1].get("kind") != "tool_request":
                return None
    events = [Event(e["sequence"], e["kind"], e["trust"], e["data"]) for e in raw_events]
    observed = evaluate(events, policy)
    if observed.status != claimed["status"]:
        return None
    if observed.status == "FAIL" and not observed.evidence_sequences:
        return None
    if (
        set(claimed_sequences) != set(observed.evidence_sequences)
        or claimed.get("attempted") is not observed.attempted
        or claimed.get("executed") is not observed.executed
    ):
        return None
    decisions = [e["data"] for e in raw_events if e["kind"] == "policy_decision"]
    if decisions:
        decision = decisions[-1]
        sequences = decision.get("evidence_sequences")
        if (
            not isinstance(sequences, list)
            or not all(type(s) is int for s in sequences)
            or set(sequences) != set(observed.evidence_sequences)
            or decision.get("status") != observed.status
            or decision.get("attempted") is not observed.attempted
            or decision.get("executed") is not observed.executed
        ):
            return None
    return observed


def verified_result(result: dict, policy: dict) -> dict | None:
    observed = observed_evaluation(result, policy)
    if observed is None or observed.status != "FAIL":
        return None
    if result.get("severity") not in {"critical", "high", "medium", "low", "info"}:
        return None
    if not all(
        result.get(key)
        for key in ("scenario_id", "scenario_version", "engine_version", "title", "category")
    ):
        return None
    evidence = redact(result)
    evidence["evaluation"] = asdict(observed)
    evidence["actual_behavior"] = observed.reason
    return evidence
