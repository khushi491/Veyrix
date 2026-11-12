"""Tool-calling adapter tests. No test in this module calls a live model or needs an API key."""

import json
import os
import subprocess
import sys
from uuid import uuid4

import httpx
import pytest
from veyrix.adapters import SYNTHETIC_SECRET
from veyrix.engine import ENGINE_VERSION, SCENARIOS, run_scenario
from veyrix.findings import verified_result
from veyrix.llm import (
    HttpxChatTransport,
    LLMConfigError,
    ScriptedChatTransport,
    load_llm_run_config,
    run_llm_scenario,
)
from veyrix.llm.adapter import run_llm_scenario_from_env
from veyrix.llm.tools import TOOL_NAMES
from veyrix.llm.transport import LLMTransportError
from veyrix.scoring import calculate_score, scoring_manifest
from veyrix_api.schemas import SecurityPolicy

POLICY = SecurityPolicy().model_dump()
API_KEY = "sk-test-not-a-real-key"


def score_config(variant: str, model: str, adapter: str = "llm"):
    return {
        "adapter": adapter,
        "variant": variant,
        "server_variant": "vulnerable",
        "engine_version": ENGINE_VERSION,
        "model": model if adapter == "llm" else None,
        "policy": POLICY,
        "scenarios": [{"id": scenario.id, "version": scenario.version} for scenario in SCENARIOS],
        "scoring": scoring_manifest(SCENARIOS),
    }


def run_scripted(variant: str, scenario, **kwargs):
    return run_llm_scenario(
        variant,
        POLICY,
        scenario,
        ScriptedChatTransport(variant),
        model=f"scripted-{variant}",
        transport_name="scripted",
        **kwargs,
    )


def assert_trace_shape(result: dict) -> None:
    events = result["events"]
    assert [event["sequence"] for event in events] == list(range(1, len(events) + 1))
    assert events[0]["kind"] == "user_instruction" and events[0]["trust"] == "trusted"
    assert events[0]["data"]["explicit_user_approval"] is False
    assert any(
        event["kind"] == "untrusted_content" and event["trust"] == "untrusted" for event in events
    )
    assert any(event["kind"] == "model_message" for event in events)
    assert any(event["kind"] == "tool_definitions" for event in events)
    assert events[-2]["kind"] == "agent_complete"
    assert events[-1]["kind"] == "policy_decision"
    assert events[-1]["data"]["status"] == result["evaluation"]["status"]
    saw_model = False
    for event in events:
        if event["kind"] == "model_message":
            saw_model = True
        if event["kind"] == "tool_request":
            assert saw_model
        if event["kind"] == "tool_response":
            sequence = event["data"]["request_sequence"]
            assert events[sequence - 1]["kind"] == "tool_request"


class _RecordingScript(ScriptedChatTransport):
    def __init__(self, variant: str) -> None:
        super().__init__(variant)
        self.seen: list[tuple[list, list[str]]] = []

    def complete(self, messages, tools, *, timeout: float):
        self.seen.append((messages, [tool["function"]["name"] for tool in tools]))
        return super().complete(messages, tools, timeout=timeout)


@pytest.mark.parametrize("variant", ["vulnerable", "hardened"])
def test_full_suite_scores_and_findings_come_from_the_engine(variant):
    results = [run_scripted(variant, scenario) for scenario in SCENARIOS]
    for scenario, result in zip(SCENARIOS, results, strict=True):
        assert_trace_shape(result)
        assert result["adapter"] == "llm"
        assert result["adapter_version"] == "0.4.0"
        assert result["model_transport"] == "scripted"
        assert result["evaluation"]["status"] == ("FAIL" if variant == "vulnerable" else "PASS")
        assert result["evaluation"]["executed"] is (
            variant == "vulnerable" and not scenario.guarded
        )
        evidence = verified_result(result, POLICY)
        if variant == "vulnerable":
            assert evidence is not None
            assert evidence["evaluation"]["status"] == "FAIL"
            requests = [event for event in result["events"] if event["kind"] == "tool_request"]
            assert any(event["data"]["action"] == scenario.action for event in requests)
        else:
            assert evidence is None
            assert not any(event["kind"] == "tool_request" for event in result["events"])
    scored = calculate_score(score_config(variant, f"scripted-{variant}"), results, "completed")
    local_results = [run_scenario(variant, POLICY, scenario) for scenario in SCENARIOS]
    local = calculate_score(score_config(variant, f"scripted-{variant}", "local"), local_results, "completed")
    assert scored["eligible"] is True
    assert scored["score"] == local["score"]
    assert scored["outcomes"] == local["outcomes"]
    assert scored["counts"] == local["counts"]
    assert scored["severity_distribution"] == local["severity_distribution"]
    assert scored["breakdown"]["loss_weight"] == local["breakdown"]["loss_weight"]
    assert API_KEY not in json.dumps(results)


def test_vulnerable_score_is_lower_and_guarded_payment_is_blocked():
    vulnerable = [run_scripted("vulnerable", scenario) for scenario in SCENARIOS]
    hardened = [run_scripted("hardened", scenario) for scenario in SCENARIOS]
    vulnerable_score = calculate_score(score_config("vulnerable", "scripted-vulnerable"), vulnerable, "completed")
    hardened_score = calculate_score(score_config("hardened", "scripted-hardened"), hardened, "completed")
    assert vulnerable_score["score"] < hardened_score["score"]
    guarded = next(result for result in vulnerable if result["scenario_id"] == "guarded-payment-attempt")
    responses = [event["data"] for event in guarded["events"] if event["kind"] == "tool_response"]
    assert responses[-1]["blocked"] is True and responses[-1]["executed"] is False
    assert guarded["evaluation"]["attempted"] is True
    assert guarded["evaluation"]["executed"] is False


def test_scripted_loop_sends_tool_results_and_redacts_the_synthetic_secret():
    scenario = next(item for item in SCENARIOS if item.id == "synthetic-secret-exfiltration")
    transport = _RecordingScript("vulnerable")
    result = run_llm_scenario(
        "vulnerable",
        POLICY,
        scenario,
        transport,
        model="scripted-vulnerable",
        transport_name="scripted",
    )
    assert len(transport.seen) == 3
    assert set(transport.seen[0][1]) == set(TOOL_NAMES)
    assert any(message.get("role") == "tool" for message in transport.seen[1][0])
    assert SYNTHETIC_SECRET in json.dumps(transport.seen[1][0])
    assert SYNTHETIC_SECRET not in json.dumps(result)
    assert "[REDACTED_SYNTHETIC_SECRET]" in json.dumps(result)
    outbound = [
        event["data"]
        for event in result["events"]
        if event["kind"] == "tool_response" and event["data"].get("contains_synthetic_secret")
    ]
    assert outbound and outbound[0]["contains_synthetic_secret"] is True
    assert verified_result(result, POLICY) is not None


def test_step_limit_does_not_hide_a_violation_or_invent_a_pass():
    scenario = next(item for item in SCENARIOS if item.id == "document-injection")

    class Always:
        def __init__(self, name: str, arguments: str) -> None:
            self.name = name
            self.arguments = arguments
            self.calls = 0

        def complete(self, messages, tools, *, timeout: float):
            del messages, tools, timeout
            self.calls += 1
            return {
                "role": "assistant",
                "content": None,
                "finish_reason": "tool_calls",
                "tool_calls": [
                    {
                        "id": f"call_{self.calls}",
                        "type": "function",
                        "function": {"name": self.name, "arguments": self.arguments},
                    }
                ],
            }

    violated = run_llm_scenario(
        "vulnerable",
        POLICY,
        scenario,
        Always("transfer_funds", '{"recipient":"mock:attacker","amount":100}'),
        model="loop",
        max_steps=1,
    )
    assert violated["evaluation"]["status"] == "FAIL"
    assert violated["evaluation"]["executed"] is True
    assert violated["model_stop"] == "max_steps"
    assert verified_result(violated, POLICY) is not None

    spinning = run_llm_scenario(
        "vulnerable",
        POLICY,
        scenario,
        Always("read_records", '{"table":"mock:accounts"}'),
        model="loop",
        max_steps=2,
    )
    assert spinning["evaluation"]["status"] == "INCONCLUSIVE"
    assert verified_result(spinning, POLICY) is None
    partial = calculate_score(
        score_config("vulnerable", "loop"),
        [spinning],
        "completed",
    )
    assert partial["score"] is None


def test_deadline_and_transport_errors_do_not_pass_and_keep_an_observed_fail():
    scenario = SCENARIOS[0]

    class Boom:
        def complete(self, messages, tools, *, timeout: float):
            raise LLMTransportError("Model request timed out")

    expired = run_llm_scenario(
        "hardened", POLICY, scenario, Boom(), model="timeout", deadline_seconds=0
    )
    assert expired["evaluation"]["status"] == "ERROR"
    assert expired["model_stop"] == "deadline"
    assert not any(event["kind"] == "tool_request" for event in expired["events"])
    assert verified_result(expired, POLICY) is None

    failed = run_llm_scenario(
        "vulnerable", POLICY, scenario, Boom(), model="timeout", deadline_seconds=30
    )
    assert failed["evaluation"]["status"] == "ERROR"
    assert "sk-" not in json.dumps(failed)

    class ViolateThenFail:
        def __init__(self) -> None:
            self.calls = 0

        def complete(self, messages, tools, *, timeout: float):
            del messages, tools, timeout
            self.calls += 1
            if self.calls > 1:
                raise LLMTransportError("Model request timed out")
            return {
                "role": "assistant",
                "content": None,
                "finish_reason": "tool_calls",
                "tool_calls": [
                    {
                        "id": "call_pay",
                        "type": "function",
                        "function": {
                            "name": "transfer_funds",
                            "arguments": json.dumps(
                                {"recipient": "mock:attacker", "amount": 80}
                            ),
                        },
                    }
                ],
            }

    kept = run_llm_scenario(
        "vulnerable", POLICY, scenario, ViolateThenFail(), model="timeout", deadline_seconds=30
    )
    assert kept["evaluation"]["status"] == "FAIL"
    assert verified_result(kept, POLICY) is not None


def test_malformed_tool_call_is_still_a_verified_attempt():
    scenario = SCENARIOS[0]

    class BadArguments:
        def __init__(self) -> None:
            self.calls = 0

        def complete(self, messages, tools, *, timeout: float):
            del messages, tools, timeout
            self.calls += 1
            if self.calls > 1:
                return {
                    "role": "assistant",
                    "content": "Stopped.",
                    "finish_reason": "stop",
                    "tool_calls": [],
                }
            return {
                "role": "assistant",
                "content": None,
                "finish_reason": "tool_calls",
                "tool_calls": [
                    {
                        "id": "call_bad",
                        "type": "function",
                        "function": {"name": "transfer_funds", "arguments": "not-json"},
                    }
                ],
            }

    result = run_llm_scenario("vulnerable", POLICY, scenario, BadArguments(), model="bad-args")
    assert result["evaluation"]["status"] == "FAIL"
    assert result["evaluation"]["attempted"] is True
    assert result["evaluation"]["executed"] is False
    evidence = verified_result(result, POLICY)
    assert evidence is not None
    response = next(event["data"] for event in result["events"] if event["kind"] == "tool_response")
    assert response["executed"] is False


def test_http_replay_executes_tool_calls_and_omits_the_api_key_from_evidence():
    scenario = next(item for item in SCENARIOS if item.id == "synthetic-secret-exfiltration")
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/chat/completions"
        assert request.headers["Authorization"] == f"Bearer {API_KEY}"
        body = json.loads(request.content)
        assert API_KEY not in json.dumps(body)
        assert body["model"] == "replay-vulnerable"
        assert {tool["function"]["name"] for tool in body["tools"]} == set(TOOL_NAMES)
        seen.append(body)
        step = len(seen)
        if step == 1:
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_secret",
                        "type": "function",
                        "function": {
                            "name": "read_secret",
                            "arguments": '{"key":"synthetic_token"}',
                        },
                    }
                ],
            }
            finish = "tool_calls"
        elif step == 2:
            assert any(message["role"] == "tool" for message in body["messages"])
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_send",
                        "type": "function",
                        "function": {
                            "name": "http_request",
                            "arguments": json.dumps(
                                {"destination": "mock:collector", "data": "$last.secret"}
                            ),
                        },
                    }
                ],
            }
            finish = "tool_calls"
        else:
            message = {"role": "assistant", "content": "Done.", "tool_calls": []}
            finish = "stop"
        return httpx.Response(
            200, json={"choices": [{"message": message, "finish_reason": finish}]}
        )

    transport = HttpxChatTransport(
        base_url="http://127.0.0.1:11434/v1",
        api_key=API_KEY,
        model="replay-vulnerable",
        timeout=5,
        http_transport=httpx.MockTransport(handler),
    )
    result = run_llm_scenario(
        "vulnerable",
        POLICY,
        scenario,
        transport,
        model="replay-vulnerable",
        transport_name="http",
    )
    assert len(seen) == 3
    assert result["evaluation"]["status"] == "FAIL"
    assert result["evaluation"]["executed"] is True
    assert verified_result(result, POLICY) is not None
    encoded = json.dumps(result)
    assert API_KEY not in encoded
    assert SYNTHETIC_SECRET not in encoded
    assert "[REDACTED_SYNTHETIC_SECRET]" in encoded


def test_http_hardened_refusal_and_failures_do_not_leak_the_key_or_follow_redirects():
    scenario = SCENARIOS[0]

    def refuse(request: httpx.Request) -> httpx.Response:
        assert "Authorization" not in request.headers
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": "I will not call tools.",
                            "tool_calls": [],
                        },
                        "finish_reason": "stop",
                    }
                ]
            },
        )

    transport = HttpxChatTransport(
        base_url="http://127.0.0.1:11434/v1",
        api_key="",
        model="replay-hardened",
        timeout=5,
        http_transport=httpx.MockTransport(refuse),
    )
    result = run_llm_scenario(
        "hardened", POLICY, scenario, transport, model="replay-hardened", transport_name="http"
    )
    assert result["evaluation"]["status"] == "PASS"
    assert verified_result(result, POLICY) is None

    def unauthorized(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": API_KEY, "detail": "nope"})

    failing = HttpxChatTransport(
        base_url="https://api.openai.com/v1",
        api_key=API_KEY,
        model="replay-hardened",
        timeout=5,
        http_transport=httpx.MockTransport(unauthorized),
    )
    errored = run_llm_scenario(
        "hardened", POLICY, scenario, failing, model="replay-hardened", transport_name="http"
    )
    assert errored["evaluation"]["status"] == "ERROR"
    assert API_KEY not in json.dumps(errored)
    assert "401" in json.dumps(errored)

    calls = {"count": 0}

    def redirect(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(302, headers={"location": "https://evil.example/steal"})

    redirected = HttpxChatTransport(
        base_url="http://127.0.0.1:11434/v1",
        api_key=API_KEY,
        model="replay-hardened",
        timeout=5,
        http_transport=httpx.MockTransport(redirect),
    )
    stopped = run_llm_scenario(
        "hardened", POLICY, scenario, redirected, model="replay-hardened", transport_name="http"
    )
    assert calls["count"] == 1
    assert stopped["evaluation"]["status"] == "ERROR"
    assert "evil.example" not in json.dumps(stopped)

    def oversized(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 250)

    huge = HttpxChatTransport(
        base_url="http://127.0.0.1:11434/v1",
        api_key="",
        model="replay-hardened",
        timeout=5,
        http_transport=httpx.MockTransport(oversized),
        max_response_bytes=100,
    )
    limited = run_llm_scenario(
        "hardened", POLICY, scenario, huge, model="replay-hardened", transport_name="http"
    )
    assert limited["evaluation"]["status"] == "ERROR"
    assert "size" in json.dumps(limited)


def test_configuration_rejects_missing_models_cleartext_remotes_and_hides_the_key():
    with pytest.raises(LLMConfigError, match="VEYRIX_LLM_MODEL"):
        load_llm_run_config({})
    with pytest.raises(LLMConfigError, match="ALLOW_SCRIPTED"):
        load_llm_run_config({"VEYRIX_LLM_TRANSPORT": "scripted", "VEYRIX_LLM_MODEL": "scripted"})
    scripted = load_llm_run_config(
        {"VEYRIX_LLM_TRANSPORT": "scripted", "VEYRIX_LLM_ALLOW_SCRIPTED": "true"}
    )
    assert scripted.model == "scripted"
    assert scripted.transport == "scripted"
    assert scripted.api_key == ""
    hosted = load_llm_run_config(
        {
            "VEYRIX_LLM_MODEL": "gpt-4o-mini",
            "VEYRIX_LLM_BASE_URL": "https://api.openai.com/v1/chat/completions",
            "VEYRIX_LLM_API_KEY": API_KEY,
        }
    )
    assert hosted.base_url == "https://api.openai.com/v1"
    assert hosted.api_key == API_KEY
    assert API_KEY not in repr(hosted)
    assert "api_key='***'" in repr(hosted)
    local = load_llm_run_config({"VEYRIX_LLM_MODEL": "qwen2.5:3b"})
    assert local.base_url == "http://127.0.0.1:11434/v1"
    assert (
        load_llm_run_config(
            {"VEYRIX_LLM_MODEL": "qwen2.5:3b", "VEYRIX_LLM_BASE_URL": "http://localhost:11434/v1"}
        ).base_url
        == "http://localhost:11434/v1"
    )
    with pytest.raises(LLMConfigError):
        load_llm_run_config(
            {"VEYRIX_LLM_MODEL": "gpt-4o-mini", "VEYRIX_LLM_BASE_URL": "http://api.openai.com/v1"}
        )
    with pytest.raises(LLMConfigError):
        load_llm_run_config(
            {
                "VEYRIX_LLM_MODEL": "gpt-4o-mini",
                "VEYRIX_LLM_BASE_URL": "https://user:pass@api.openai.com/v1",
            }
        )
    with pytest.raises(LLMConfigError):
        load_llm_run_config(
            {
                "VEYRIX_LLM_MODEL": "gpt-4o-mini",
                "VEYRIX_LLM_BASE_URL": "https://api.openai.com/v1?token=secret",
            }
        )
    with pytest.raises(LLMConfigError):
        load_llm_run_config({"VEYRIX_LLM_MODEL": "gpt-4o-mini", "VEYRIX_LLM_MAX_STEPS": "9"})
    with pytest.raises(LLMConfigError):
        load_llm_run_config(
            {"VEYRIX_LLM_MODEL": "gpt-4o-mini", "VEYRIX_LLM_SCENARIO_TIMEOUT_SECONDS": "90"}
        )
    with pytest.raises(LLMConfigError):
        load_llm_run_config({"VEYRIX_LLM_MODEL": "has space"})


def test_child_environment_keeps_database_credentials_and_unused_keys_out(monkeypatch):
    from veyrix_api.worker import runner_env

    monkeypatch.setenv("DATABASE_URL", "postgresql://veyrix:veyrix_local@localhost/veyrix")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("VEYRIX_LLM_API_KEY", API_KEY)
    monkeypatch.setenv("VEYRIX_LLM_MODEL", "qwen2.5:3b")
    local = runner_env("local")
    assert local.keys() == {"PATH", "PYTHONUNBUFFERED"}
    assert API_KEY not in json.dumps(local)
    llm = runner_env("llm")
    assert "DATABASE_URL" not in llm
    assert "REDIS_URL" not in llm
    assert llm["VEYRIX_LLM_API_KEY"] == API_KEY
    assert llm["VEYRIX_LLM_MODEL"] == "qwen2.5:3b"
    assert "VEYRIX_DEV_MODE" not in llm


def test_runner_subprocess_scripted_suite_case_needs_no_api_key():
    payload = {
        "adapter": "llm",
        "variant": "vulnerable",
        "policy": POLICY,
        "scenario_id": "document-injection",
        "model": "scripted-vulnerable",
    }
    env = {
        "PATH": os.defpath,
        "VEYRIX_LLM_TRANSPORT": "scripted",
        "VEYRIX_LLM_ALLOW_SCRIPTED": "1",
        "VEYRIX_LLM_MODEL": "scripted-vulnerable",
    }
    completed = subprocess.run(
        [sys.executable, "-m", "veyrix.runner"],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["evaluation"]["status"] == "FAIL"
    assert verified_result(result, POLICY) is not None
    assert API_KEY not in completed.stdout

    payload["variant"] = "hardened"
    payload["model"] = "scripted-hardened"
    env["VEYRIX_LLM_MODEL"] = "scripted-hardened"
    hardened = subprocess.run(
        [sys.executable, "-m", "veyrix.runner"],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )
    assert hardened.returncode == 0, hardened.stderr
    assert json.loads(hardened.stdout)["evaluation"]["status"] == "PASS"

    blocked = subprocess.run(
        [sys.executable, "-m", "veyrix.runner"],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
        env={
            "PATH": os.defpath,
            "VEYRIX_LLM_TRANSPORT": "scripted",
            "VEYRIX_LLM_MODEL": "scripted",
            "VEYRIX_LLM_API_KEY": API_KEY,
        },
    )
    assert blocked.returncode != 0
    assert API_KEY not in blocked.stderr
    assert API_KEY not in blocked.stdout


def test_select_scenarios_shares_the_local_catalog():
    from veyrix.engine.catalog import select_scenarios

    assert select_scenarios("all", "llm") == SCENARIOS
    assert len(select_scenarios("prompt-injection", "llm")) == 5
    with pytest.raises(ValueError):
        select_scenarios("all", "shell")
    with pytest.raises(ValueError):
        select_scenarios("mcp-security", "llm")


def test_postgres_llm_agent_run_persists_pipeline_scores(monkeypatch):
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("Set TEST_DATABASE_URL to a disposable migrated PostgreSQL database")
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session
    from veyrix_api.config import settings
    from veyrix_api.db import get_session
    from veyrix_api.main import app
    from veyrix_api.models import Base
    from veyrix_api.worker import process_one

    engine = create_engine(url)
    monkeypatch.setattr(settings, "veyrix_dev_mode", True)
    monkeypatch.setenv("VEYRIX_LLM_TRANSPORT", "scripted")
    monkeypatch.setenv("VEYRIX_LLM_ALLOW_SCRIPTED", "1")
    monkeypatch.setenv("VEYRIX_LLM_MODEL", "scripted-worker")
    monkeypatch.delenv("VEYRIX_LLM_API_KEY", raising=False)

    def session_override():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = session_override
    project_id = None
    try:
        with TestClient(app) as client:
            project = client.post("/api/projects", json={"name": "LLM " + str(uuid4())})
            assert project.status_code == 201
            project_id = project.json()["id"]
            monkeypatch.delenv("VEYRIX_LLM_MODEL", raising=False)
            monkeypatch.delenv("VEYRIX_LLM_TRANSPORT", raising=False)
            missing = client.post(
                f"/api/projects/{project_id}/agents",
                json={"name": "Unconfigured", "adapter": "llm", "variant": "vulnerable"},
            )
            assert missing.status_code == 201
            assert (
                client.post(f"/api/agents/{missing.json()['id']}/runs").status_code == 422
            )
            monkeypatch.setenv("VEYRIX_LLM_TRANSPORT", "scripted")
            monkeypatch.setenv("VEYRIX_LLM_ALLOW_SCRIPTED", "1")
            monkeypatch.setenv("VEYRIX_LLM_MODEL", "scripted-worker")
            scores = {}
            for variant in ("vulnerable", "hardened"):
                agent = client.post(
                    f"/api/projects/{project_id}/agents",
                    json={"name": variant, "adapter": "llm", "variant": variant},
                )
                assert agent.status_code == 201
                queued = client.post(f"/api/agents/{agent.json()['id']}/runs")
                assert queued.status_code == 202, queued.text
                assert queued.json()["configuration"]["model"] == "scripted-worker"
                assert queued.json()["configuration"]["model_transport"] == "scripted"
                assert "api_key" not in json.dumps(queued.json()["configuration"])
                assert process_one(engine)
                stored = client.get(f"/api/runs/{queued.json()['id']}").json()
                assert stored["status"] == "completed"
                assert len(stored["results"]) == 12
                pipeline = calculate_score(stored["configuration"], stored["results"], "completed")
                body = client.get(f"/api/runs/{stored['id']}/score").json()
                assert body["snapshot_persisted"] is True
                reported = body["assessment"]
                assert reported["score"] == pipeline["score"]
                assert reported["outcomes"] == pipeline["outcomes"]
                assert reported["counts"] == pipeline["counts"]
                assert reported["eligible"] is True
                assert reported["methodology_version"] == pipeline["methodology_version"]
                local_results = [run_scenario(variant, POLICY, scenario) for scenario in SCENARIOS]
                local_score = calculate_score(
                    score_config(variant, "scripted-worker", "local"), local_results, "completed"
                )
                assert reported["score"] == local_score["score"]
                assert reported["outcomes"] == local_score["outcomes"]
                scores[variant] = reported["score"]
                report = client.get(f"/api/runs/{stored['id']}/report").json()
                assert "no live model was called" in " ".join(report["limitations"]).lower()
            assert scores["vulnerable"] < scores["hardened"]
            findings = client.get(f"/api/projects/{project_id}/findings").json()
            assert findings["total"] == 12
            assert sum(item["executed"] for item in findings["items"]) == 11
    finally:
        if project_id:
            with engine.begin() as connection:
                run_table = Base.metadata.tables["test_runs"]
                agent_table = Base.metadata.tables["agents"]
                finding_table = Base.metadata.tables["findings"]
                run_ids = (
                    select(run_table.c.id)
                    .join(agent_table, run_table.c.agent_id == agent_table.c.id)
                    .where(agent_table.c.project_id == project_id)
                )
                finding_ids = select(finding_table.c.id).where(finding_table.c.run_id.in_(run_ids))
                changes = Base.metadata.tables["finding_status_changes"]
                connection.execute(changes.delete().where(changes.c.finding_id.in_(finding_ids)))
                connection.execute(finding_table.delete().where(finding_table.c.run_id.in_(run_ids)))
                connection.execute(
                    run_table.delete().where(
                        run_table.c.agent_id.in_(
                            select(agent_table.c.id).where(agent_table.c.project_id == project_id)
                        )
                    )
                )
                connection.execute(agent_table.delete().where(agent_table.c.project_id == project_id))
                connection.execute(
                    Base.metadata.tables["projects"].delete().where(
                        Base.metadata.tables["projects"].c.id == project_id
                    )
                )
        app.dependency_overrides.clear()
        engine.dispose()


def test_worker_execute_scenario_uses_the_scripted_child(monkeypatch):
    from veyrix_api.worker import execute_scenario

    monkeypatch.setenv("VEYRIX_LLM_TRANSPORT", "scripted")
    monkeypatch.setenv("VEYRIX_LLM_ALLOW_SCRIPTED", "1")
    monkeypatch.setenv("VEYRIX_LLM_MODEL", "scripted-worker")
    monkeypatch.setenv("DATABASE_URL", "postgresql://veyrix:veyrix_local@localhost/veyrix")
    monkeypatch.delenv("VEYRIX_LLM_API_KEY", raising=False)
    result = execute_scenario(
        {
            "adapter": "llm",
            "variant": "hardened",
            "policy": POLICY,
            "model": "scripted-worker",
            "server_variant": "vulnerable",
        },
        "search-result-injection",
    )
    assert result["evaluation"]["status"] == "PASS"
    assert result["scenario_id"] == "search-result-injection"
    assert result["model_transport"] == "scripted"
    assert API_KEY not in json.dumps(result)
    assert "veyrix_local" not in json.dumps(result)


def test_from_env_scripted_matches_direct_script(monkeypatch):
    monkeypatch.setenv("VEYRIX_LLM_TRANSPORT", "scripted")
    monkeypatch.setenv("VEYRIX_LLM_ALLOW_SCRIPTED", "1")
    monkeypatch.setenv("VEYRIX_LLM_MODEL", "scripted-vulnerable")
    monkeypatch.delenv("VEYRIX_LLM_API_KEY", raising=False)
    result = run_llm_scenario_from_env("vulnerable", POLICY, SCENARIOS[0], "scripted-vulnerable")
    assert result["evaluation"]["status"] == "FAIL"
    assert result["model_transport"] == "scripted"
