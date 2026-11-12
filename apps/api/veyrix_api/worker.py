"""Durable test consumer. Start with python -m veyrix_api.worker."""

import json
import logging
import os
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from redis import RedisError
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session
from veyrix.engine import ENGINE_VERSION
from veyrix.llm.config import LLMRunConfig, load_llm_run_config

from veyrix_api.config import llm_execution_environ
from veyrix_api.db import engine
from veyrix_api.findings import persist_finding
from veyrix_api.jobs import WAKE_KEY, redis_client
from veyrix_api.models import TestRun
from veyrix_api.scoring import persist_score

logger = logging.getLogger(__name__)
LEASE_SECONDS = 60
SCENARIO_TIMEOUT = 15


def runner_env(adapter: str, llm_config: LLMRunConfig | None = None) -> dict[str, str]:
    """Minimal child environment. Database credentials are never copied in.

    The llm child receives only its endpoint settings. The API key is included only when
    one is configured, and only for that adapter.
    """
    env = {"PATH": os.defpath, "PYTHONUNBUFFERED": "1"}
    if adapter != "llm":
        return env
    if llm_config is None:
        llm_config = load_llm_run_config(llm_execution_environ())
    env.update(
        {
            "VEYRIX_LLM_TRANSPORT": llm_config.transport,
            "VEYRIX_LLM_MODEL": llm_config.model,
            "VEYRIX_LLM_BASE_URL": llm_config.base_url,
            "VEYRIX_LLM_TIMEOUT_SECONDS": str(llm_config.timeout_seconds),
            "VEYRIX_LLM_MAX_STEPS": str(llm_config.max_steps),
            "VEYRIX_LLM_SCENARIO_TIMEOUT_SECONDS": str(llm_config.scenario_timeout_seconds),
            "VEYRIX_LLM_DEADLINE_SECONDS": str(llm_config.deadline_seconds),
        }
    )
    if llm_config.transport == "scripted":
        env["VEYRIX_LLM_ALLOW_SCRIPTED"] = "1"
    if llm_config.api_key:
        env["VEYRIX_LLM_API_KEY"] = llm_config.api_key
    return env


def execute_scenario(configuration: dict, scenario_id: str) -> dict:
    adapter = configuration.get("adapter", "local")
    payload = {
        "variant": configuration["variant"],
        "policy": configuration["policy"],
        "scenario_id": scenario_id,
        "adapter": adapter,
        "server_variant": configuration.get("server_variant", "vulnerable"),
        "model": configuration.get("model"),
    }
    timeout = SCENARIO_TIMEOUT
    llm_config = None
    if adapter == "llm":
        llm_config = load_llm_run_config(llm_execution_environ())
        timeout = llm_config.scenario_timeout_seconds
    with subprocess.Popen(
        [sys.executable, "-m", "veyrix.runner"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
        env=runner_env(adapter, llm_config),
    ) as process:
        try:
            stdout, _ = process.communicate(json.dumps(payload), timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise
        if process.returncode:
            raise subprocess.CalledProcessError(process.returncode, "bundled-runner")
    if len(stdout) > 1024 * 1024:
        raise ValueError("Runner response exceeded size limit")
    return json.loads(stdout)


def recover_interrupted(db_engine: Engine) -> None:
    now = datetime.now(UTC)
    with Session(db_engine) as db:
        for run in db.scalars(
            select(TestRun)
            .where(TestRun.status.in_(["running", "cancelling"]), TestRun.lease_expires_at < now)
            .with_for_update(skip_locked=True)
        ):
            run.status = "cancelled" if run.status == "cancelling" else "error"
            run.error = "Worker lease expired; run was interrupted. Start a new run to retry."
            run.finished_at = now
            run.worker_token = None
            run.lease_expires_at = None
            persist_score(db, run)
        db.commit()


def claim_next(db_engine: Engine) -> tuple[str, str, dict] | None:
    with Session(db_engine) as db:
        run = db.scalar(
            select(TestRun)
            .where(TestRun.status == "queued")
            .order_by(TestRun.created_at)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if run is None:
            return None
        run.status = "running"
        run.started_at = datetime.now(UTC)
        run.lease_expires_at = run.started_at + timedelta(seconds=LEASE_SECONDS)
        run.worker_token = str(uuid4())
        db.commit()
        return run.id, run.worker_token, run.configuration


def update_owned(
    db_engine: Engine,
    run_id: str,
    token: str,
    result: dict | None = None,
    finish: bool = False,
    error: str | None = None,
) -> bool:
    with Session(db_engine) as db:
        run = db.scalar(select(TestRun).where(TestRun.id == run_id).with_for_update())
        if run is None or run.worker_token != token or run.status not in {"running", "cancelling"}:
            return False
        if result is not None:
            run.results = [*run.results, result]
            persist_finding(db, run, result)
        if run.status == "cancelling":
            run.status = "cancelled"
            finish = True
        elif error:
            run.status = "error"
            run.error = error
            finish = True
        elif finish:
            run.status = "completed"
        if finish:
            run.finished_at = datetime.now(UTC)
            run.worker_token = None
            run.lease_expires_at = None
            persist_score(db, run)
        else:
            run.lease_expires_at = datetime.now(UTC) + timedelta(seconds=LEASE_SECONDS)
        db.commit()
        return not finish


def process_one(db_engine: Engine = engine) -> bool:
    recover_interrupted(db_engine)
    claimed = claim_next(db_engine)
    if claimed is None:
        return False
    run_id, token, configuration = claimed
    logger.info("%s", json.dumps({"event": "run_started", "run_id": run_id}))
    try:
        if configuration["engine_version"] != ENGINE_VERSION:
            raise ValueError("Engine version differs from queued configuration")
        for scenario in configuration["scenarios"]:
            if not update_owned(db_engine, run_id, token):
                return True
            result = execute_scenario(configuration, scenario["id"])
            if (
                result["scenario_version"] != scenario["version"]
                or result["scenario_id"] != scenario["id"]
                or result["engine_version"] != configuration["engine_version"]
            ):
                raise ValueError("Runner identity differs from queued configuration")
            if not update_owned(db_engine, run_id, token, result=result):
                return True
        update_owned(db_engine, run_id, token, finish=True)
    except subprocess.TimeoutExpired:
        update_owned(db_engine, run_id, token, error="Scenario exceeded the execution timeout.")
    except Exception as exc:  # noqa: BLE001 - supervisor records failure without exposing secrets
        # Do not put subprocess stderr, configuration, or secrets into run errors/logs.
        logger.error(
            "%s",
            json.dumps({"event": "run_error", "run_id": run_id, "error_type": type(exc).__name__}),
        )
        update_owned(
            db_engine,
            run_id,
            token,
            error="Execution failed. Check worker compatibility and start a new run.",
        )
    return True


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    stopping = False

    def stop(*_: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopping:
        try:
            if process_one():
                continue
            try:
                with redis_client() as client:
                    client.blpop(WAKE_KEY, timeout=1)
            except RedisError:
                time.sleep(1)
        except Exception as exc:  # noqa: BLE001 - supervisor records failure without exposing secrets
            logger.error(
                "%s", json.dumps({"event": "worker_error", "error_type": type(exc).__name__})
            )
            time.sleep(1)


if __name__ == "__main__":
    main()
