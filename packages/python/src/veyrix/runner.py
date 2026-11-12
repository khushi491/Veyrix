"""Bounded subprocess entry point. Only bundled scenarios may be executed."""

import asyncio
import json
import sys

from veyrix.engine import SCENARIOS, run_scenario


def main() -> None:
    # Limits are applied inside the child, never via preexec_fn in a threaded worker.
    import resource

    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if sys.platform == "linux":
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    payload = json.loads(sys.stdin.read(128 * 1024))
    adapter = payload.get("adapter", "local")
    if adapter == "mcp":
        from veyrix.engine.catalog import MCP_SCENARIOS
        from veyrix.mcp_testing.adapter import run_mcp_scenario

        scenario = next(s for s in MCP_SCENARIOS if s.id == payload["scenario_id"])
        result = asyncio.run(
            run_mcp_scenario(
                payload["variant"],
                payload["policy"],
                scenario,
                payload.get("server_variant", "vulnerable"),
            )
        )
    elif adapter == "llm":
        from veyrix.llm.adapter import run_llm_scenario_from_env

        scenario = next(s for s in SCENARIOS if s.id == payload["scenario_id"])
        # Model name may be snapshotted on the run. The API key stays in the environment.
        result = run_llm_scenario_from_env(
            payload["variant"], payload["policy"], scenario, payload.get("model")
        )
    else:
        scenario = next(s for s in SCENARIOS if s.id == payload["scenario_id"])
        result = run_scenario(payload["variant"], payload["policy"], scenario)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
