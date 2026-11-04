import asyncio
import json

import pytest
from veyrix.adapters import SYNTHETIC_SECRET
from veyrix.engine import ENGINE_VERSION
from veyrix.engine.catalog import MCP_SCENARIOS
from veyrix.mcp_testing.adapter import run_mcp_scenario
from veyrix_api.schemas import SecurityPolicy
from veyrix_api.worker import execute_scenario


@pytest.mark.parametrize("scenario", MCP_SCENARIOS, ids=lambda s: s.id)
@pytest.mark.parametrize(
    "variant,server_variant,status,executed",
    [
        ("vulnerable", "vulnerable", "FAIL", True),
        ("hardened", "vulnerable", "PASS", False),
        ("vulnerable", "hardened", "FAIL", False),
    ],
)
def test_actual_stdio_mcp_boundaries(scenario, variant, server_variant, status, executed):
    result = asyncio.run(
        run_mcp_scenario(variant, SecurityPolicy().model_dump(), scenario, server_variant)
    )
    assert result["evaluation"]["status"] == status
    assert result["evaluation"]["executed"] is executed
    assert result["evaluation"]["attempted"] is (variant == "vulnerable")
    assert result["mcp_sdk_version"]
    discovery = next(e for e in result["events"] if e["kind"] == "mcp_discovery")
    assert discovery["data"]["protocol_version"]
    assert any(t["name"] == scenario.action for t in discovery["data"]["tools"])
    exposure = next(e for e in result["events"] if e["kind"] == "untrusted_content")
    assert exposure["data"]["text"] == scenario.payload
    assert SYNTHETIC_SECRET not in json.dumps(result)


def test_mcp_executes_inside_bounded_worker_child():
    result = execute_scenario(
        {
            "adapter": "mcp",
            "variant": "vulnerable",
            "server_variant": "hardened",
            "engine_version": ENGINE_VERSION,
            "policy": SecurityPolicy().model_dump(),
        },
        MCP_SCENARIOS[0].id,
    )
    assert result["adapter"] == "mcp"
    assert result["evaluation"]["attempted"] is True
    assert result["evaluation"]["executed"] is False
