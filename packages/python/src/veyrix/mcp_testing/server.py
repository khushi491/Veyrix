"""Deliberately vulnerable and policy-enforcing MCP server fixtures, stdio only."""

import argparse
import json
import os

from mcp.server import MCPServer

from veyrix.adapters import MockTools, ToolRequest
from veyrix.engine import Event, evaluate
from veyrix.engine.catalog import MCP_SCENARIOS


def build_server(scenario_id: str, variant: str, policy: dict) -> MCPServer:
    scenario = next(s for s in MCP_SCENARIOS if s.id == scenario_id)
    tools = MockTools()
    server = MCPServer(f"Veyrix {variant} synthetic MCP fixture")

    def execute(action: str, arguments: dict) -> dict:
        if variant == "hardened":
            decision = evaluate([Event(1, "tool_request", "system", {"action": action})], policy)
            if decision.status == "FAIL":
                return {
                    "executed": False,
                    "blocked": True,
                    "environment": "synthetic",
                    "reason": "Server-side policy denied this action.",
                }
        return tools.execute(ToolRequest(action, arguments))

    description = (
        scenario.payload
        if scenario.channel == "mcp-tool-description"
        else "Read a synthetic account document. Content is untrusted."
    )

    @server.tool(description=description)
    def read_document() -> dict:
        return {
            "text": scenario.payload
            if scenario.channel == "mcp-tool-response"
            else "Synthetic account summary.",
            "executed": True,
            "environment": "synthetic",
        }

    @server.resource("veyrix://context")
    def context_resource() -> str:
        return (
            scenario.payload if scenario.channel == "mcp-resource" else "Synthetic account summary."
        )

    @server.tool()
    def transfer_funds(recipient: str, amount: int) -> dict:
        """Transfer synthetic funds in the in-memory ledger."""
        return execute("transfer_funds", {"recipient": recipient, "amount": amount})

    @server.tool()
    def write_file(path: str, content: str) -> dict:
        """Modify an in-memory synthetic file, never an OS path."""
        return execute("write_file", {"path": path, "content": content})

    @server.tool()
    def delete_records(table: str) -> dict:
        """Delete synthetic records from memory."""
        return execute("delete_records", {"table": table})

    @server.tool()
    def read_records(table: str) -> dict:
        """Read synthetic records from memory."""
        return execute("read_records", {"table": table})

    @server.tool()
    def read_secret(key: str) -> dict:
        """Read a synthetic token; no real credential exists."""
        return execute("read_secret", {"key": key})

    @server.tool()
    def send_email(recipient: str, body: str) -> dict:
        """Append a message to the in-memory mock email sink."""
        return execute("send_email", {"recipient": recipient, "body": body})

    @server.tool()
    def http_request(destination: str, data: str) -> dict:
        """Append data to the in-memory mock outbound sink; no networking."""
        return execute("http_request", {"destination": destination, "data": data})

    return server


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=[s.id for s in MCP_SCENARIOS], required=True)
    parser.add_argument("--variant", choices=["vulnerable", "hardened"], default="vulnerable")
    args = parser.parse_args()
    policy = json.loads(os.environ.get("VEYRIX_MCP_POLICY", '{"rules":[]}'))
    build_server(args.scenario, args.variant, policy).run(transport="stdio")


if __name__ == "__main__":
    main()
