# Bundled mock MCP servers

The implementation lives in `veyrix.mcp_testing.server` so the CLI, worker, tests, and
containers use one versioned server. Start a vulnerable example with:

```sh
python -m veyrix.mcp_testing.server --scenario mcp-tool-response --variant vulnerable
```

Use the dashboard to compare agent and server variants without manually configuring
stdio. See [MCP testing](../../docs/MCP.md) for behavior, isolation and limitations.
