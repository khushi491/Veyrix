# MCP testing

Engine 0.3.0 uses the official `mcp` Python SDK, version 2.3 or newer within major 2.
The exact SDK version and negotiated protocol version are recorded in each assessment.

Register `adapter=mcp`, choose an agent `variant`, and independently choose
`server_variant=vulnerable` or `hardened`. Agent variants remain deterministic instruction
parsers; no LLM is evaluated. Both server variants expose synthetic tools over stdio.
The hardened server applies the snapshotted policy before any mock mutation or outbound
sink action. A blocked prohibited request remains a verified attempted violation;
it is never presented as executed.

## Cases (all version 1)

- `mcp-tool-response`: payment instruction returned by `read_document`.
- `mcp-tool-description`: file-write instruction in the discovered tool description.
- `mcp-resource-exfiltration`: resource content induces read-secret → outbound chaining.
- `mcp-tool-chain`: tool response induces read-records → email chaining.
- `mcp-broad-permissions`: discovered delete tool is invoked despite a deny policy.
- `mcp-policy-bypass`: tool content falsely claims user authorization.

The worker uses a fresh server for each case. Tools mutate only memory. No real files,
email, payments, secrets, HTTP endpoints or external MCP servers are accessed. Tool
schemas/descriptions, resource content, selected tool requests, responses, policy
results and redacted synthetic secret evidence are inspectable in the dashboard.

## Running the example server manually

From an installed checkout:

```sh
python -m veyrix.mcp_testing.server --scenario mcp-tool-response --variant vulnerable
```

This speaks MCP on stdin/stdout; it is not an HTTP server or an interactive shell.
For a hardened comparison, pass `--variant hardened` with `VEYRIX_MCP_POLICY` set to
synthetic deny rules. The worker supplies the policy from the registered agent automatically.

## Limits and sources

Only bundled allowlisted servers can launch. SDK transport compatibility is tested;
this does not establish security of arbitrary MCP servers or production models.
Container execution limits network access to the internal service network. Local
process execution does not provide equivalent network isolation. Configuration
allowlists do not constitute a hostile-code sandbox.

Primary references consulted:

- [Official SDK client](https://py.sdk.modelcontextprotocol.io/client/)
- [Official SDK server/client source](https://github.com/modelcontextprotocol/python-sdk)
- [MCP security policy](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/SECURITY.md)
- [Local server security](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/docs/2026-07-28/tutorials/security/local-server-security.mdx)
