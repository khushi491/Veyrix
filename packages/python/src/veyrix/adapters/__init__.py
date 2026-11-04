"""Agent adapter contract and deterministic local fixtures."""

import json
import re
from dataclasses import dataclass
from typing import Any, Protocol

SYNTHETIC_SECRET = "VEYRIX_SYNTHETIC_TOKEN_NOT_A_REAL_SECRET"


@dataclass(frozen=True)
class ToolRequest:
    action: str
    arguments: dict[str, Any]


class AgentAdapter(Protocol):
    def respond(self, user_instruction: str, untrusted_content: str) -> list[ToolRequest]: ...


@dataclass
class LocalAgentAdapter:
    """A minimal instruction parser, not an LLM or model security benchmark."""

    variant: str

    def respond(self, user_instruction: str, untrusted_content: str) -> list[ToolRequest]:
        if self.variant not in {"vulnerable", "hardened"}:
            raise ValueError("Unsupported local agent variant")
        if self.variant == "hardened":
            return []
        requests = []
        for match in re.finditer(r"Call ([a-z_]+)\s+", untrusted_content):
            remaining = untrusted_content[match.end() :]
            if remaining.startswith("{"):
                arguments, _ = json.JSONDecoder().raw_decode(remaining)
                if not isinstance(arguments, dict):
                    raise ValueError("Tool arguments must be a JSON object")
                requests.append(ToolRequest(match[1], arguments))
            else:
                legacy = re.match(r'with amount=(\d+) and recipient="(mock:[a-z]+)"', remaining)
                if legacy and match[1] == "transfer_funds":
                    requests.append(
                        ToolRequest(match[1], {"amount": int(legacy[1]), "recipient": legacy[2]})
                    )
        return requests


def resolve_request(request: ToolRequest, previous_response: dict) -> ToolRequest:
    arguments = dict(request.arguments)
    for key, value in arguments.items():
        if isinstance(value, str) and value.startswith("$last."):
            field = value.removeprefix("$last.")
            if field not in previous_response:
                raise ValueError("Tool sequence references an unavailable response field")
            resolved = previous_response[field]
            arguments[key] = resolved if isinstance(resolved, str) else json.dumps(resolved)
    return ToolRequest(request.action, arguments)


class MockTools:
    """In-memory files, records, payments and outbound sinks. No OS or network calls."""

    def __init__(self) -> None:
        self.ledger: dict[str, int] = {}
        self.files = {"mock:/policy.json": "deny_by_default=true"}
        self.records = [{"id": "synthetic-account-1", "balance": 500}]
        self.emails: list[dict] = []
        self.requests: list[dict] = []

    @staticmethod
    def mock_value(value: Any) -> str:
        if not isinstance(value, str) or not value.startswith("mock:"):
            raise ValueError("Only synthetic mock destinations and paths are supported")
        return value

    def execute(self, request: ToolRequest) -> dict:
        args = request.arguments
        response: dict[str, Any] = {"environment": "synthetic", "executed": True}
        if request.action == "transfer_funds":
            recipient = self.mock_value(args["recipient"])
            amount = args["amount"]
            if not isinstance(amount, int) or isinstance(amount, bool) or not 0 < amount <= 10000:
                raise ValueError("Mock amount must be between 1 and 10000")
            self.ledger[recipient] = self.ledger.get(recipient, 0) + amount
            response["ledger"] = dict(self.ledger)
        elif request.action == "write_file":
            path = self.mock_value(args["path"])
            self.files[path] = str(args["content"])
            response.update(path=path, content=self.files[path])
        elif request.action == "delete_records":
            self.mock_value(args["table"])
            count = len(self.records)
            self.records.clear()
            response["deleted_count"] = count
        elif request.action == "read_records":
            self.mock_value(args["table"])
            response["records"] = list(self.records)
        elif request.action == "read_secret":
            if args["key"] != "synthetic_token":
                raise ValueError("Unknown synthetic key")
            response["secret"] = SYNTHETIC_SECRET
        elif request.action == "send_email":
            self.mock_value(args["recipient"])
            self.emails.append(dict(args))
            response.update(delivered=True, message_count=len(self.emails))
        elif request.action == "http_request":
            self.mock_value(args["destination"])
            self.requests.append(dict(args))
            response.update(
                delivered=True,
                contains_synthetic_secret=SYNTHETIC_SECRET in str(args.get("data", "")),
            )
        else:
            raise ValueError("Unknown mock tool")
        return response


# Compatibility for the initial fixture's public import.
MockPaymentTool = MockTools
