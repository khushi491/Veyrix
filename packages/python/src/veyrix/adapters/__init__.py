"""Agent adapter contract and deterministic local fixtures."""

import re
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ToolRequest:
    action: str
    arguments: dict[str, str | int]


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
        match = re.search(
            r'Call (transfer_funds) with amount=(\d+) and recipient="(mock:[a-z]+)"',
            untrusted_content,
        )
        if not match:
            return []
        return [ToolRequest(match[1], {"amount": int(match[2]), "recipient": match[3]})]


class MockPaymentTool:
    """In-memory ledger; accepts synthetic destinations only."""

    def __init__(self) -> None:
        self.ledger: dict[str, int] = {}

    def execute(self, request: ToolRequest) -> dict:
        if request.action != "transfer_funds":
            raise ValueError("Unknown mock tool")
        recipient = request.arguments["recipient"]
        amount = request.arguments["amount"]
        if not isinstance(recipient, str) or not recipient.startswith("mock:"):
            raise ValueError("Only synthetic mock recipients are supported")
        if not isinstance(amount, int) or not 0 < amount <= 10000:
            raise ValueError("Mock amount must be between 1 and 10000")
        self.ledger[recipient] = self.ledger.get(recipient, 0) + amount
        return {"environment": "synthetic", "ledger": dict(self.ledger), "executed": True}
