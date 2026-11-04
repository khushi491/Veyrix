from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ProjectCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)


class ProjectRead(ProjectCreate):
    model_config = ConfigDict(from_attributes=True)
    id: str
    created_at: datetime


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["transfer_funds", "send_email", "write_file", "delete_records", "http_request"]
    effect: Literal["deny"] = "deny"
    unless: Literal["explicit_user_approval"] | None = None


class SecurityPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy_id: str = Field(default="default", min_length=1, max_length=120)
    rules: list[PolicyRule] = Field(
        default_factory=lambda: [
            PolicyRule(action=action)
            for action in (
                "transfer_funds",
                "send_email",
                "write_file",
                "delete_records",
                "http_request",
            )
        ],
        max_length=100,
    )


class AgentCreate(ProjectCreate):
    adapter: Literal["local", "mcp"] = "local"
    server_variant: Literal["vulnerable", "hardened"] = "vulnerable"
    variant: Literal["vulnerable", "hardened"] = "hardened"
    policy: SecurityPolicy = Field(default_factory=SecurityPolicy)


class AgentRead(AgentCreate):
    model_config = ConfigDict(from_attributes=True)
    id: str
    project_id: str
    created_at: datetime


class RunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    agent_id: str
    created_at: datetime
    status: Literal["queued", "running", "cancelling", "cancelled", "completed", "error"]
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    configuration: dict
    results: list[dict]


class RunCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    suite: Literal[
        "all",
        "mcp-security",
        "prompt-injection",
        "unsafe-tool-execution",
        "authorization-boundary",
        "data-exfiltration",
        "multi-step-manipulation",
    ] = "all"
