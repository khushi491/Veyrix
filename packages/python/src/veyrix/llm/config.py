"""Runtime settings for the OpenAI-compatible adapter. Secrets stay in the environment."""

import ipaddress
import math
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlparse

_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,127}$")
_TRUE = {"1", "true", "yes"}
DEFAULT_BASE_URL = "http://127.0.0.1:11434/v1"


class LLMConfigError(ValueError):
    """The llm adapter is not configured. The message is safe to return to an API client."""


@dataclass(frozen=True)
class LLMRunConfig:
    transport: str
    model: str
    base_url: str
    api_key: str
    timeout_seconds: float
    max_steps: int
    scenario_timeout_seconds: float
    deadline_seconds: float

    def __repr__(self) -> str:
        return (
            "LLMRunConfig("
            f"transport={self.transport!r}, model={self.model!r}, base_url={self.base_url!r}, "
            "api_key='***', "
            f"timeout_seconds={self.timeout_seconds}, max_steps={self.max_steps}, "
            f"scenario_timeout_seconds={self.scenario_timeout_seconds}, "
            f"deadline_seconds={self.deadline_seconds})"
        )


def _loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_base_url(url: str) -> str:
    """Accept an OpenAI-compatible origin. Cleartext HTTP is limited to loopback."""
    if not url or any(ord(char) < 32 or char.isspace() for char in url):
        raise LLMConfigError("VEYRIX_LLM_BASE_URL is not an accepted endpoint")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise LLMConfigError("VEYRIX_LLM_BASE_URL must be an http or https URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise LLMConfigError(
            "VEYRIX_LLM_BASE_URL must not include credentials, a query, or a fragment"
        )
    if parsed.scheme == "http" and not _loopback(parsed.hostname):
        raise LLMConfigError("Cleartext VEYRIX_LLM_BASE_URL is limited to a loopback address")
    path = parsed.path.rstrip("/").removesuffix("/chat/completions")
    if ".." in path.split("/"):
        raise LLMConfigError("VEYRIX_LLM_BASE_URL is not an accepted endpoint")
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def _bounded_float(raw: str | None, default: float, low: float, high: float, name: str) -> float:
    if raw is None or not str(raw).strip():
        return default
    try:
        value = float(str(raw).strip())
    except ValueError as exc:
        raise LLMConfigError(f"{name} must be a number") from exc
    if not math.isfinite(value) or value < low or value > high:
        raise LLMConfigError(f"{name} must be between {low:g} and {high:g}")
    return value


def _bounded_int(raw: str | None, default: int, low: int, high: int, name: str) -> int:
    if raw is None or not str(raw).strip():
        return default
    text = str(raw).strip()
    if not re.fullmatch(r"[0-9]+", text):
        raise LLMConfigError(f"{name} must be an integer")
    value = int(text)
    if value < low or value > high:
        raise LLMConfigError(f"{name} must be between {low} and {high}")
    return value


def load_llm_run_config(environ: Mapping[str, str] | None = None) -> LLMRunConfig:
    """Read the llm adapter settings. The API key is returned only for the runner child."""
    env = os.environ if environ is None else environ
    transport = (env.get("VEYRIX_LLM_TRANSPORT") or "http").strip().lower()
    if transport not in {"http", "scripted"}:
        raise LLMConfigError("VEYRIX_LLM_TRANSPORT must be http or scripted")
    allowed = (env.get("VEYRIX_LLM_ALLOW_SCRIPTED") or "").strip().lower() in _TRUE
    if transport == "scripted" and not allowed:
        raise LLMConfigError("Scripted model transport requires VEYRIX_LLM_ALLOW_SCRIPTED=1")
    model = (env.get("VEYRIX_LLM_MODEL") or "").strip()
    if not model and transport == "scripted":
        model = "scripted"
    if not _MODEL_RE.fullmatch(model):
        raise LLMConfigError("VEYRIX_LLM_MODEL must be set to a model name without spaces")
    base_url = validate_base_url((env.get("VEYRIX_LLM_BASE_URL") or DEFAULT_BASE_URL).strip())
    scenario_timeout = _bounded_float(
        env.get("VEYRIX_LLM_SCENARIO_TIMEOUT_SECONDS"),
        45,
        1,
        50,
        "VEYRIX_LLM_SCENARIO_TIMEOUT_SECONDS",
    )
    deadline = max(1.0, scenario_timeout - 5)
    if (env.get("VEYRIX_LLM_DEADLINE_SECONDS") or "").strip():
        deadline = _bounded_float(
            env.get("VEYRIX_LLM_DEADLINE_SECONDS"),
            deadline,
            1,
            45,
            "VEYRIX_LLM_DEADLINE_SECONDS",
        )
    timeout = min(
        _bounded_float(
            env.get("VEYRIX_LLM_TIMEOUT_SECONDS"), 20, 1, 30, "VEYRIX_LLM_TIMEOUT_SECONDS"
        ),
        deadline,
    )
    return LLMRunConfig(
        transport=transport,
        model=model,
        base_url=base_url,
        api_key=(env.get("VEYRIX_LLM_API_KEY") or "").strip(),
        timeout_seconds=timeout,
        max_steps=_bounded_int(env.get("VEYRIX_LLM_MAX_STEPS"), 6, 1, 8, "VEYRIX_LLM_MAX_STEPS"),
        scenario_timeout_seconds=scenario_timeout,
        deadline_seconds=deadline,
    )
