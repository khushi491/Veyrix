"""OpenAI-compatible tool-calling adapter. Tool execution stays in the synthetic sandbox."""

from veyrix.llm.adapter import run_llm_scenario
from veyrix.llm.config import LLMConfigError, LLMRunConfig, load_llm_run_config
from veyrix.llm.transport import HttpxChatTransport, ScriptedChatTransport

__all__ = [
    "HttpxChatTransport",
    "LLMConfigError",
    "LLMRunConfig",
    "ScriptedChatTransport",
    "load_llm_run_config",
    "run_llm_scenario",
]
