import os

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str = "postgresql+psycopg://veyrix:veyrix_local@localhost:58439/veyrix"
    redis_url: str = "redis://localhost:6379/0"
    veyrix_dev_mode: bool = False
    # Empty strings are valid so .env.example can list these without values.
    # The API key is excluded from repr so a logged settings object does not reveal it.
    veyrix_llm_base_url: str = ""
    veyrix_llm_model: str = ""
    veyrix_llm_api_key: str = Field(default="", repr=False)
    veyrix_llm_timeout_seconds: str = ""
    veyrix_llm_max_steps: str = ""
    veyrix_llm_scenario_timeout_seconds: str = ""
    veyrix_llm_transport: str = ""
    veyrix_llm_allow_scripted: str = ""


settings = Settings()

_LLM_ENV_FIELDS = (
    ("VEYRIX_LLM_BASE_URL", "veyrix_llm_base_url"),
    ("VEYRIX_LLM_MODEL", "veyrix_llm_model"),
    ("VEYRIX_LLM_API_KEY", "veyrix_llm_api_key"),
    ("VEYRIX_LLM_TIMEOUT_SECONDS", "veyrix_llm_timeout_seconds"),
    ("VEYRIX_LLM_MAX_STEPS", "veyrix_llm_max_steps"),
    ("VEYRIX_LLM_SCENARIO_TIMEOUT_SECONDS", "veyrix_llm_scenario_timeout_seconds"),
    ("VEYRIX_LLM_TRANSPORT", "veyrix_llm_transport"),
    ("VEYRIX_LLM_ALLOW_SCRIPTED", "veyrix_llm_allow_scripted"),
)


def llm_execution_environ() -> dict[str, str]:
    """LLM settings from the process environment, then `.env` when a variable is unset.

    A fresh Settings read picks up variables exported after import. The mapping contains
    only LLM keys. It is not a child process environment. Do not log it: it can hold the
    API key.
    """
    current = Settings()
    merged: dict[str, str] = {}
    for key, field_name in _LLM_ENV_FIELDS:
        value = os.environ.get(key) or getattr(current, field_name) or ""
        if value:
            merged[key] = value
    return merged
