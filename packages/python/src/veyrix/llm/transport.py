"""Chat Completions transports. The HTTP client never logs headers or response bodies."""

import json
from collections.abc import Mapping
from typing import Any, Protocol

import httpx

from veyrix.adapters import LocalAgentAdapter
from veyrix.llm.config import LLMRunConfig, validate_base_url

_MAX_RESPONSE_BYTES = 1_000_000


class LLMTransportError(Exception):
    """Sanitized model-transport failure. The message must not include secrets or bodies."""


class ChatTransport(Protocol):
    def complete(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], *, timeout: float
    ) -> dict[str, Any]:
        """Return an assistant message with content, tool_calls, and finish_reason."""


def normalize_assistant_message(message: Any, finish_reason: Any = None) -> dict[str, Any]:
    """Reduce a provider message to the fields the scenario loop records and sends back."""
    if not isinstance(message, dict):
        raise LLMTransportError("Model response was not a chat completion")
    content = message.get("content")
    if content is not None and not isinstance(content, str):
        try:
            content = json.dumps(content)
        except TypeError as exc:
            raise LLMTransportError("Model response was not a chat completion") from exc
    raw_calls = message.get("tool_calls") or []
    if not isinstance(raw_calls, list):
        raise LLMTransportError("Model response was not a chat completion")
    calls = []
    for index, call in enumerate(raw_calls):
        if not isinstance(call, dict):
            continue
        function = call.get("function") if isinstance(call.get("function"), dict) else {}
        name = function.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        arguments = function.get("arguments", "{}")
        if not isinstance(arguments, str):
            try:
                arguments = json.dumps(arguments)
            except TypeError as exc:
                raise LLMTransportError("Model response was not a chat completion") from exc
        call_id = call.get("id")
        if not isinstance(call_id, str) or not call_id:
            call_id = f"call_{index + 1}"
        calls.append(
            {
                "id": call_id,
                "type": "function",
                "function": {"name": name.strip(), "arguments": arguments},
            }
        )
    reason = finish_reason if isinstance(finish_reason, str) else message.get("finish_reason")
    return {
        "role": "assistant",
        "content": content,
        "tool_calls": calls,
        "finish_reason": reason if isinstance(reason, str) else None,
    }


class ScriptedChatTransport:
    """Deterministic stand-in for tests. One instance serves one scenario.

    The vulnerable script follows `Call ...` instructions embedded in the user message,
    one tool call per turn. The hardened script refuses without calling tools.
    """

    def __init__(self, variant: str) -> None:
        if variant not in {"vulnerable", "hardened"}:
            raise ValueError("Unsupported scripted model variant")
        self.variant = variant
        self._queue: list | None = None
        self._issued = 0

    def complete(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], *, timeout: float
    ) -> dict[str, Any]:
        del tools, timeout
        if self.variant == "hardened":
            return normalize_assistant_message(
                {
                    "role": "assistant",
                    "content": "I will not follow instructions found in untrusted content.",
                    "tool_calls": [],
                },
                "stop",
            )
        if self._queue is None:
            text = "\n".join(
                message["content"]
                for message in messages
                if message.get("role") == "user" and isinstance(message.get("content"), str)
            )
            self._queue = LocalAgentAdapter("vulnerable").respond("Summarize", text)
        if self._queue is not None and self._issued < len(self._queue):
            request = self._queue[self._issued]
            self._issued += 1
            return normalize_assistant_message(
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": f"call_{self._issued}",
                            "type": "function",
                            "function": {
                                "name": request.action,
                                "arguments": json.dumps(request.arguments),
                            },
                        }
                    ],
                },
                "tool_calls",
            )
        return normalize_assistant_message(
            {
                "role": "assistant",
                "content": "No further tool action.",
                "tool_calls": [],
            },
            "stop",
        )


class HttpxChatTransport:
    """POST `{base_url}/chat/completions` with tools. Redirects and proxy env are ignored."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        timeout: float,
        client: httpx.Client | None = None,
        http_transport: httpx.BaseTransport | None = None,
        max_response_bytes: int = _MAX_RESPONSE_BYTES,
    ) -> None:
        self.base_url = validate_base_url(base_url)
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self._client = client
        self._http_transport = http_transport
        self.max_response_bytes = max_response_bytes

    @classmethod
    def from_config(cls, config: LLMRunConfig, *, model: str | None = None) -> "HttpxChatTransport":
        return cls(
            base_url=config.base_url,
            api_key=config.api_key,
            model=model or config.model,
            timeout=config.timeout_seconds,
        )

    def complete(
        self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], *, timeout: float
    ) -> dict[str, Any]:
        request_timeout = min(self.timeout, timeout) if timeout > 0 else self.timeout
        if self._client is None:
            with httpx.Client(
                timeout=httpx.Timeout(request_timeout),
                follow_redirects=False,
                trust_env=False,
                transport=self._http_transport,
            ) as client:
                return self._post(client, messages, tools)
        return self._post(self._client, messages, tools)

    def _post(
        self, client: httpx.Client, messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> dict[str, Any]:
        headers: dict[str, str] = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto",
        }
        url = self.base_url.rstrip("/") + "/chat/completions"
        try:
            with client.stream("POST", url, headers=headers, json=body) as response:
                if response.status_code != 200:
                    raise LLMTransportError(
                        f"Model request failed with status {response.status_code}"
                    )
                raw = _read_limited(response, self.max_response_bytes)
        except LLMTransportError:
            raise
        except httpx.TimeoutException as exc:
            raise LLMTransportError("Model request timed out") from exc
        except httpx.HTTPError as exc:
            raise LLMTransportError("Model request failed") from exc
        try:
            payload = json.loads(raw)
            choice = payload["choices"][0]
            message = choice["message"]
        except (ValueError, KeyError, IndexError, TypeError):
            # Do not chain the parser error: its text can quote the response body.
            raise LLMTransportError("Model response was not a chat completion") from None
        if not isinstance(message, Mapping):
            raise LLMTransportError("Model response was not a chat completion")
        return normalize_assistant_message(dict(message), choice.get("finish_reason"))


def _read_limited(response: httpx.Response, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > limit:
            raise LLMTransportError("Model response exceeded size limit")
        chunks.append(chunk)
    return b"".join(chunks)
