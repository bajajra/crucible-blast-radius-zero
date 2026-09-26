"""Small, synchronous client for Vultr Serverless Inference.

The model catalog is public. Generation and reranking require a Serverless
Inference subscription key, which is distinct from a Vultr infrastructure API
key. No request or exception exposes the key or prompt body.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import ssl
import sys
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


DEFAULT_BASE_URL = "https://api.vultrinference.com/v1"
DEFAULT_TIMEOUT = 30.0
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

# Defaults from the project plan. The live catalog is checked by the smoke
# command, and each role can be overridden without modifying source code.
MODEL_ROLES = {
    "red": "glm-5.3",
    "worker": "deepseek-v4-flash-0731",
    "evolver": "glm-5.3",
    "supervisor": "glm-5.3-flash",
    # The content-safety model emits fixed safety labels, not our custom JSON
    # policy verdict. GLM Flash follows the typed D3 decision contract.
    "classifier": "glm-5.3-flash",
    "reranker": "bge-reranker-v2-m3",
}


class VultrError(Exception):
    """Base class for errors with safe, credential-free messages."""


class VultrConfigError(VultrError):
    """Missing or invalid client configuration."""


class VultrAPIError(VultrError):
    """The server returned a non-success HTTP status."""

    def __init__(self, status: int, path: str):
        self.status = status
        self.path = path
        super().__init__(f"Vultr inference {path} returned HTTP {status}")


class VultrTimeoutError(VultrError):
    """The request exceeded its timeout."""


class VultrResponseError(VultrError):
    """The server response was missing, malformed, or unexpected."""


def model_for_role(role: str) -> str:
    """Resolve a role to its configured model ID."""
    if role not in MODEL_ROLES:
        raise VultrConfigError(f"Unknown Vultr model role: {role!r}")
    model = os.getenv(f"VULTR_MODEL_{role.upper()}", MODEL_ROLES[role]).strip()
    if not model or any(char.isspace() for char in model):
        raise VultrConfigError(f"Invalid model ID for role {role!r}")
    return model


def configured_models() -> dict[str, str]:
    return {role: model_for_role(role) for role in MODEL_ROLES}


def _base_url() -> str:
    url = os.getenv("VULTR_INFERENCE_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    parsed = urlsplit(url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise VultrConfigError("Invalid Vultr inference base URL")
    if parsed.scheme != "https" and not (
        parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    ):
        raise VultrConfigError("Vultr inference base URL must use HTTPS")
    if not parsed.netloc or not parsed.path.rstrip("/").endswith("/v1"):
        raise VultrConfigError("Vultr inference base URL must end in /v1")
    return url


def _api_key() -> str:
    # The first name matches the project plan; the second matches Vultr's docs.
    key = (
        os.getenv("VULTR_INFERENCE_API_KEY")
        or os.getenv("VULTR_SERVERLESS_INFERENCE_API_KEY")
        or ""
    ).strip()
    if not key:
        raise VultrConfigError(
            "Set VULTR_INFERENCE_API_KEY or VULTR_SERVERLESS_INFERENCE_API_KEY"
        )
    if any(char in key for char in "\r\n"):
        raise VultrConfigError("Invalid Vultr inference key")
    return key


def _tls_context() -> ssl.SSLContext | None:
    """Use an installed CA bundle when this Python has no default cert file.

    Some python.org macOS builds ship without their OpenSSL cert file. Certifi
    is optional: Linux system Python normally has a working default bundle.
    """
    if ssl.get_default_verify_paths().cafile:
        return None
    try:
        import certifi
    except ImportError:
        return None
    return ssl.create_default_context(cafile=certifi.where())


class _RejectRedirects(HTTPRedirectHandler):
    """A redirected request must never carry the inference bearer key."""

    def redirect_request(self, request: Request, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        return None


def _open_request(request: Request, *, timeout: float, context: ssl.SSLContext | None) -> Any:
    # urllib's default opener follows redirects. Build a per-call opener so a
    # 30x response cannot forward Authorization to another origin.
    return build_opener(_RejectRedirects(), HTTPSHandler(context=context)).open(request, timeout=timeout)


def _request(path: str, payload: dict[str, Any] | None = None, *, authenticated: bool, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    headers = {"Accept": "application/json"}
    if authenticated:
        headers["Authorization"] = f"Bearer {_api_key()}"
    data = None
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    url = _base_url() + path
    request = Request(url, data=data, headers=headers, method="POST" if data is not None else "GET")
    try:
        context = _tls_context() if url.startswith("https://") else None
        with _open_request(request, timeout=timeout, context=context) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        raise VultrAPIError(exc.code, path) from None
    except (TimeoutError, socket.timeout) as exc:
        raise VultrTimeoutError(f"Vultr inference {path} timed out") from None
    except URLError as exc:
        if isinstance(exc.reason, (TimeoutError, socket.timeout)):
            raise VultrTimeoutError(f"Vultr inference {path} timed out") from None
        raise VultrError(f"Vultr inference {path} connection failed") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise VultrResponseError(f"Vultr inference {path} response exceeded size limit")
    try:
        result = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise VultrResponseError(f"Vultr inference {path} returned invalid JSON") from None
    if not isinstance(result, dict):
        raise VultrResponseError(f"Vultr inference {path} returned an unexpected JSON shape")
    return result


def list_models(*, timeout: float = DEFAULT_TIMEOUT) -> list[dict[str, Any]]:
    """Fetch the live public catalog, including chat and reranking models."""
    response = _request("/models", authenticated=False, timeout=timeout)
    models = response.get("data")
    if not isinstance(models, list) or not all(isinstance(m, dict) and isinstance(m.get("id"), str) for m in models):
        raise VultrResponseError("Vultr inference /models returned an unexpected catalog")
    return models


def _default_reasoning(model: str) -> dict[str, Any] | None:
    """Keep reasoning bounded while leaving enough room for visible text.

    The live catalog says GLM-5.3 enforces a thinking-token budget. DeepSeek
    V4 Flash does not, so its worker actions use non-thinking mode instead.
    """
    if model.startswith("glm-5.3"):
        return {"effort": "minimal", "max_tokens": 32}
    if model.startswith("deepseek-v4"):
        return {"enabled": False}
    return None


def chat_completion(role: str, messages: list[dict[str, Any]], *, timeout: float = DEFAULT_TIMEOUT, **kwargs: Any) -> dict[str, Any]:
    """Return the complete OpenAI-compatible chat-completion response."""
    if not isinstance(messages, list) or not messages or not all(isinstance(m, dict) for m in messages):
        raise ValueError("messages must be a nonempty list of dictionaries")
    if {"model", "messages"} & kwargs.keys():
        raise ValueError("model and messages are set by the role and messages arguments")
    if kwargs.get("stream"):
        raise ValueError("streaming responses are not supported by this client")
    model = model_for_role(role)
    options = dict(kwargs)
    if "reasoning" not in options and "reasoning_effort" not in options:
        default_reasoning = _default_reasoning(model)
        if default_reasoning is not None:
            options["reasoning"] = default_reasoning
    # max_tokens is Vultr's deprecated alias for a total completion cap. Our
    # callers use it as the desired visible-output allowance; reserve the
    # explicit GLM thinking budget on top, still with a firm total cap.
    visible_tokens = options.pop("max_tokens", None)
    if visible_tokens is not None:
        if "max_completion_tokens" in options:
            raise ValueError("use either max_tokens or max_completion_tokens")
        if isinstance(visible_tokens, bool) or not isinstance(visible_tokens, int) or visible_tokens < 1:
            raise ValueError("max_tokens must be a positive integer")
        reasoning = options.get("reasoning")
        budget = reasoning.get("max_tokens", 0) if isinstance(reasoning, dict) else 0
        options["max_completion_tokens"] = visible_tokens + budget
    else:
        options.setdefault("max_completion_tokens", 512)
    payload: dict[str, Any] = {"model": model, "messages": messages}
    payload.update(options)
    response = _request("/chat/completions", payload, authenticated=True, timeout=timeout)
    if not isinstance(response.get("choices"), list):
        raise VultrResponseError("Vultr inference chat response has no choices")
    return response


def chat(role: str, messages: list[dict[str, Any]], **kwargs: Any) -> str:
    """Return the first assistant text; use chat_completion for tool calls."""
    response = chat_completion(role, messages, **kwargs)
    try:
        content = response["choices"][0]["message"]["content"]
    except (IndexError, KeyError, TypeError):
        raise VultrResponseError("Vultr inference chat response has no message content") from None
    if not isinstance(content, str):
        raise VultrResponseError("Vultr inference chat returned no visible text; raise the completion cap or reduce reasoning")
    return content


def chat_json(role: str, messages: list[dict[str, Any]], **kwargs: Any) -> dict[str, Any]:
    """Extract one JSON object from a chat response, including fenced output."""
    content = chat(role, messages, **kwargs).strip()
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", content):
        try:
            value, _ = decoder.raw_decode(content[match.start():])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise VultrResponseError("Vultr inference chat response contained no JSON object")


def rerank(query: str, documents: list[str], top_n: int = 5, *, timeout: float = DEFAULT_TIMEOUT) -> list[dict[str, Any]]:
    """Rerank past episodes with Vultr's documented /v1/rerank API."""
    if not isinstance(query, str) or not query.strip():
        raise ValueError("query must be a nonempty string")
    if not isinstance(documents, list) or not all(isinstance(doc, str) for doc in documents):
        raise ValueError("documents must be a list of strings")
    if not documents:
        return []
    if not isinstance(top_n, int) or isinstance(top_n, bool) or not 1 <= top_n <= 100:
        raise ValueError("top_n must be an integer from 1 to 100")
    response = _request(
        "/rerank",
        {"model": model_for_role("reranker"), "query": query, "documents": documents,
         "top_n": min(top_n, len(documents)), "return_documents": True},
        authenticated=True,
        timeout=timeout,
    )
    results = response.get("results")
    if not isinstance(results, list) or not all(isinstance(item, dict) for item in results):
        raise VultrResponseError("Vultr inference /rerank returned an unexpected result")
    return results


def _smoke(with_chat: bool) -> int:
    models = list_models()
    available = {model["id"] for model in models}
    print(f"Catalog: {len(models)} models")
    for role, model in configured_models().items():
        print(f"  {role}: {model} ({'available' if model in available else 'not in catalog'})")
    if with_chat:
        reply = chat("supervisor", [{"role": "user", "content": "Reply with the single word up."}], max_tokens=96)
        print(f"Chat: OK ({len(reply)} characters returned)")
    else:
        print("Chat: skipped (pass --chat for a small authenticated test)")
    return 0


def main(argv: list[str] | None = None) -> int:
    from crucible.env import load_env_local
    from pathlib import Path
    load_env_local(Path(__file__).resolve().parent.parent)
    parser = argparse.ArgumentParser(description="Vultr Serverless Inference utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)
    smoke = subparsers.add_parser("smoke", help="check the live model catalog")
    smoke.add_argument("--chat", action="store_true", help="make one small billable chat request")
    args = parser.parse_args(argv)
    try:
        if args.command == "smoke":
            return _smoke(args.chat)
    except VultrError as exc:
        print(f"Smoke failed: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
