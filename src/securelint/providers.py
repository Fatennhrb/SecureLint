"""The AI providers ``scan --explain`` can use, chosen in the settings.

Each provider only puts the prompt built by ``securelint.prompt`` into its
own request format and returns the text of the answer. Checking that answer
is done in ``securelint.explain``, the same way for every provider.

* ``anthropic``: Claude, through Anthropic's official Python package. It is
  an optional extra (``pip install "securelint[anthropic]"``), so SecureLint
  itself keeps no dependency.
* ``openai-compatible``: any service that speaks the widely copied
  ``/chat/completions`` format: OpenAI, or a model on this machine such as
  Ollama or LM Studio. Plain ``urllib``, no package.

A key is read from the environment variable the settings name, never from
the settings file.
"""

import importlib
import json
import os
import urllib.error
import urllib.request
from typing import Any

from securelint.config import AISettings
from securelint.explain import Explainer
from securelint.prompt import Prompt

TIMEOUT = 60.0
"""Seconds to wait for one answer."""

MAX_TOKENS = 16_000
"""Room for the model's answer. The answer asked for is short; the room is
large so a model that thinks first is not cut off before it answers."""

MAX_RESPONSE = 1_000_000
"""Bytes read from an OpenAI-compatible service at most."""

# Claude models that accept server-side fallbacks: if the model declines a
# request, Anthropic answers it with a fallback model in the same call.
_FALLBACK_MODELS = frozenset(
    {
        "claude-fable-5-2",
        "claude-fable-5-1",
        "claude-opus-5-5",
        "claude-opus-5",
        "claude-sonnet-5-5",
    }
)
_FALLBACK_BETA = "server-side-fallback-2026-07-01"


class ProviderError(Exception):
    """The provider cannot be used or did not answer; the message says why."""


def make_provider(settings: AISettings) -> Explainer:
    """Return the explainer the settings ask for.

    Raises ``ProviderError`` when it cannot be set up, for example when its
    key is missing.
    """
    key = _key(settings)
    if settings.provider == "anthropic":
        return AnthropicExplainer(settings.model, _anthropic_client(key))
    if settings.base_url is None:
        # The settings reader requires it; this only guards direct callers.
        raise ProviderError("an openai-compatible provider needs base-url")
    return OpenAICompatibleExplainer(settings.model, settings.base_url, key)


def _key(settings: AISettings) -> str | None:
    if settings.api_key_env is None:
        return None
    key = os.environ.get(settings.api_key_env, "").strip()
    if not key:
        raise ProviderError(
            f"the environment variable {settings.api_key_env} is not set; "
            "it must hold the key"
        )
    return key


class AnthropicExplainer:
    """Asks Claude, through a client of the ``anthropic`` package."""

    def __init__(self, model: str, client: Any) -> None:
        self.model = model
        self.client = client

    def explain(self, prompt: Prompt) -> str:
        request: dict[str, Any] = {
            "model": self.model,
            "max_tokens": MAX_TOKENS,
            "system": prompt.system,
            "messages": [{"role": "user", "content": prompt.user}],
        }
        if self.model in _FALLBACK_MODELS:
            response = self.client.beta.messages.create(
                **request, betas=[_FALLBACK_BETA], fallbacks="default"
            )
        else:
            response = self.client.messages.create(**request)

        if response.stop_reason == "refusal":
            raise ProviderError("the model declined to explain this finding")
        if response.stop_reason == "max_tokens":
            raise ProviderError("the answer was cut off before its end")
        # The answer can hold other blocks too (thinking, for example).
        return "".join(block.text for block in response.content if block.type == "text")


def _anthropic_client(key: str | None) -> Any:
    try:
        anthropic = importlib.import_module("anthropic")
    except ImportError:
        raise ProviderError(
            "the anthropic package is not installed; "
            'install it with: pip install "securelint[anthropic]"'
        ) from None
    options: dict[str, Any] = {"timeout": TIMEOUT, "max_retries": 2}
    if key is not None:
        options["api_key"] = key
    # Without a key, the package finds one itself (ANTHROPIC_API_KEY, or a
    # profile saved by Anthropic's own command-line tool).
    return anthropic.Anthropic(**options)


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse redirects: the code and the key go to the address in the
    settings and nowhere else."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class OpenAICompatibleExplainer:
    """Asks a service that speaks the OpenAI ``/chat/completions`` format."""

    def __init__(self, model: str, base_url: str, key: str | None) -> None:
        self.model = model
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.key = key
        self.opener = urllib.request.build_opener(_NoRedirects)

    def explain(self, prompt: Prompt) -> str:
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": prompt.system},
                {"role": "user", "content": prompt.user},
            ],
        }
        headers = {"Content-Type": "application/json"}
        if self.key is not None:
            headers["Authorization"] = f"Bearer {self.key}"
        request = urllib.request.Request(  # noqa: S310 (scheme checked in the settings)
            self.url, data=json.dumps(body).encode(), headers=headers, method="POST"
        )
        try:
            with self.opener.open(request, timeout=TIMEOUT) as response:
                raw = response.read(MAX_RESPONSE + 1)
        except urllib.error.HTTPError as error:
            # The body is not shown: a service may echo the request in it.
            raise ProviderError(f"the service answered HTTP {error.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise ProviderError(f"cannot reach {self.url}: {error}") from None
        if len(raw) > MAX_RESPONSE:
            raise ProviderError("the service's answer is too large")
        return _completion_text(raw)


def _completion_text(raw: bytes) -> str:
    try:
        document = json.loads(raw)
        choice = document["choices"][0]
        text = choice["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError):
        raise ProviderError("the service's answer is not a chat completion") from None
    if not isinstance(text, str):
        raise ProviderError("the service's answer holds no text")
    if choice.get("finish_reason") == "length":
        raise ProviderError("the answer was cut off before its end")
    return text
