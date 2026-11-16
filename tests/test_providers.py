"""Tests for the AI providers and their settings.

No test talks to a real AI. A small HTTP server on this machine plays the
service, so the tests see exactly what each provider sends, and nothing
leaves the machine or costs money.
"""

import json
import sys
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from securelint import providers
from securelint.cli import main
from securelint.config import AISettings, ConfigError, ai_provider, load_config
from securelint.prompt import Prompt
from securelint.providers import (
    AnthropicExplainer,
    OpenAICompatibleExplainer,
    ProviderError,
    make_provider,
)

PROMPT = Prompt(system="Explain findings.", user="Rule: SL101")
ANSWER = json.dumps({"explanation": "eval runs any code.", "fix": "Remove it."})


# A fake service.


@dataclass
class Service:
    """What the fake service answers, and what it received."""

    status: int = 200
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    requests: list[tuple[str, dict[str, str], Any]] = field(default_factory=list)
    url: str = ""
    first: list[tuple[int, dict[str, str]]] = field(default_factory=list)
    """Statuses (with headers) answered first, one per request, before the
    usual answer: to play a busy service."""
    slow: list[float] = field(default_factory=list)
    """Seconds to wait before answering, one per request: to play a slow
    service."""

    def answer(self, document: Any, status: int = 200) -> None:
        self.status = status
        self.body = json.dumps(document).encode()


class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request: Any, client_address: Any) -> None:
        # A client that stopped waiting (the timeout tests) closes the
        # connection before the answer is written: expected, not an error.
        pass


@pytest.fixture
def service() -> Iterator[Service]:
    state = Service()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"null")
            # Header names in lower case: their case is not part of HTTP.
            sent = {name.lower(): value for name, value in self.headers.items()}
            state.requests.append((self.path, sent, body))
            if state.slow:
                time.sleep(state.slow.pop(0))
            status, headers, answer = state.status, state.headers, state.body
            if state.first:
                status, headers = state.first.pop(0)
                answer = b'{"error": "busy"}'
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(answer)))
            self.end_headers()
            self.wfile.write(answer)

        def log_message(self, *args: Any) -> None:
            pass

    server = QuietServer(("127.0.0.1", 0), Handler)
    # Stopping the server never waits for a connection a client left open.
    server.daemon_threads = True
    server.block_on_close = False
    # A short poll interval, so stopping the server does not wait 0.5 s.
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    state.url = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()


# Settings.


def settings_of(tmp_path: Path, table: str) -> AISettings | None:
    (tmp_path / "pyproject.toml").write_text(
        "[tool.securelint.ai]\n" + table, encoding="utf-8"
    )
    return load_config(tmp_path, []).ai


def test_settings_for_claude(tmp_path: Path) -> None:
    ai = settings_of(tmp_path, 'provider = "anthropic"\nmodel = "claude-opus-5-5"\n')

    assert ai == AISettings(provider="anthropic", model="claude-opus-5-5")


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:11434/v1",
        "http://127.0.0.1:8080",
        "https://api.example.com/v1",
    ],
)
def test_settings_for_an_openai_compatible_service(tmp_path: Path, url: str) -> None:
    ai = settings_of(
        tmp_path,
        f'provider = "openai-compatible"\nmodel = "llama3"\nbase-url = "{url}"\n'
        'api-key-env = "MY_KEY"\n',
    )

    assert ai == AISettings("openai-compatible", "llama3", url, "MY_KEY")


def test_no_ai_table_means_no_provider(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[tool.securelint]\n", encoding="utf-8")

    assert load_config(tmp_path, []).ai is None


@pytest.mark.parametrize(
    ("table", "message"),
    [
        (
            'provider = "anthropic"\nmodel = "m"\napi-key = "sk-123"\n',
            "must not hold a key",
        ),
        (
            'provider = "anthropic"\nmodel = "m"\nkey = "sk-123"\n',
            "must not hold a key",
        ),
        ('provider = "gemini"\nmodel = "m"\n', "provider must be one of"),
        ('provider = "anthropic"\n', "model must name a model"),
        ('provider = "anthropic"\nmodel = "m"\ntemperature = 0\n', "unknown setting"),
        ('provider = "openai-compatible"\nmodel = "m"\n', "needs base-url"),
        (
            'provider = "anthropic"\nmodel = "m"\nbase-url = "https://x.example"\n',
            "only for openai-compatible",
        ),
        (
            'provider = "openai-compatible"\nmodel = "m"\nbase-url = "http://x.example"\n',
            "must be an https:// address",
        ),
        (
            'provider = "openai-compatible"\nmodel = "m"\n'
            'base-url = "https://me:pw@x.example"\n',
            "without a name or password",
        ),
        (
            'provider = "openai-compatible"\nmodel = "m"\nbase-url = "file:///etc"\n',
            "must be an https:// address",
        ),
        (
            'provider = "anthropic"\nmodel = "m"\napi-key-env = "MY KEY"\n',
            "api-key-env",
        ),
    ],
)
def test_wrong_settings_stop_the_scan(tmp_path: Path, table: str, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        settings_of(tmp_path, table)


def test_a_missing_key_is_said(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_SUCH_KEY", raising=False)
    ai = AISettings("openai-compatible", "m", "http://localhost:1", "NO_SUCH_KEY")

    with pytest.raises(ProviderError, match="NO_SUCH_KEY is not set"):
        make_provider(ai)


# Claude, with a fake client: what is asked, and how the answer is read.


class FakeClient:
    def __init__(self, stop_reason: str = "end_turn") -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        content = [
            SimpleNamespace(type="thinking", thinking=""),
            SimpleNamespace(type="text", text=ANSWER),
        ]
        response = SimpleNamespace(stop_reason=stop_reason, content=content)

        def create(kind: str) -> Callable[..., Any]:
            def call(**request: Any) -> Any:
                self.calls.append((kind, request))
                return response

            return call

        self.messages = SimpleNamespace(create=create("messages"))
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=create("beta")))


def test_claude_gets_the_prompt_and_answers_with_text() -> None:
    client = FakeClient()

    text = AnthropicExplainer("claude-opus-5-5", client).explain(PROMPT)

    assert text == ANSWER
    ((kind, request),) = client.calls
    assert kind == "beta"
    assert request["model"] == "claude-opus-5-5"
    assert request["system"] == "Explain findings."
    assert request["messages"] == [{"role": "user", "content": "Rule: SL101"}]
    # A model that declines is replaced by Anthropic's own fallback.
    assert request["fallbacks"] == "default"
    assert request["betas"] == ["server-side-fallback-2026-07-01"]


def test_models_without_fallbacks_use_the_plain_request() -> None:
    client = FakeClient()

    AnthropicExplainer("claude-haiku-5-5", client).explain(PROMPT)

    ((kind, request),) = client.calls
    assert kind == "messages"
    assert "fallbacks" not in request


@pytest.mark.parametrize(
    ("stop_reason", "message"),
    [("refusal", "declined"), ("max_tokens", "cut off")],
)
def test_an_unfinished_claude_answer_is_an_error(
    stop_reason: str, message: str
) -> None:
    explainer = AnthropicExplainer("claude-opus-5-5", FakeClient(stop_reason))

    with pytest.raises(ProviderError, match=message):
        explainer.explain(PROMPT)


def test_without_the_package_claude_cannot_be_set_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # None in sys.modules makes any import of the package fail.
    monkeypatch.setitem(sys.modules, "anthropic", None)

    with pytest.raises(ProviderError, match=r'pip install "securelint\[anthropic\]"'):
        make_provider(AISettings("anthropic", "claude-opus-5-5"))


# Claude, with the real anthropic package and a fake Anthropic service.


def message(stop_reason: str = "end_turn") -> dict[str, Any]:
    return {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-5-5",
        "content": [{"type": "text", "text": ANSWER}],
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 5},
    }


def test_the_real_package_sends_the_expected_request(
    service: Service, monkeypatch: pytest.MonkeyPatch
) -> None:
    anthropic = pytest.importorskip("anthropic")
    service.answer(message())
    monkeypatch.setenv("TEST_ANTHROPIC_KEY", "sk-ant-test")
    # Only the address changes: the package is used exactly as it will be.
    real = anthropic.Anthropic

    def to_fake_service(**options: Any) -> Any:
        return real(**options, base_url=service.url)

    monkeypatch.setattr(anthropic, "Anthropic", to_fake_service)

    explainer = make_provider(
        AISettings("anthropic", "claude-opus-5-5", api_key_env="TEST_ANTHROPIC_KEY")
    )
    text = explainer.explain(PROMPT)

    assert text == ANSWER
    ((path, headers, body),) = service.requests
    assert path.startswith("/v1/messages")
    # The key from the environment variable the settings name.
    assert "sk-ant-test" in headers["authorization"]
    assert "anthropic-version" in headers
    assert "server-side-fallback-2026-07-01" in headers["anthropic-beta"]
    assert body["model"] == "claude-opus-5-5"
    assert body["fallbacks"] == "default"
    assert body["system"] == "Explain findings."
    assert body["messages"] == [{"role": "user", "content": "Rule: SL101"}]
    # Nothing that the current API version refuses.
    assert not {"temperature", "top_p", "top_k"} & set(body)


# OpenAI-compatible services, through urllib.


def completion(text: str = ANSWER, finish_reason: str = "stop") -> dict[str, Any]:
    return {
        "choices": [
            {
                "message": {"role": "assistant", "content": text},
                "finish_reason": finish_reason,
            }
        ]
    }


def test_a_compatible_service_gets_the_prompt(service: Service) -> None:
    service.answer(completion())
    explainer = OpenAICompatibleExplainer("llama3", service.url + "/v1/", "sk-test")

    text = explainer.explain(PROMPT)

    assert text == ANSWER
    ((path, headers, body),) = service.requests
    assert path == "/v1/chat/completions"
    assert headers["authorization"] == "Bearer sk-test"
    assert body == {
        "model": "llama3",
        "messages": [
            {"role": "system", "content": "Explain findings."},
            {"role": "user", "content": "Rule: SL101"},
        ],
    }


def test_a_local_service_needs_no_key(service: Service) -> None:
    service.answer(completion())

    OpenAICompatibleExplainer("llama3", service.url, None).explain(PROMPT)

    ((_, headers, _),) = service.requests
    assert "authorization" not in headers


def test_an_error_status_does_not_show_the_service_answer(service: Service) -> None:
    service.answer({"error": "bad key sk-test"}, status=401)
    explainer = OpenAICompatibleExplainer("llama3", service.url, "sk-test")

    with pytest.raises(ProviderError, match="HTTP 401") as error:
        explainer.explain(PROMPT)

    assert "sk-test" not in str(error.value)


def test_a_redirect_is_not_followed(service: Service) -> None:
    service.answer({}, status=307)
    service.headers = {"Location": "https://elsewhere.example/steal"}
    explainer = OpenAICompatibleExplainer("llama3", service.url, "sk-test")

    with pytest.raises(ProviderError, match="HTTP 307"):
        explainer.explain(PROMPT)

    assert len(service.requests) == 1


def test_a_huge_answer_is_refused(service: Service) -> None:
    service.body = b"x" * (providers.MAX_RESPONSE + 10)

    with pytest.raises(ProviderError, match="too large"):
        OpenAICompatibleExplainer("llama3", service.url, None).explain(PROMPT)


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({"error": "no"}, "not a chat completion"),
        ({"choices": []}, "not a chat completion"),
        (completion(text=None), "holds no text"),  # type: ignore[arg-type]
        (completion(finish_reason="length"), "cut off"),
    ],
)
def test_a_strange_answer_is_an_error(
    service: Service, document: Any, message: str
) -> None:
    service.answer(document)

    with pytest.raises(ProviderError, match=message):
        OpenAICompatibleExplainer("llama3", service.url, None).explain(PROMPT)


def test_a_service_that_cannot_be_reached(tmp_path: Path) -> None:
    # Port 9 on this machine: nothing listens there.
    explainer = OpenAICompatibleExplainer("llama3", "http://127.0.0.1:9", None)

    with pytest.raises(ProviderError, match="cannot reach"):
        explainer.explain(PROMPT)


# The whole command, with a local compatible service.


def project_with_ai(tmp_path: Path, url: str, extra: str = "") -> Path:
    (tmp_path / "app.py").write_text("eval(x)\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[tool.securelint.ai]\n"
        f'provider = "openai-compatible"\nmodel = "llama3"\nbase-url = "{url}"\n'
        + extra,
        encoding="utf-8",
    )
    return tmp_path


def test_scan_explain_uses_the_provider_of_the_settings(
    tmp_path: Path, service: Service, capsys: pytest.CaptureFixture[str]
) -> None:
    service.answer(completion())
    project = project_with_ai(tmp_path, service.url)

    assert main(["scan", str(project), "--explain"]) == 1

    out = capsys.readouterr().out
    assert "AI explanation (may be wrong): eval runs any code. Fix: Remove it." in out
    ((_, _, body),) = service.requests
    assert "> 1 | eval(x)" in body["messages"][1]["content"]


def test_a_provider_that_cannot_be_set_up_changes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("NO_SUCH_KEY", raising=False)
    project = project_with_ai(
        tmp_path, "http://localhost:1", 'api-key-env = "NO_SUCH_KEY"\n'
    )

    assert main(["scan", str(project), "--explain"]) == 1

    captured = capsys.readouterr()
    assert "no explanations were added: the environment variable NO_SUCH_KEY" in (
        captured.err
    )
    assert "AI explanation" not in captured.out


def test_without_ai_settings_the_option_says_how_to_set_one_up(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "app.py").write_text("eval(x)\n", encoding="utf-8")

    assert main(["scan", str(tmp_path), "--explain"]) == 1
    assert "no AI provider is set up in [tool.securelint.ai]" in capsys.readouterr().err


# A busy service is asked again; other errors are not.


class Waits:
    """Records the waits instead of sleeping, so tests stay fast."""

    def __init__(self) -> None:
        self.seconds: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.seconds.append(seconds)


def busy_explainer(service: Service, waits: Waits) -> OpenAICompatibleExplainer:
    return OpenAICompatibleExplainer("gemini", service.url, "k", sleep=waits)


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
def test_a_busy_service_is_asked_again(service: Service, status: int) -> None:
    service.answer(completion())
    service.first = [(status, {})]
    waits = Waits()

    text = busy_explainer(service, waits).explain(PROMPT)

    assert text == ANSWER
    assert len(service.requests) == 2
    assert waits.seconds == [2.0]


def test_a_service_busy_every_time_gives_up_after_three_attempts(
    service: Service,
) -> None:
    service.answer(completion())
    service.first = [(503, {}), (503, {}), (503, {})]
    waits = Waits()

    with pytest.raises(ProviderError, match=r"HTTP 503 \(after 3 attempts\)"):
        busy_explainer(service, waits).explain(PROMPT)

    assert len(service.requests) == 3
    # Waiting longer each time.
    assert waits.seconds == [2.0, 4.0]


@pytest.mark.parametrize(
    ("retry_after", "waited"), [("1", 1.0), ("3600", 30.0), ("soon", 2.0)]
)
def test_the_service_says_how_long_to_wait(
    service: Service, retry_after: str, waited: float
) -> None:
    service.answer(completion())
    service.first = [(429, {"Retry-After": retry_after})]
    waits = Waits()

    busy_explainer(service, waits).explain(PROMPT)

    # Followed when short, capped when long, ignored when not a number.
    assert waits.seconds == [waited]


@pytest.mark.parametrize("status", [400, 401, 403, 404])
def test_a_wrong_setting_is_never_retried(service: Service, status: int) -> None:
    service.answer({"error": "no"}, status=status)
    waits = Waits()

    with pytest.raises(ProviderError, match=f"HTTP {status}$"):
        busy_explainer(service, waits).explain(PROMPT)

    assert len(service.requests) == 1
    assert waits.seconds == []


# A slow service is asked once more; a second slow answer is the end.


def test_one_slow_answer_is_asked_again(
    service: Service, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(providers, "TIMEOUT", 0.3)
    service.answer(completion())
    service.slow = [1.0]
    waits = Waits()

    text = busy_explainer(service, waits).explain(PROMPT)

    assert text == ANSWER
    assert len(service.requests) == 2
    # Asked again at once: the timeout has already been a long wait.
    assert waits.seconds == []


def test_two_slow_answers_give_up(
    service: Service, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(providers, "TIMEOUT", 0.3)
    service.answer(completion())
    service.slow = [1.0, 1.0]

    with pytest.raises(ProviderError, match="timed out"):
        busy_explainer(service, Waits()).explain(PROMPT)

    assert len(service.requests) == 2


# Which provider the settings name, read without checking the rest.


@pytest.mark.parametrize(
    ("content", "provider"),
    [
        ('[tool.securelint.ai]\nprovider = "anthropic"\n', "anthropic"),
        ('[tool.securelint.ai]\nprovider = "openai-compatible"\n', "openai-compatible"),
        ("[tool.securelint]\n", None),
        ("[tool.securelint.ai]\nprovider = 3\n", None),
        ("not [valid toml", None),
    ],
)
def test_the_named_provider(tmp_path: Path, content: str, provider: str | None) -> None:
    (tmp_path / "pyproject.toml").write_text(content, encoding="utf-8")

    assert ai_provider(tmp_path) == provider


def test_no_settings_name_no_provider(tmp_path: Path) -> None:
    assert ai_provider(tmp_path) is None
