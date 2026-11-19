> [← Back to SecureLint overview](../README.md) · [Full original README snapshot](archive/README-original-2026-11-18.md)

> AI is optional. Security gates are decided before any model is consulted. The `securelint explain FILE --line N` command is currently on `main`, **not** in the published PyPI 1.0.0 release.

## Explaining findings with an AI

`scan --explain` adds a short explanation, written by an AI, under each
finding shown: why the code is risky here and how to fix it. It is off unless
asked for, and the AI is the one the project chooses in its settings:

```toml
[tool.securelint.ai]
provider = "anthropic"            # Claude
model = "claude-opus-5-5"
api-key-env = "ANTHROPIC_API_KEY" # the variable that holds the key
```

```toml
[tool.securelint.ai]
provider = "openai-compatible"    # OpenAI, or a model on this machine
model = "llama3"
base-url = "http://localhost:11434/v1"  # here: Ollama, no key needed
```

| Setting | Meaning |
|---------|---------|
| `provider` | `"anthropic"` or `"openai-compatible"`. |
| `model` | The provider's name for the model. |
| `base-url` | Only for `openai-compatible`: where the service answers. It must be `https://`, or `http://` on this machine. |
| `api-key-env` | The environment variable that holds the key. The key itself is never written in the settings: a setting that looks like a key stops the scan. Optional for Anthropic, which then finds its key itself; leave it out for a local model. |

The `anthropic` provider uses Anthropic's own Python package, installed only
when asked for: `pip install "securelint[anthropic]"`. SecureLint itself still
needs nothing beyond Python. With the Claude models that support it, a request
the model declines is answered by Anthropic's fallback model in the same call.
The `openai-compatible` provider needs no package. It works with any service
that offers the OpenAI `/chat/completions` format, Gemini included (its
`base-url` is `https://generativelanguage.googleapis.com/v1beta/openai`). When
the service is busy (HTTP 429, 500, 502, 503 or 504), it is asked again up to
two times, after 2 and then 4 seconds, or after the wait the service asks for
(30 seconds at most). An answer that takes longer than 60 seconds is asked for
once more, at once. A wrong key, model or address is never retried.

What the AI can and cannot do:

- It only explains. Explanations are added after the policy has decided what
  blocks, so they never change the exit code; one that fails is skipped and
  said on standard error.
- It receives the finding and the 3 lines around it, never the whole file. A
  hard-coded secret, the value of a name that sounds secret, and text shaped
  like a known key are replaced by `***` before anything is sent.
- Its answer must be the short JSON the prompt asks for, or it is dropped.
  Control characters are removed, and every report labels it "AI explanation
  (may be wrong)".
- At most 10 findings are explained in one scan, blocking ones first. Each
  explanation is a paid request to the provider, unless the model runs on this
  machine.
- Explanations are kept in `.securelint-cache/` at the top of the project, so
  the next scan asks again only when something changed: the rule, the lines
  around the finding, the provider or the model. Only answers that passed the
  checks are kept, and the cache holds no code. The folder has its own
  `.gitignore`, so it is never committed; delete it to ask everything again.

### Explaining one line

`securelint explain FILE --line N` explains only the findings on one line of
one file, for example the line an editor's cursor is on:

```bash
securelint explain app.py --line 12
securelint explain app.py --line 12 --format json
```

The file goes through the same steps as with `scan` (settings, baseline,
policy), so the findings explained are the ones a scan shows: silenced and
known findings are not. The report, in text or in the same JSON format as
`scan`, holds only that line's findings, each with its explanation. The exit
code is 0 when every finding on the line was explained, or when the line has
none (then nothing is sent), and 2 when one could not be explained or the file
could not be scanned.
