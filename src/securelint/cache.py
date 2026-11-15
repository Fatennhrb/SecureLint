"""Remember explanations, so the same finding is not paid for twice.

An explanation is kept under a fingerprint of everything that was sent for
it: the provider, the model and the whole prompt (the rule, the message and
the masked lines around the finding). The same question gets the same
answer back; a change in any of them, such as an edited line nearby or
another model, asks the AI again.

The cache lives in ``.securelint-cache/`` at the top of the project, with a
``.gitignore`` of its own so it is never committed. It holds the
explanations and their fingerprints, never any code.

A cache is a convenience: one that cannot be read starts empty, and one
that cannot be written is only reported. Neither changes a scan.
"""

import hashlib
import json
from pathlib import Path

from securelint.prompt import Prompt

CACHE_FOLDER = ".securelint-cache"
_FILE_NAME = "explanations.json"
_FORMAT_VERSION = 1

MAX_ENTRIES = 1000
"""Explanations kept at most; the oldest go first."""


class ExplanationCache:
    """The explanations of one project, for one provider and model."""

    def __init__(self, folder: Path, scope: str) -> None:
        """Open the cache in ``folder``. ``scope`` names the provider and
        model, so their explanations are never mixed with another's."""
        self.folder = folder
        self.scope = scope
        self.problem: str | None = None
        """Why the saved cache could not be used, if it could not."""
        self.entries = self._load()
        self.changed = False
        self.hits = 0
        """How many explanations were found in the cache."""

    def get(self, prompt: Prompt) -> str | None:
        """Return the explanation kept for ``prompt``, if there is one."""
        explanation = self.entries.get(self._key(prompt))
        if explanation is not None:
            self.hits += 1
        return explanation

    def put(self, prompt: Prompt, explanation: str) -> None:
        """Keep ``explanation`` as the answer to ``prompt``."""
        key = self._key(prompt)
        # Put back at the end: the newest entries are the last to go.
        self.entries.pop(key, None)
        self.entries[key] = explanation
        while len(self.entries) > MAX_ENTRIES:
            del self.entries[next(iter(self.entries))]
        self.changed = True

    def save(self) -> str | None:
        """Write the cache if it changed; return why it failed, if it did."""
        if not self.changed:
            return None
        document = {"format_version": _FORMAT_VERSION, "entries": self.entries}
        try:
            self.folder.mkdir(exist_ok=True)
            ignore = self.folder / ".gitignore"
            if not ignore.exists():
                ignore.write_text("# Made by SecureLint.\n*\n", encoding="utf-8")
            # Written beside, then put in place in one step, so a scan that
            # stops halfway never leaves half a file.
            path = self.folder / _FILE_NAME
            partial = path.with_suffix(".tmp")
            partial.write_text(json.dumps(document, indent=1), encoding="utf-8")
            partial.replace(path)
        except OSError as error:
            return f"cannot save the explanation cache: {error}"
        self.changed = False
        return None

    def _key(self, prompt: Prompt) -> str:
        parts = [self.scope, prompt.system, prompt.user]
        return hashlib.sha256("\0".join(parts).encode()).hexdigest()

    def _load(self) -> dict[str, str]:
        path = self.folder / _FILE_NAME
        if not path.exists():
            return {}
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            entries = document["entries"]
            if document["format_version"] != _FORMAT_VERSION or not all(
                isinstance(key, str) and isinstance(text, str)
                for key, text in entries.items()
            ):
                raise ValueError("unexpected content")
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            self.problem = f"the explanation cache was not used: {error}"
            return {}
        return dict(entries)
