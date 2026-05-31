"""Minimal i18n: load a JSON dict from locales/<lang>.json and look up keys.

Add new languages by dropping a JSON file in `locales/`. Switch via
`set_language("xx")` — by default we use English. Missing keys fall back to
the key itself so missing translations are visible but never crash the UI.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_LOCALES_DIR = Path(__file__).parent / "locales"
_DEFAULT_LANG = "en"

_messages: dict[str, str] = {}


def set_language(lang: str) -> None:
    """Load `lang` (e.g. "en"). Falls back to English if the file is missing."""
    global _messages
    path = _LOCALES_DIR / f"{lang}.json"
    if not path.is_file():
        path = _LOCALES_DIR / f"{_DEFAULT_LANG}.json"
    with path.open("r", encoding="utf-8") as f:
        _messages = json.load(f)


def t(key: str, *args: Any) -> str:
    """Translate `key`. Positional args fill `{0}`, `{1}`, ... placeholders."""
    if not _messages:
        set_language(_DEFAULT_LANG)
    msg = _messages.get(key, key)
    if args:
        try:
            return msg.format(*args)
        except (IndexError, KeyError):
            return msg
    return msg
