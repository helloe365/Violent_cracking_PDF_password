"""Access bundled password-recovery assets."""

from __future__ import annotations

import json
from pathlib import Path

_DATA_DIRECTORY = Path(__file__).with_name("data")


def bundled_wordlist() -> Path:
    """Return the bundled SecLists common-password dictionary."""
    return _DATA_DIRECTORY / "Pwdb_top-10000000.txt"


def bundled_license() -> Path:
    """Return the bundled SecLists license."""
    return _DATA_DIRECTORY / "SecLists-LICENSE"


def bundled_wordlist_metadata() -> dict[str, str | int]:
    """Return verification metadata for the bundled dictionary."""
    with (_DATA_DIRECTORY / "SOURCE.json").open(encoding="utf-8") as source_file:
        return json.load(source_file)
