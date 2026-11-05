"""Portable JSON configuration loading."""

import json
from pathlib import Path


def read_config(path: str) -> dict:
    """Read a JSON object from *path*.

    Configuration intentionally contains connection metadata and credential
    references only; secret resolution belongs to ``core.secrets``.
    """

    config_path = Path(path)
    if not config_path.is_file():
        raise ValueError("config not found: {0}".format(path))
    with config_path.open("r", encoding="utf-8") as handle:
        config = json.load(handle)
    if not isinstance(config, dict):
        raise ValueError("config root must be a JSON object")
    return config
