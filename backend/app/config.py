"""Configuration loading.

The YAML file is the single source of detector thresholds. Environment variable
PUSHPAK_CONFIG may point to an alternative file. A shallow `local.yaml` next to
the default config is merged on top when present (operator overrides).
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "configs"
DEFAULT_CONFIG = CONFIG_DIR / "default.yaml"
LOCAL_CONFIG = CONFIG_DIR / "local.yaml"


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


class Config:
    def __init__(self, data: dict[str, Any], path: Path):
        self.data = data
        self.path = path

    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> "Config":
        p = Path(path or os.environ.get("PUSHPAK_CONFIG") or DEFAULT_CONFIG)
        with open(p, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if p == DEFAULT_CONFIG and LOCAL_CONFIG.exists():
            with open(LOCAL_CONFIG, "r", encoding="utf-8") as fh:
                data = _deep_merge(data, yaml.safe_load(fh) or {})
        return cls(data, p)

    def get(self, dotted: str, default: Any = None) -> Any:
        cur: Any = self.data
        for part in dotted.split("."):
            if not isinstance(cur, dict) or part not in cur:
                return default
            cur = cur[part]
        return cur

    def detector(self, name: str) -> dict:
        return dict(self.get(f"ids.detectors.{name}", {}) or {})

    def resolve_path(self, dotted: str, default: str) -> Path:
        raw = self.get(dotted, default) or default
        p = Path(raw)
        if not p.is_absolute():
            p = PROJECT_ROOT / p
        p.mkdir(parents=True, exist_ok=True)
        return p

    def redacted(self) -> dict:
        """Config view safe for display/export: secrets and token hashes removed."""
        d = copy.deepcopy(self.data)
        sec = d.get("security", {})
        if sec.get("tokens"):
            sec["tokens"] = [{"role": t.get("role"), "user": t.get("user"), "token_hash": "<redacted>"} for t in sec["tokens"]]
        mav = d.get("mavlink", {})
        if mav.get("signing_key_file"):
            mav["signing_key_file"] = "<configured — path redacted>"
        return d

    def update_overrides(self, patch: dict) -> None:
        """Persist operator overrides to configs/local.yaml (settings changes)."""
        current = {}
        if LOCAL_CONFIG.exists():
            with open(LOCAL_CONFIG, "r", encoding="utf-8") as fh:
                current = yaml.safe_load(fh) or {}
        merged = _deep_merge(current, patch)
        with open(LOCAL_CONFIG, "w", encoding="utf-8") as fh:
            yaml.safe_dump(merged, fh, sort_keys=False)
        self.data = _deep_merge(self.data, patch)


SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def severity_rank(sev: str | None) -> int:
    try:
        return SEVERITIES.index((sev or "INFO").upper())
    except ValueError:
        return 0
