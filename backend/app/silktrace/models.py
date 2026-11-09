from __future__ import annotations
from dataclasses import asdict, dataclass, field
from typing import Any

@dataclass
class ParseResult:
    format_id: str = "unknown.binary"
    format_name: str = "Unknown binary"
    support_level: str = "L1"
    decoder: str = "generic-inspector"
    confidence: float = 0.0
    records: int = 0
    channels: list[dict[str, Any]] = field(default_factory=list)
    samples: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
