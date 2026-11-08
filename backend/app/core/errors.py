"""Structured error model (spec §97). Stack traces are kept for engineer mode only."""
from __future__ import annotations

import itertools
import threading
import traceback
from collections import deque
from typing import Optional

from ..models.events import utc_now_iso


class ErrorRegistry:
    def __init__(self, maxlen: int = 2000):
        self._items: deque[dict] = deque(maxlen=maxlen)
        self._counter = itertools.count(1)
        self._lock = threading.Lock()
        self.counts: dict[str, int] = {}
        self._listeners = []

    def on_error(self, fn) -> None:
        self._listeners.append(fn)

    def record(self, component: str, type_: str, message: str, recoverable: bool = True,
               exc: Optional[BaseException] = None, context: Optional[dict] = None) -> dict:
        with self._lock:
            err = {
                "error_id": f"ERR-{next(self._counter):06d}",
                "component": component,
                "type": type_,
                "message": message[:500],
                "recoverable": recoverable,
                "timestamp": utc_now_iso(),
                "context": context or {},
                "_detail": "".join(traceback.format_exception(exc))[-4000:] if exc else None,
            }
            self._items.append(err)
            self.counts[component] = self.counts.get(component, 0) + 1
        for fn in self._listeners:
            try:
                fn(err)
            except Exception:
                pass
        return err

    def list(self, limit: int = 200, component: Optional[str] = None, detail: bool = False) -> list[dict]:
        with self._lock:
            items = list(self._items)
        if component:
            items = [e for e in items if e["component"] == component]
        items = items[-limit:][::-1]
        out = []
        for e in items:
            d = {k: v for k, v in e.items() if k != "_detail"}
            if detail:
                d["detail"] = e.get("_detail")
            out.append(d)
        return out

    @staticmethod
    def public(err: dict) -> dict:
        return {k: v for k, v in err.items() if k != "_detail"}
