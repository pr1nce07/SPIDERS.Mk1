"""Bounded rolling buffers (spec §34). Time- and count-bounded; rotation is
counted so evidence loss is never silent. Snapshot capture copies the pre-event
window out immediately, so confirmed-incident evidence survives rotation."""
from __future__ import annotations

import bisect
import threading
from collections import deque
from typing import Any, Callable, Iterable, Optional


class RollingBuffer:
    def __init__(self, seconds: float, max_items: int, key: Callable[[Any], float]):
        self.seconds = seconds
        self.max_items = max_items
        self.key = key
        self.items: deque = deque()
        self.rotated = 0
        self._lock = threading.Lock()

    def append(self, item) -> None:
        with self._lock:
            self.items.append(item)
            t = self.key(item)
            while self.items and (len(self.items) > self.max_items or t - self.key(self.items[0]) > self.seconds):
                self.items.popleft()
                self.rotated += 1

    def window(self, t0: float, t1: float = float("inf")) -> list:
        with self._lock:
            return [x for x in self.items if t0 <= self.key(x) <= t1]

    def last(self, n: int) -> list:
        with self._lock:
            return list(self.items)[-n:]

    def __len__(self) -> int:
        return len(self.items)

    def clear(self) -> None:
        with self._lock:
            self.items.clear()

    def stats(self) -> dict:
        span = (self.key(self.items[-1]) - self.key(self.items[0])) if len(self.items) > 1 else 0
        return {"items": len(self.items), "max_items": self.max_items, "seconds": self.seconds,
                "span_s": round(span, 1), "rotated": self.rotated}


class PacketIndex:
    """Rolling buffer of TelemetryEvents with O(log n) lookup by idx."""

    def __init__(self, seconds: float, max_items: int):
        self.buf = RollingBuffer(seconds, max_items, key=lambda e: e.t)

    def append(self, ev) -> None:
        self.buf.append(ev)

    def get(self, idx: int):
        with self.buf._lock:
            items = self.buf.items
            if not items or idx < items[0].idx or idx > items[-1].idx:
                return None
            lst = list(items)
        i = bisect.bisect_left([e.idx for e in lst], idx)
        return lst[i] if i < len(lst) and lst[i].idx == idx else None

    def window(self, t0: float, t1: float = float("inf")) -> list:
        return self.buf.window(t0, t1)

    def last(self, n: int) -> list:
        return self.buf.last(n)
