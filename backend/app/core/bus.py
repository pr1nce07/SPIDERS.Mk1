"""Internal asynchronous event bus with bounded, lossy-for-presentation queues.

Publishing never blocks the ingest path. Each subscriber owns a bounded queue;
when a presentation subscriber falls behind the oldest item is dropped and the
drop is counted (and visible in the health view). Forensic persistence does not
rely on the bus — the recorder and DB writer are called directly by the
pipeline so that evidence is never subject to presentation back-pressure.
"""
from __future__ import annotations

import asyncio
import threading
from collections import defaultdict
from typing import Callable, Iterable

from ..models.events import BusEvent


class Subscription:
    def __init__(self, name: str, types: set[str] | None, maxsize: int):
        self.name = name
        self.types = types
        self.queue: asyncio.Queue[BusEvent] = asyncio.Queue(maxsize=maxsize)
        self.dropped = 0
        self.delivered = 0

    def offer(self, ev: BusEvent) -> None:
        if self.types is not None and ev.type not in self.types:
            return
        try:
            self.queue.put_nowait(ev)
            self.delivered += 1
        except asyncio.QueueFull:
            try:
                self.queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
            self.dropped += 1
            try:
                self.queue.put_nowait(ev)
            except asyncio.QueueFull:
                pass


class EventBus:
    def __init__(self, default_maxsize: int = 1000):
        self._subs: list[Subscription] = []
        self._sync: dict[str, list[Callable[[BusEvent], None]]] = defaultdict(list)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.Lock()
        self.default_maxsize = default_maxsize
        self.published = defaultdict(int)

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self, name: str, types: Iterable[str] | None = None, maxsize: int | None = None) -> Subscription:
        sub = Subscription(name, set(types) if types else None, maxsize or self.default_maxsize)
        with self._lock:
            self._subs.append(sub)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        with self._lock:
            if sub in self._subs:
                self._subs.remove(sub)

    def on(self, type_: str, fn: Callable[[BusEvent], None]) -> None:
        self._sync[type_].append(fn)

    def publish(self, type_: str, payload, source: str = "core") -> BusEvent:
        ev = BusEvent(type=type_, payload=payload, source=source)
        self.published[type_] += 1
        for fn in self._sync.get(type_, ()):
            try:
                fn(ev)
            except Exception:  # a sync listener must never break publishing
                pass
        loop = self._loop
        if loop is None:
            return ev
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        with self._lock:
            subs = list(self._subs)
        if running is loop:
            for s in subs:
                s.offer(ev)
        else:  # called from a worker thread
            for s in subs:
                loop.call_soon_threadsafe(s.offer, ev)
        return ev

    def stats(self) -> dict:
        with self._lock:
            subs = list(self._subs)
        return {
            "subscribers": [{"name": s.name, "queued": s.queue.qsize(), "dropped": s.dropped, "delivered": s.delivered} for s in subs],
            "published": dict(self.published),
        }
