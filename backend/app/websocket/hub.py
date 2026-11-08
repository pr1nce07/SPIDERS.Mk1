"""WebSocket fan-out. High-rate state streams (telemetry) are separated from
low-rate alert/event streams; each client has a bounded queue and slow clients
lose intermediate visual states only (never evidence — that lives in the DB and
case store). On (re)connect a client receives a full resync snapshot."""
from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any

import orjson

CHANNELS = ("telemetry", "ids", "incidents", "events", "health", "builder")


class Client:
    def __init__(self, ws, channel: str, maxsize: int):
        self.ws = ws
        self.channel = channel
        self.q: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self.dropped = 0

    def offer(self, payload: bytes) -> None:
        try:
            self.q.put_nowait(payload)
        except asyncio.QueueFull:
            try:
                self.q.get_nowait()
            except asyncio.QueueEmpty:
                pass
            self.dropped += 1
            try:
                self.q.put_nowait(payload)
            except asyncio.QueueFull:
                pass


class Hub:
    def __init__(self, max_queue: int = 500):
        self.clients: dict[str, set[Client]] = defaultdict(set)
        self.max_queue = max_queue
        self.sent: dict[str, int] = defaultdict(int)
        self.dropped_total = 0

    def register(self, ws, channel: str) -> Client:
        c = Client(ws, channel, self.max_queue)
        self.clients[channel].add(c)
        return c

    def unregister(self, c: Client) -> None:
        self.clients[c.channel].discard(c)
        self.dropped_total += c.dropped

    def has(self, channel: str) -> bool:
        return bool(self.clients.get(channel))

    def send(self, channel: str, type_: str, data: Any) -> None:
        clients = self.clients.get(channel)
        if not clients:
            return
        payload = orjson.dumps({"type": type_, "data": data}, default=str, option=orjson.OPT_NON_STR_KEYS | orjson.OPT_SERIALIZE_NUMPY)
        for c in list(clients):
            c.offer(payload)
        self.sent[channel] += 1

    async def pump(self, c: Client) -> None:
        while True:
            payload = await c.q.get()
            await c.ws.send_text(payload.decode())

    def stats(self) -> dict:
        return {"clients": {ch: len(cs) for ch, cs in self.clients.items()}, "sent": dict(self.sent),
                "dropped": self.dropped_total + sum(c.dropped for cs in self.clients.values() for c in cs),
                "max_queue": self.max_queue}
