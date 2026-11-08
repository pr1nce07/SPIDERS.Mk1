"""LiveMavlinkSource: Serial/USB, UDP and TCP receive transports.

Read-only by construction: the transports expose no write path, so the GCS
cannot emit MAVLink (no heartbeats, no requests, no commands). Reconnection uses
exponential backoff and never blocks the event loop.
"""
from __future__ import annotations

import asyncio
import re
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

STATES = ["DISCONNECTED", "CONNECTING", "CONNECTED", "DEGRADED", "RECONNECTING", "ERROR"]


@dataclass
class LinkSpec:
    kind: str       # udp | tcp | serial
    host: str = ""
    port: int = 0
    device: str = ""
    baud: int = 115200
    text: str = ""


def parse_spec(spec: str, baud: int = 115200) -> LinkSpec:
    s = spec.strip()
    m = re.fullmatch(r"(udp|udpin):([\w.\-]+):(\d{1,5})", s)
    if m:
        return LinkSpec("udp", host=m.group(2), port=int(m.group(3)), text=s)
    m = re.fullmatch(r"tcp:([\w.\-]+):(\d{1,5})", s)
    if m:
        return LinkSpec("tcp", host=m.group(1), port=int(m.group(2)), text=s)
    m = re.fullmatch(r"(?:serial:)?((?:COM\d+)|(?:/dev/[\w./\-]+))(?:[:,@](\d{3,7}))?", s)
    if m:
        return LinkSpec("serial", device=m.group(1), baud=int(m.group(2) or baud), text=s)
    if s.startswith("udpout:"):
        raise ValueError("udpout requires transmitting; the GCS is read-only — listen with udp:<host>:<port>")
    raise ValueError(f"unrecognised connection string '{spec}' (examples: udp:127.0.0.1:14550, tcp:127.0.0.1:5760, /dev/ttyUSB0, COM3)")


class LiveMavlinkSource:
    def __init__(self, spec: LinkSpec, push: Callable[[float, bytes, str], None], on_state: Callable[[str, str], None],
                 reconnect: bool = True, rmin: float = 1.0, rmax: float = 15.0):
        self.spec = spec
        self.push = push
        self.on_state = on_state
        self.reconnect = reconnect
        self.rmin, self.rmax = rmin, rmax
        self.state = "DISCONNECTED"
        self.detail = ""
        self.bytes = 0
        self.last_rx: Optional[float] = None
        self._stop = asyncio.Event()
        self._task: Optional[asyncio.Task] = None
        self._transport = None
        self._serial_thread: Optional[threading.Thread] = None
        self._serial_stop = threading.Event()
        self.link_name = spec.text

    def _set(self, st, detail=""):
        self.state, self.detail = st, detail
        self.on_state(st, detail)

    def start(self):
        self._task = asyncio.get_running_loop().create_task(self._run())

    async def stop(self):
        self._stop.set()
        self._serial_stop.set()
        if self._transport is not None:
            try:
                self._transport.close()
            except Exception:
                pass
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        self._set("DISCONNECTED", "stopped by operator")

    def _rx(self, data: bytes):
        self.bytes += len(data)
        self.last_rx = time.monotonic()
        self.push(time.time(), data, self.link_name)

    async def _run(self):
        delay = self.rmin
        first = True
        while not self._stop.is_set():
            self._set("CONNECTING" if first else "RECONNECTING", self.spec.text)
            first = False
            try:
                if self.spec.kind == "udp":
                    await self._run_udp()
                elif self.spec.kind == "tcp":
                    await self._run_tcp()
                else:
                    await self._run_serial()
                delay = self.rmin
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._set("ERROR", f"{type(exc).__name__}: {exc}"[:200])
            if not self.reconnect or self._stop.is_set():
                break
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass
            delay = min(self.rmax, delay * 2)

    async def _watch(self, alive: Callable[[], bool]):
        """Mark DEGRADED when no bytes arrive for 3 s; return when the link dies."""
        while not self._stop.is_set() and alive():
            await asyncio.sleep(0.5)
            if self.last_rx is None:
                continue
            gap = time.monotonic() - self.last_rx
            if gap > 3 and self.state == "CONNECTED":
                self._set("DEGRADED", f"no data for {gap:.0f} s")
            elif gap <= 3 and self.state == "DEGRADED":
                self._set("CONNECTED", self.spec.text)

    async def _run_udp(self):
        loop = asyncio.get_running_loop()
        src = self

        class P(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                if src.state in ("CONNECTING", "RECONNECTING", "ERROR"):
                    src._set("CONNECTED", f"{src.spec.text} ← {addr[0]}:{addr[1]}")
                src._rx(data)

            def error_received(self, exc):
                src._set("DEGRADED", str(exc))

        transport, _ = await loop.create_datagram_endpoint(P, local_addr=(self.spec.host, self.spec.port))
        self._transport = transport
        self._set("CONNECTING", f"listening on {self.spec.host}:{self.spec.port} (waiting for data)")
        try:
            await self._watch(lambda: not transport.is_closing())
        finally:
            transport.close()

    async def _run_tcp(self):
        reader, writer = await asyncio.wait_for(asyncio.open_connection(self.spec.host, self.spec.port), timeout=5)
        self._transport = writer
        self._set("CONNECTED", self.spec.text)
        watch = asyncio.create_task(self._watch(lambda: not writer.is_closing()))
        try:
            while not self._stop.is_set():
                data = await reader.read(65536)
                if not data:
                    raise ConnectionError("remote closed connection")
                self._rx(data)
        finally:
            watch.cancel()
            writer.close()

    async def _run_serial(self):
        try:
            import serial  # pyserial
        except ImportError as exc:
            raise RuntimeError("pyserial not installed") from exc
        loop = asyncio.get_running_loop()
        port = serial.Serial(self.spec.device, self.spec.baud, timeout=0.2)
        self._set("CONNECTED", f"{self.spec.device} @ {self.spec.baud}")
        done = asyncio.Event()
        self._serial_stop.clear()

        def reader():
            try:
                while not self._serial_stop.is_set():
                    data = port.read(4096)
                    if data:
                        loop.call_soon_threadsafe(self._rx, data)
            except Exception as exc:
                loop.call_soon_threadsafe(self._set, "ERROR", f"serial: {exc}")
            finally:
                try:
                    port.close()
                except Exception:
                    pass
                loop.call_soon_threadsafe(done.set)

        self._serial_thread = threading.Thread(target=reader, name="serial-rx", daemon=True)
        self._serial_thread.start()
        watch = asyncio.create_task(self._watch(lambda: not done.is_set()))
        try:
            await done.wait()
        finally:
            watch.cancel()
            self._serial_stop.set()
