"""Continuous raw capture: every raw frame of a session is appended to a .tlog
(8-byte big-endian µs timestamp + exact wire frame) — a standard format that the
log importer, replay engine and other tools (MAVProxy, Mission Planner) read.
Disk exhaustion stops writing and records the loss explicitly."""
from __future__ import annotations

import shutil
import threading
import time
from pathlib import Path
from typing import Optional

from ..mavlink.decoder import tlog_record


class RawRecorder:
    def __init__(self, capture_dir: Path, session_id: str, min_free_mb: int, errors, on_event=None, enabled: bool = True):
        self.path = capture_dir / f"{session_id}.tlog"
        self.enabled = enabled
        self.min_free = min_free_mb * 1024 * 1024
        self.errors = errors
        self.on_event = on_event
        self.frames = 0
        self.bytes = 0
        self.lost_frames = 0
        self.status = "RECORDING" if enabled else "DISABLED"
        self._fh = open(self.path, "ab", buffering=1 << 16) if enabled else None
        self._last_flush = time.monotonic()
        self._last_disk_check = 0.0
        self._lock = threading.Lock()

    def write(self, t: float, raw: Optional[bytes]) -> None:
        if not raw or self._fh is None:
            if raw and self.status == "STOPPED_DISK_LOW":
                self.lost_frames += 1
            return
        now = time.monotonic()
        if now - self._last_disk_check > 5:
            self._last_disk_check = now
            free = shutil.disk_usage(self.path.parent).free
            if free < self.min_free:
                self._stop("STOPPED_DISK_LOW", f"free disk {free // (1 << 20)} MB below limit; raw capture stopped")
                self.lost_frames += 1
                return
        try:
            with self._lock:
                rec = tlog_record(t, raw)
                self._fh.write(rec)
                self.frames += 1
                self.bytes += len(rec)
                if now - self._last_flush > 1.0:
                    self._fh.flush()
                    self._last_flush = now
        except OSError as exc:
            self._stop("ERROR", f"capture write failed: {exc}")
            self.lost_frames += 1

    def _stop(self, status: str, msg: str) -> None:
        self.status = status
        self.errors.record("RECORDER", status, msg, recoverable=True)
        if self.on_event:
            self.on_event("RECORDING_STOPPED", "HIGH", msg)
        try:
            if self._fh:
                self._fh.flush()
                self._fh.close()
        except OSError:
            pass
        self._fh = None

    def close(self) -> None:
        with self._lock:
            if self._fh:
                self._fh.flush()
                self._fh.close()
                self._fh = None
        if self.status == "RECORDING":
            self.status = "CLOSED"

    def stats(self) -> dict:
        return {"status": self.status, "path": self.path.name, "frames": self.frames, "bytes": self.bytes,
                "lost_frames": self.lost_frames}
