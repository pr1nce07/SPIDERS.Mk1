"""Streaming statistical primitives (spec §45). Every primitive can describe
itself (method + parameters) so results retain their provenance."""
from __future__ import annotations

import math
from collections import Counter, deque
from typing import Optional


class EWMA:
    def __init__(self, alpha: float = 0.2):
        self.alpha = alpha
        self.mean: Optional[float] = None
        self.var = 0.0
        self.n = 0

    def update(self, x: float) -> float:
        self.n += 1
        if self.mean is None:
            self.mean = x
            return x
        d = x - self.mean
        self.mean += self.alpha * d
        self.var = (1 - self.alpha) * (self.var + self.alpha * d * d)
        return self.mean

    @property
    def std(self) -> float:
        return math.sqrt(max(self.var, 0.0))

    def z(self, x: float) -> Optional[float]:
        if self.mean is None or self.n < 5:
            return None
        s = self.std
        return (x - self.mean) / s if s > 1e-9 else 0.0

    def describe(self) -> dict:
        return {"method": "EWMA", "alpha": self.alpha}


class CUSUM:
    """One-sided (upper) CUSUM on standardized input."""

    def __init__(self, k: float = 0.5, h: float = 5.0):
        self.k, self.h = k, h
        self.s = 0.0

    def update(self, z: float) -> float:
        self.s = max(0.0, self.s + z - self.k)
        return self.s

    @property
    def alarm(self) -> bool:
        return self.s > self.h

    def reset(self) -> None:
        self.s = 0.0

    def describe(self) -> dict:
        return {"method": "CUSUM", "k": self.k, "h": self.h}


class RollingWindow:
    def __init__(self, n: int = 30):
        self.n = n
        self.buf: deque[float] = deque(maxlen=n)

    def push(self, x: float) -> None:
        self.buf.append(x)

    def __len__(self) -> int:
        return len(self.buf)

    def mean(self) -> Optional[float]:
        return sum(self.buf) / len(self.buf) if self.buf else None

    def std(self) -> Optional[float]:
        if len(self.buf) < 2:
            return None
        m = self.mean()
        return math.sqrt(sum((x - m) ** 2 for x in self.buf) / (len(self.buf) - 1))

    def median(self) -> Optional[float]:
        return median(list(self.buf)) if self.buf else None

    def mad(self) -> Optional[float]:
        if not self.buf:
            return None
        m = self.median()
        return median([abs(x - m) for x in self.buf])

    def zscore(self, x: float) -> Optional[float]:
        s, m = self.std(), self.mean()
        if s is None or m is None:
            return None
        return (x - m) / s if s > 1e-9 else 0.0

    def robust_z(self, x: float) -> Optional[float]:
        if len(self.buf) < 5:
            return None
        m, mad = self.median(), self.mad()
        scale = 1.4826 * mad
        if scale < 1e-9:
            return 0.0 if abs(x - m) < 1e-9 else math.copysign(99.0, x - m)
        return (x - m) / scale


def median(xs: list[float]) -> float:
    s = sorted(xs)
    n = len(s)
    if n == 0:
        return 0.0
    mid = n // 2
    return s[mid] if n % 2 else 0.5 * (s[mid - 1] + s[mid])


class RateMeter:
    """Event rate over a sliding time window using monotonic seconds."""

    def __init__(self, window_s: float = 5.0):
        self.window = window_s
        self.times: deque[float] = deque()

    def add(self, t: float) -> None:
        self.times.append(t)
        self._trim(t)

    def _trim(self, now: float) -> None:
        while self.times and now - self.times[0] > self.window:
            self.times.popleft()

    def rate(self, now: float) -> float:
        self._trim(now)
        return len(self.times) / self.window

    def count(self, now: float) -> int:
        self._trim(now)
        return len(self.times)


class Persistence:
    """True once a condition has held continuously for `duration` seconds."""

    def __init__(self, duration: float):
        self.duration = duration
        self.since: Optional[float] = None

    def update(self, cond: bool, t: float) -> tuple[bool, float]:
        if cond:
            if self.since is None:
                self.since = t
            held = t - self.since
            return held >= self.duration, held
        self.since = None
        return False, 0.0


def shannon_entropy(counts: Counter) -> float:
    total = sum(counts.values())
    if not total:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c)


def haversine_m(lat1, lon1, lat2, lon2) -> float:
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


def clamp01(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1 else x
