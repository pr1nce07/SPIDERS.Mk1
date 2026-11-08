"""Incident correlation engine (spec §30, §31, §73, §74).

OBSERVATION → DETECTOR → EVIDENCE → CONFIDENCE → PERSISTENCE → CROSS-DETECTOR
CORRELATION → INCIDENT. Every underlying result is kept on the incident; the
confidence is a list of labelled contributors, never an opaque score.
"""
from __future__ import annotations

import itertools
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Callable, Optional

from ..config import SEVERITIES, severity_rank
from ..models.events import DetectorResult, iso_from_epoch, state_rank

DOMAIN_TITLES = {
    "GPS_INTEGRITY": "GPS integrity incident", "MAVLINK_SECURITY": "Correlated MAVLink security incident",
    "LINK": "Link degradation incident", "MISSION": "Mission integrity incident", "SENSOR": "Sensor consistency incident",
    "PUSHPAK": "PUSHPAK FC incident", "RULE": "Rule-driven incident", "ML": "ML baseline incident",
}
DOMAIN_LIMITATIONS = {
    "GPS_INTEGRITY": ["No independent RF measurement is available.", "This evidence alone does not prove intentional spoofing."],
    "LINK": ["Range loss, antenna faults and interference produce similar link symptoms."],
    "MAVLINK_SECURITY": ["Traffic on links not visible to this GCS is not observed."],
}
SOURCE_WEIGHT = {"GROUND": 0.35, "FC": 0.25, "LUA": 0.20, "CORRELATED": 0.30}
STATE_ONLY_WEIGHT = {"ANOMALOUS": 0.20, "SUSPECTED": 0.35, "CONFIRMED": 0.5}
NEVER_OPENS = {"ML_BASELINE", "SOURCE_IDENTITY"}


class IncidentIdAllocator:
    def __init__(self, start: int = 0):
        self._c = itertools.count(start + 1)
        self._lock = threading.Lock()

    def next(self) -> str:
        with self._lock:
            n = next(self._c)
        return f"INC-{datetime.now(timezone.utc).year}-{n:06d}"


class Correlator:
    def __init__(self, config, allocator: IncidentIdAllocator, session_id: str,
                 on_created: Callable[[dict], None] | None = None, on_updated: Callable[[dict], None] | None = None):
        self.window = float(config.get("ids.correlation_window_seconds", 10))
        self.min_det = int(config.get("ids.min_correlated_detectors", 2))
        self.susp_thr = float(config.get("ids.suspected_threshold", 0.45))
        self.conf_thr = float(config.get("ids.confirmed_threshold", 0.75))
        self.alloc = allocator
        self.session_id = session_id
        self.on_created = on_created
        self.on_updated = on_updated
        self.recent: deque = deque(maxlen=2000)         # (mono, result) alerts + context
        self.incidents: dict[str, dict] = {}
        self.open_by_key: dict[str, str] = {}

    @staticmethod
    def actor(r: DetectorResult, ctx) -> Optional[int]:
        s = r.inputs.get("sysid") if isinstance(r.inputs, dict) else None
        s = s if isinstance(s, int) else r.sysid
        if s is None or s == ctx.vehicle_sysid or ctx.is_trusted_gcs(s):
            return None
        return s

    def ingest(self, r: DetectorResult, ctx) -> Optional[dict]:
        rank = state_rank(r.state)
        self.recent.append((ctx.mono, r, self.actor(r, ctx)))
        if r.kind in ("recovery", "health") or (rank < 2 and not r.actions.get("incident")):
            # context only; attach to an open incident in the same domain/actor if any
            inc = self._find_open(r, ctx)
            if inc and r.kind != "health":
                self._attach(inc, r, ctx, context=True)
                return inc
            return None
        inc = self._find_open(r, ctx)
        if inc is not None:
            self._attach(inc, r, ctx)
            return inc
        # creation criteria
        members = self._window_members(r, ctx)
        alerts = [m for m in members if state_rank(m.state) >= 2]
        dets = {m.detector for m in alerts}
        srcs = {m.source for m in alerts}
        create_reason = None
        if r.actions.get("incident"):
            create_reason = f"rule {r.rule_id} v{r.rule_version} output INCIDENT"
        elif r.source in ("FC", "LUA") and rank >= 3:
            create_reason = f"{r.source} reported {r.state}"
        elif len(dets - NEVER_OPENS) >= 1 and len(dets) >= self.min_det and self._confidence(alerts)[0] >= self.susp_thr:
            create_reason = f"{len(dets)} detectors correlated within {self.window:.0f} s"
        elif rank >= 3 and severity_rank(r.severity) >= severity_rank("HIGH") and r.detector not in NEVER_OPENS:
            create_reason = f"single detector {r.detector} SUSPECTED at {r.severity}"
        if not create_reason:
            return None
        return self._create(r, ctx, members, create_reason)

    # ------------------------------------------------------------ internals
    def _window_members(self, r, ctx) -> list[DetectorResult]:
        a = self.actor(r, ctx)
        out = []
        for mono, m, ma in self.recent:
            if ctx.mono - mono > self.window:
                continue
            if m.domain == r.domain or (a is not None and ma == a):
                out.append(m)
        return out

    def _find_open(self, r, ctx) -> Optional[dict]:
        a = self.actor(r, ctx)
        best = None
        for inc in self.incidents.values():
            if inc["status"] in ("RESOLVED", "FALSE_POSITIVE"):
                continue
            if ctx.mono - inc["_last_mono"] > max(self.window, 30):
                continue
            if inc["domain"] == r.domain or (a is not None and a in inc["actors"]):
                if best is None or inc["_last_mono"] > best["_last_mono"]:
                    best = inc
        return best

    def _create(self, r, ctx, members, reason) -> dict:
        iid = self.alloc.next()
        inc = {
            "incident_id": iid, "session_id": self.session_id, "first_seen": r.t, "last_seen": r.t,
            "first_seen_iso": iso_from_epoch(r.t), "last_seen_iso": iso_from_epoch(r.t),
            "status": "OPEN", "state": "SUSPECTED", "severity": r.severity, "confidence": 0.0,
            "domain": r.domain, "title": DOMAIN_TITLES.get(r.domain, f"{r.domain} incident") if not r.rule_id else r.title,
            "detectors": [], "observations": [], "evidence": [], "sources": [], "rule_versions": [], "actors": [],
            "contributors": [], "limitations": list(DOMAIN_LIMITATIONS.get(r.domain, [])), "creation_reason": reason,
            "case_id": None, "_last_mono": ctx.mono, "_members": set(),
        }
        self.incidents[iid] = inc
        for m in members:
            if m is not r:
                self._attach(inc, m, ctx, context=state_rank(m.state) < 2, notify=False)
        self._attach(inc, r, ctx, notify=False)
        if not ctx.fc_states and r.domain != "RULE":
            inc["limitations"].append("No PUSHPAK FC/Lua telemetry received this session (see firmware discrepancy DISC-001).")
        if self.on_created:
            self.on_created(inc)
        return inc

    def _attach(self, inc, r: DetectorResult, ctx, context: bool = False, notify: bool = True) -> None:
        if r.result_id in inc["_members"]:
            return
        inc["_members"].add(r.result_id)
        inc["observations"].append({"result_id": r.result_id, "t": r.t, "ts": iso_from_epoch(r.t), "detector": r.detector,
                                    "title": r.title, "state": r.state, "severity": r.severity, "confidence": r.confidence,
                                    "source": r.source, "context": context, "rule_id": r.rule_id, "rule_version": r.rule_version,
                                    "packet_refs": r.packet_refs[:20]})
        inc["evidence"] = sorted(set(inc["evidence"]) | set(r.packet_refs[:50]))[-500:]
        a = self.actor(r, ctx)
        if a is not None and a not in inc["actors"]:
            inc["actors"].append(a)
        if not context:
            if r.detector not in inc["detectors"]:
                inc["detectors"].append(r.detector)
            if r.source not in inc["sources"]:
                inc["sources"].append(r.source)
            if r.rule_id and {"rule_id": r.rule_id, "version": r.rule_version} not in inc["rule_versions"]:
                inc["rule_versions"].append({"rule_id": r.rule_id, "version": r.rule_version})
            if severity_rank(r.severity) > severity_rank(inc["severity"]):
                inc["severity"] = r.severity
        inc["last_seen"] = max(inc["last_seen"], r.t)
        inc["last_seen_iso"] = iso_from_epoch(inc["last_seen"])
        inc["_last_mono"] = ctx.mono
        self._rescore(inc)
        if notify and self.on_updated:
            self.on_updated(inc)

    def _confidence(self, results: list[DetectorResult]) -> tuple[float, list[dict]]:
        best: dict[tuple, DetectorResult] = {}
        for m in results:
            if state_rank(m.state) < 2:
                continue
            k = (m.detector, m.source)
            cur = best.get(k)
            if cur is None or (m.confidence or 0) > (cur.confidence or 0):
                best[k] = m
        contributors = []
        for (det, src), m in best.items():
            w = SOURCE_WEIGHT.get(src, 0.3)
            if m.rule_id:
                w = SOURCE_WEIGHT["CORRELATED"]
            if m.confidence is not None:
                v = w * m.confidence
                basis = f"{src} {det} confidence {m.confidence:.2f} × weight {w}"
            else:
                v = w * STATE_ONLY_WEIGHT.get(m.state, 0.2) * 2
                basis = f"{src} {det} state {m.state} (no confidence reported; state-based weight)"
            if det == "ML_BASELINE":
                v *= 0.3
            contributors.append({"label": f"{m.title}", "detector": det, "source": src, "value": round(v, 3), "basis": basis})
        contributors.sort(key=lambda c: -c["value"])
        total = min(0.99, sum(c["value"] for c in contributors))
        return total, contributors

    def _rescore(self, inc) -> None:
        members = [m for _, m, _ in self.recent if m.result_id in inc["_members"]]
        conf, contributors = self._confidence(members)
        # keep contributors from members that already rotated out of `recent`
        old = {c["detector"] + c["source"]: c for c in inc["contributors"]}
        for c in contributors:
            key = c["detector"] + c["source"]
            if key not in old or c["value"] >= old[key]["value"]:
                old[key] = c
        inc["contributors"] = sorted(old.values(), key=lambda c: -c["value"])
        inc["confidence"] = round(min(0.99, sum(c["value"] for c in inc["contributors"])), 3)
        indep = {s for s in inc["sources"] if s in ("GROUND", "FC", "LUA")}
        if any(s.startswith("RULE:") for s in inc["detectors"]):
            indep.add("GROUND")
        n_det = len(set(inc["detectors"]) - {"ML_BASELINE"})
        prev = inc["state"]
        if inc["confidence"] >= self.conf_thr and (len(indep) >= 2 or n_det >= 3):
            inc["state"] = "CONFIRMED"
        elif n_det >= 2 or len(indep) >= 2:
            inc["state"] = "CORRELATED"
        else:
            inc["state"] = "SUSPECTED"
        if state_rank(prev) > state_rank(inc["state"]):
            inc["state"] = prev  # analytic state never silently downgrades; analysts use workflow status
        inc["explanation"] = self.explain(inc)

    def explain(self, inc) -> dict:
        obs = [o for o in inc["observations"] if not o["context"]]
        return {
            "what": inc["title"],
            "why": f"{inc['creation_reason']}; {len(obs)} alerts from {len(inc['detectors'])} detector(s) "
                   f"({', '.join(inc['detectors'])}) and sources {', '.join(inc['sources'])}.",
            "when": f"{inc['first_seen_iso']} → {inc['last_seen_iso']}",
            "source": ", ".join(inc["sources"]),
            "evidence": [f"{o['ts']} {o['detector']} {o['state']}: {o['title']}" for o in inc["observations"][-20:]],
            "rule": ", ".join(f"{r['rule_id']} v{r['version']}" for r in inc["rule_versions"]) or "ground detectors (see each result)",
            "confidence": f"{round(inc['confidence'] * 100)}%",
            "contributors": inc["contributors"],
            "limitations": inc["limitations"],
            "state_policy": f"CONFIRMED requires confidence ≥ {self.conf_thr} and ≥2 independent sources (GROUND/FC/LUA) or ≥3 detectors.",
        }

    @staticmethod
    def public(inc: dict) -> dict:
        return {k: v for k, v in inc.items() if not k.startswith("_")}
