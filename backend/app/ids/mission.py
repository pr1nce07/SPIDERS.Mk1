"""Mission integrity detector (spec §24): full mission-item fingerprinting."""
from __future__ import annotations

import hashlib
from collections import deque
from typing import Optional

from ..models.events import TelemetryEvent
from .base import AnalysisContext, Detector


def _item_key(f: dict) -> tuple:
    return (f.get("seq"), f.get("command"), f.get("frame"), f.get("x"), f.get("y"), round(float(f.get("z") or 0), 2),
            round(float(f.get("param1") or 0), 3), round(float(f.get("param2") or 0), 3),
            round(float(f.get("param3") or 0), 3), round(float(f.get("param4") or 0), 3))


class MissionDetector(Detector):
    detector_id = "MISSION"
    name = "Mission Integrity"
    domain = "MISSION"
    data_sources = ("MISSION_COUNT", "MISSION_ITEM_INT", "MISSION_ITEM", "MISSION_ACK", "MISSION_CURRENT",
                    "MISSION_CLEAR_ALL", "MISSION_SET_CURRENT", "MISSION_ITEM_REACHED")
    methods = ("full mission-item SHA-256 fingerprint", "mission count change", "current-index continuity",
               "armed/airborne context", "change-rate")
    description = "Mission replacement, in-flight edits, rapid changes and index jumps."
    limitations = ("Mission uploads on links invisible to this GCS are only detected via a later download or MISSION_CURRENT behaviour.",)

    def __init__(self, cfg):
        super().__init__(cfg)
        self.index_jump = int(self.cfg.get("index_jump", 3))
        self.transfer: Optional[dict] = None
        self.baseline: Optional[dict] = None
        self.current: Optional[dict] = None
        self.changes: deque = deque()
        self.cur_seq: Optional[int] = None
        self.set_current_t: Optional[float] = None
        self.versions: list[dict] = []

    def process(self, ev: TelemetryEvent, ctx: AnalysisContext):
        self.mark_data(ctx)
        f = ev.fields
        n = ev.msg_name
        out = []
        if n == "MISSION_COUNT" and (f.get("mission_type") in (None, 0)):
            self.transfer = {"count": f.get("count"), "sysid": ev.sysid, "items": {}, "start_idx": ev.idx,
                             "t": ctx.t, "to_vehicle": ev.sysid != ctx.vehicle_sysid}
        elif n in ("MISSION_ITEM_INT", "MISSION_ITEM") and self.transfer and ev.sysid == self.transfer["sysid"]:
            if f.get("mission_type") in (None, 0):
                self.transfer["items"][f.get("seq")] = _item_key(f)
                if len(self.transfer["items"]) == self.transfer["count"]:
                    out += self._complete(ev, ctx)
        elif n == "MISSION_ACK" and self.transfer and self.transfer["count"] == 0:
            out += self._complete(ev, ctx)
        elif n == "MISSION_CLEAR_ALL" and ev.sysid != ctx.vehicle_sysid:
            if ctx.airborne or not ctx.is_trusted_gcs(ev.sysid):
                out.append(self.result(ctx, "SUSPECTED", "Mission cleared in flight" if ctx.airborne else "Mission clear from untrusted source",
                                       ev=ev, confidence=0.6, method="armed/airborne context",
                                       inputs={"sysid": ev.sysid, "airborne": ctx.airborne, "armed": ctx.armed},
                                       why="MISSION_CLEAR_ALL observed" + (" while airborne." if ctx.airborne else ".")))
        elif n == "MISSION_SET_CURRENT":
            self.set_current_t = ctx.mono
        elif n == "MISSION_CURRENT" and ev.sysid == ctx.vehicle_sysid:
            seq = f.get("seq")
            if self.cur_seq is not None and seq is not None and seq != self.cur_seq:
                jump = seq - self.cur_seq
                commanded = self.set_current_t is not None and ctx.mono - self.set_current_t < 5
                if (jump < 0 or jump > self.index_jump) and not commanded and (ctx.mode or "").upper() == "AUTO":
                    out.append(self.result(ctx, "ANOMALOUS", "Mission index discontinuity", ev=ev, severity="MEDIUM",
                                           method="current-index continuity", parameters={"index_jump": self.index_jump},
                                           inputs={"previous_seq": self.cur_seq, "new_seq": seq, "mode": ctx.mode},
                                           why=f"Current mission item jumped {self.cur_seq} → {seq} in AUTO without an observed MISSION_SET_CURRENT."))
            self.cur_seq = seq
        return out

    def _complete(self, ev, ctx) -> list:
        tr = self.transfer
        self.transfer = None
        items = [tr["items"][k] for k in sorted(k for k in tr["items"] if k is not None)]
        fp = hashlib.sha256(repr(items).encode()).hexdigest()
        version = {"fingerprint": fp, "count": len(items), "sysid": tr["sysid"], "t": ctx.t,
                   "to_vehicle": tr["to_vehicle"], "items": items[:200]}
        self.versions.append({k: v for k, v in version.items() if k != "items"})
        if self.current is None:
            self.baseline = self.current = version
            return [self.result(ctx, "OBSERVED", f"Mission recorded ({len(items)} items)", kind="observation", ev=ev,
                                inputs={"fingerprint": fp[:16], "count": len(items), "sysid": tr["sysid"]},
                                method="full mission-item SHA-256 fingerprint", why="First complete mission transfer observed; stored as baseline.")]
        if fp == self.current["fingerprint"]:
            return []
        prev = self.current
        self.current = version
        changed = [i for i, (a, b) in enumerate(zip(prev.get("items", []), items)) if a != b]
        self.changes.append(ctx.mono)
        while self.changes and ctx.mono - self.changes[0] > 60:
            self.changes.popleft()
        evid = []
        if ctx.airborne or ctx.armed:
            evid.append({"label": "mission modified while armed/airborne", "value": 0.35})
        if not ctx.is_trusted_gcs(tr["sysid"]) and tr["sysid"] != ctx.vehicle_sysid:
            evid.append({"label": "uploaded by untrusted source", "value": 0.35})
        if len(self.changes) >= 2:
            evid.append({"label": "rapid mission changes", "value": 0.15})
        if len(items) != prev["count"]:
            evid.append({"label": "mission count changed", "value": 0.10})
        inputs = {"previous_fingerprint": prev["fingerprint"][:16], "new_fingerprint": fp[:16], "previous_count": prev["count"],
                  "new_count": len(items), "changed_items": changed[:20], "writer_sysid": tr["sysid"],
                  "armed": ctx.armed, "airborne": ctx.airborne}
        if not evid:
            return [self.result(ctx, "OBSERVED", "Mission updated", kind="observation", ev=ev, inputs=inputs,
                                method="full mission-item SHA-256 fingerprint", why="Mission replaced on the ground by a trusted GCS.")]
        conf = min(0.95, sum(e["value"] for e in evid))
        return [self.result(ctx, "SUSPECTED" if len(evid) >= 2 else "ANOMALOUS",
                            "Mission modification during flight" if (ctx.airborne or ctx.armed) else "Unexpected mission replacement",
                            ev=ev, refs=[tr["start_idx"], ev.idx], confidence=conf,
                            method="full mission-item SHA-256 fingerprint + context", inputs=inputs, contributors=evid,
                            why=f"Mission fingerprint changed {prev['fingerprint'][:8]}→{fp[:8]}; items changed: {changed[:10]}.",
                            evidence=[f"{e['label']} (+{round(e['value'] * 100)})" for e in evid])]

    def tick(self, ctx):
        self.metrics = {"baseline_fingerprint": (self.baseline or {}).get("fingerprint", "")[:16] or None,
                        "current_fingerprint": (self.current or {}).get("fingerprint", "")[:16] or None,
                        "versions": len(self.versions), "current_seq": self.cur_seq}
        return []
