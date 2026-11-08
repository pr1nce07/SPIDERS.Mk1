"""PUSHPAK FC + Lua integration detector (spec §28/§29).

Consumes vehicle STATUSTEXT only. States/confidence are *reported by the FC or
Lua*, never manufactured here; when no PUSHPAK telemetry has been received the
FC/LUA columns stay N/A.
"""
from __future__ import annotations

from typing import Optional

from ..mavlink.pushpak import LUA_CONFIRM_THRESHOLD, LUA_SCRIPT_FOR_DETECTOR, PIDS_DETECTORS, StatusTextAssembler, parse_statustext
from ..models.events import TelemetryEvent
from .base import AnalysisContext, Detector

PUSHPAK_DOMAIN = {"GPS": "GPS_INTEGRITY", "MAVLINK": "MAVLINK_SECURITY", "COMMAND": "MAVLINK_SECURITY",
                  "RC_LINK": "LINK", "IMU": "SENSOR", "MISSION": "MISSION", "PARAMETER": "MAVLINK_SECURITY",
                  "OFFBOARD": "MAVLINK_SECURITY"}


class PushpakFCDetector(Detector):
    detector_id = "PUSHPAK_FC"
    name = "PUSHPAK FC / Lua"
    domain = "PUSHPAK"
    data_sources = ("STATUSTEXT",)
    methods = ("PIDS STATUSTEXT adapter", "Lua confirmation adapter", "Lua runtime-error health")
    description = "Normalises FC (PIDS) and Lua confirmation STATUSTEXT into detector states; tracks Lua script health."
    limitations = ("On the supplied firmware build the Lua `ids` binding lacks the accessor methods the scripts call "
                   "(see capabilities DISC-001); FC/Lua states will be N/A unless the firmware is corrected.",
                   "PIDS state integer mapping (0/1/2 → CLEAR/SUSPECTED/CONFIRMED) is from documentation, not verified in firmware.")

    def __init__(self, cfg):
        super().__init__(cfg)
        self.fc: dict[str, dict] = {}
        self.lua: dict[str, dict] = {}
        self.lua_health: dict[str, dict] = {}
        self.records: list[dict] = []
        self.unparsed = 0
        self.assembler = StatusTextAssembler()
        self.chunk_idx: dict = {}

    def process(self, ev: TelemetryEvent, ctx: AnalysisContext):
        if ev.sysid != ctx.vehicle_sysid:
            return []
        key = (ev.sysid, ev.compid, ev.fields.get("id") or 0)
        self.chunk_idx.setdefault(key, []).append(ev.idx)
        text, _chunks = self.assembler.push(ev.sysid, ev.compid, ev.fields, ctx.mono)
        if text is None:
            return []  # waiting for remaining chunks
        refs = self.chunk_idx.pop(key, [ev.idx])
        rec = parse_statustext(text)
        if rec is None:
            return []
        self.mark_data(ctx)
        rec.update({"t": ctx.t, "idx": ev.idx, "sysid": ev.sysid, "compid": ev.compid,
                    "severity_raw": ev.fields.get("severity"), "chunk_packets": refs})
        if rec["kind"] == "LUA_RUNTIME" and (ev.fields.get("severity") is not None and ev.fields["severity"] <= 3):
            rec["is_error"] = True
        self.records.append(rec)
        del self.records[:-500]
        kind = rec["kind"]
        if kind in ("BRIDGE", "FC_EVENT"):
            self.bridge = rec
            self.lua_health["ids_gcs_bridge.lua"] = {"status": "RUNNING", "last": ctx.t, "message": rec["original"]}
            return []
        if kind == "PIDS" and rec.get("origin") == "LUA":
            # per-script Lua result (fixed scripts publish PIDS with origin LUA)
            det = rec["detector"]
            script = LUA_SCRIPT_FOR_DETECTOR.get(det)
            if script:
                self.lua_health[script] = {"status": "RUNNING", "last": ctx.t, "message": None}
            prev = self.lua.get(det)
            lua_rec = dict(rec, **{"class": f"PIDS {rec['state']}", "script": script})
            if rec["state"] == "CLEAR":
                if prev is not None and prev.get("state") not in (None, "CLEAR"):
                    self.lua[det] = lua_rec
                    ctx.lua_states[det] = lua_rec
                return []
            if prev is not None and prev.get("class", "").startswith("PUSHPAK") is False and prev.get("state") == rec["state"]:
                self.lua[det] = dict(prev, confidence=rec["confidence"], t=ctx.t)
                return []
            self.lua[det] = lua_rec
            ctx.lua_states[det] = lua_rec
            return [self.result(ctx, "SUSPECTED" if rec["state"] == "SUSPECTED" else rec["state"] if rec["state"] == "CONFIRMED" else "ANOMALOUS",
                                f"Lua {det} {rec['state']}", ev=ev, refs=refs, source="LUA", domain=PUSHPAK_DOMAIN.get(det, "PUSHPAK"),
                                confidence=rec["confidence"], inputs=self._inputs(rec), method=f"Lua confirmation ({script})",
                                why=f"{script} reported {det} {rec['state']} (confidence {rec['confidence']:.3f}, evidence {rec['evidence'].get('bits')}).",
                                evidence=[f"original STATUSTEXT: {rec['original']}"])]
        if kind == "PIDS":
            det = rec["detector"]
            prev = self.fc.get(det)
            self.fc[det] = rec
            ctx.fc_states[det] = rec
            st = rec["state"]
            if prev is not None and prev["state"] == st and abs(prev["confidence"] - rec["confidence"]) < 0.05:
                return []
            if st == "CLEAR":
                if prev and prev["state"] != "CLEAR":
                    return [self.result(ctx, "OBSERVED", f"FC {det} cleared", kind="recovery", ev=ev, source="FC",
                                        domain=PUSHPAK_DOMAIN.get(det, "PUSHPAK"), confidence=rec["confidence"],
                                        inputs=self._inputs(rec), method="PIDS STATUSTEXT adapter", why=f"FC reports {det} CLEAR.")]
                return []
            state = st if st in ("SUSPECTED", "CONFIRMED") else "ANOMALOUS"
            return [self.result(ctx, state, f"FC IDS {det} {st}", ev=ev, refs=refs, source="FC", domain=PUSHPAK_DOMAIN.get(det, "PUSHPAK"),
                                confidence=rec["confidence"], inputs=self._inputs(rec), method="PIDS STATUSTEXT adapter",
                                why=f"Flight-controller AP_IDS reported {det} state {st} (raw {rec['state_raw']}) with confidence "
                                    f"{rec['confidence']:.3f}; evidence bits {rec['evidence'].get('bits')}.",
                                evidence=[f"original STATUSTEXT: {rec['original']}"] +
                                         [f"evidence bit {b}" for b in rec["evidence"].get("bits", [])],
                                contributors=[{"label": "FC native detector", "value": rec["confidence"]}],
                                limitations=["PIDS state mapping unverified against firmware enum"] if not rec["state_map_verified"] else [])]
        if kind == "LUA_CONFIRMATION":
            det = rec["detector"]
            self.lua[det] = rec
            ctx.lua_states[det] = rec
            if rec.get("script"):
                self.lua_health[rec["script"]] = {"status": "RUNNING", "last": ctx.t, "message": None}
            confirmed = rec["confidence"] >= LUA_CONFIRM_THRESHOLD
            return [self.result(ctx, "CONFIRMED" if confirmed else "SUSPECTED", f"Lua confirmation: {rec['class']}", ev=ev, refs=refs,
                                source="LUA", domain=PUSHPAK_DOMAIN.get(det, "PUSHPAK"), confidence=rec["confidence"],
                                inputs=self._inputs(rec), method=f"Lua second-stage fusion ({rec.get('script') or 'unknown script'})",
                                threshold=LUA_CONFIRM_THRESHOLD,
                                why=f"SD-card/ROMFS Lua script reported {rec['class']} with combined confidence {rec['confidence']:.2f} "
                                    f"(scripts confirm at ≥ {LUA_CONFIRM_THRESHOLD}).",
                                evidence=[f"original STATUSTEXT: {rec['original']}"] +
                                         [f"{k} = {v}" for k, v in (rec.get("metrics") or {}).items()] +
                                         [f"evidence bit {b}" for b in rec["evidence"].get("bits", [])],
                                contributors=[{"label": "Lua confirmation", "value": rec["confidence"]}])]
        if kind == "LUA_RUNTIME":
            script = rec.get("script") or "unknown"
            if rec["is_error"]:
                self.lua_health[script] = {"status": "ERROR", "last": ctx.t, "message": rec["message"],
                                           "missing_method": rec.get("missing_method")}
                return [self.result(ctx, "OBSERVED", f"Lua script error: {script}", kind="health", severity="MEDIUM", ev=ev, refs=refs,
                                    source="LUA", domain="PUSHPAK", method="Lua runtime-error health",
                                    inputs={"script": script, "message": rec["message"], "missing_method": rec.get("missing_method")},
                                    why="ArduPilot scripting reported a runtime error; that script's confirmations are unavailable.")]
            self.lua_health[script] = {"status": "INFO", "last": ctx.t, "message": rec["message"]}
            return []
        self.unparsed += 1
        return []

    @staticmethod
    def _inputs(rec: dict) -> dict:
        d = {k: rec.get(k) for k in ("detector", "state", "state_raw", "confidence", "class", "metric", "instance", "script") if rec.get(k) is not None}
        d["evidence"] = rec.get("evidence")
        d["original_statustext"] = rec.get("original")
        if rec.get("metrics"):
            d.update(rec["metrics"])
        return d

    def tick(self, ctx):
        self.metrics = {"fc_detectors_reporting": sorted(self.fc), "lua_detectors_reporting": sorted(self.lua),
                        "lua_scripts": self.lua_health, "records": len(self.records), "unparsed_lua": self.unparsed}
        return []

    def table(self) -> dict:
        return {"fc": self.fc, "lua": self.lua, "lua_health": self.lua_health, "known_detectors": PIDS_DETECTORS,
                "recent": self.records[-100:]}
