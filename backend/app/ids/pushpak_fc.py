"""PUSHPAK FC + Lua integration detector (spec §28/§29).

Consumes vehicle STATUSTEXT only. States/confidence are *reported by the FC or
Lua*, never manufactured here; when no PUSHPAK telemetry has been received the
FC/LUA columns stay N/A.
"""
from __future__ import annotations

from typing import Optional

from ..mavlink.pushpak import (GNSSINT_HORIZONS_S, LUA_CONFIRM_THRESHOLD, LUA_SCRIPT_FOR_DETECTOR, PIDS_DETECTORS,
                               EventDeliveryTracker, StatusTextAssembler, decode_idsg, decode_idsr, parse_statustext)
from ..models.events import TelemetryEvent
from .base import AnalysisContext, Detector

PUSHPAK_DOMAIN = {"GPS": "GPS_INTEGRITY", "MAVLINK": "MAVLINK_SECURITY", "COMMAND": "MAVLINK_SECURITY",
                  "RC_LINK": "LINK", "IMU": "SENSOR", "MISSION": "MISSION", "PARAMETER": "MAVLINK_SECURITY",
                  "OFFBOARD": "MAVLINK_SECURITY"}


class PushpakFCDetector(Detector):
    detector_id = "PUSHPAK_FC"
    name = "PUSHPAK FC / Lua"
    domain = "PUSHPAK"
    # STATUSTEXT live; DataFlash IDSE/IDSH/IDSF records from imported logs once the firmware writes them (FW-03);
    # IDSG/IDSR GNSSIntegrity physics-engine detail records (FW-13).
    data_sources = ("STATUSTEXT", "DF_IDSE", "DF_IDSH", "DF_IDSF", "DF_IDSG", "DF_IDSR")
    methods = ("PIDS STATUSTEXT adapter", "Lua confirmation adapter", "Lua runtime-error health",
               "IMU-propagated GNSS integrity (IDSG)")
    description = "Normalises FC (PIDS) and Lua confirmation STATUSTEXT into detector states; tracks Lua script health."
    limitations = ("FC/Lua states are N/A until the vehicle sends PUSHPAK STATUSTEXT: the Lua scripts must be installed "
                   "(SCR_ENABLE=1) and the telemetry link must carry STATUSTEXT.",
                   "A PIDS state is flagged unverified unless configs/capabilities.json verifies the AP_IDS state enum.")

    def __init__(self, cfg):
        super().__init__(cfg)
        self.fc: dict[str, dict] = {}
        self.lua: dict[str, dict] = {}
        self.lua_health: dict[str, dict] = {}
        self.records: list[dict] = []
        self.unparsed = 0
        self.assembler = StatusTextAssembler()
        self.chunk_idx: dict = {}
        self.delivery = EventDeliveryTracker()
        self.gnss_integrity: Optional[dict] = None   # latest IDSG summary with its IDSR horizons
        self.gnss_integrity_history: list[dict] = []
        self._idsr_pending: dict[tuple, dict] = {}
        self._idsg_seen: set[tuple] = set()

    def process(self, ev: TelemetryEvent, ctx: AnalysisContext):
        if ev.sysid != ctx.vehicle_sysid:
            return []
        if ev.msg_name in ("DF_IDSE", "DF_IDSH", "DF_IDSF"):
            return self._dataflash(ev, ctx)
        if ev.msg_name in ("DF_IDSG", "DF_IDSR"):
            return self._gnss_integrity(ev, ctx)
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
        if kind in ("BRIDGE", "FC_EVENT", "STATEMAP", "SYNC"):
            self.bridge = rec
            self.lua_health["ids_gcs_bridge.lua"] = {"status": "RUNNING", "last": ctx.t, "message": rec["original"]}
            return self._delivery(rec, ctx, ev, refs)
        if kind == "PIDS" and rec.get("origin") == "LUA":
            # per-script Lua result (fixed scripts publish PIDS with origin LUA)
            sm = self.delivery.state_map
            if sm is not None and rec["state_raw"] in sm:
                # Lua scripts announced their own state numbering (bridge STATEMAP); use it.
                rec["state"], rec["state_map_verified"] = sm[rec["state_raw"]], True
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
            if rec.get("boot_id") is not None and rec.get("seq") is not None and self.delivery.on_native_event(rec["boot_id"], rec["seq"]):
                return []  # same AP_IDS event already processed
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

    def _dataflash(self, ev, ctx) -> list:
        """Onboard AP_IDS DataFlash records (firmware FW-03): same meaning as the PIDS STATUSTEXT, but durable."""
        f = ev.fields
        self.mark_data(ctx)
        if ev.msg_name == "DF_IDSE":
            det_i = int(f.get("Det", -1))
            det = PIDS_DETECTORS[det_i] if 0 <= det_i < len(PIDS_DETECTORS) else f"UNKNOWN({det_i})"
            text = (f"PIDS|2|FC|{det}|{int(f.get('St', 0))}|{float(f.get('Conf', 0)):.3f}|{int(f.get('Ev', 0))}|"
                    f"{float(f.get('Met', 0)):.2f}|{int(f.get('Inst', 0))}|{int(f.get('Boot', 0))}|{int(f.get('Seq', 0))}")
            ev.fields = {"text": text, "severity": None, "dataflash": dict(f)}
            ev.msg_name = "STATUSTEXT"
            try:
                return self.process(ev, ctx)
            finally:
                ev.msg_name = "DF_IDSE"
                ev.fields = f
        if ev.msg_name == "DF_IDSH":
            out = []
            q, lg = int(f.get("QDrop", 0)), int(f.get("LogDrop", 0))
            last = getattr(self, "_pidh", {"QDrop": 0, "LogDrop": 0})
            if q > last["QDrop"] or lg > last["LogDrop"]:
                out.append(self.result(ctx, "OBSERVED", f"AP_IDS event loss on board: ring dropped {q}, log dropped {lg}", kind="health",
                                       severity="MEDIUM", ev=ev, source="FC", domain="PUSHPAK", method="DataFlash IDSH counters",
                                       inputs=dict(f), why="The native IDS reports events it could not queue or log; they are lost, not hidden."))
            self._pidh = {"QDrop": q, "LogDrop": lg}
            self.delivery.ring_dropped = max(self.delivery.ring_dropped, q)
            return out
        return [self.result(ctx, "OBSERVED", f"AP_IDS fault code {f.get('Code')} (subsystem {f.get('Sub')})", kind="health",
                            severity="MEDIUM", ev=ev, source="FC", domain="PUSHPAK", method="DataFlash IDSF fault record",
                            inputs=dict(f), why="The native IDS recorded an internal fault and its recovery state.")]

    GNSSINT_LIMITATIONS = (
        "GNSS/INS disagreement is evidence of GNSS integrity loss, not proof of intentional spoofing.",
        "Shares the GNSS receiver with GPS_INTEGRITY and the IMU with IMU_CONSISTENCY: the correlator counts "
        "them as one line of evidence, not as independent corroboration.",
        "An attack already present when the engine was seeded cannot be detected by this method.",
    )

    def _gnss_integrity(self, ev, ctx) -> list:
        """FW-13: native GNSSIntegrity engine (IMU-only prediction vs GNSS), DataFlash IDSG + IDSR."""
        f = ev.fields
        self.mark_data(ctx)
        key = (int(f.get("Boot", 0)), int(f.get("Seq", 0)))
        if ev.msg_name == "DF_IDSR":
            row = decode_idsr(f)
            self._idsr_pending.setdefault(key, {})[row["index"]] = row
            for k in list(self._idsr_pending)[:-8]:   # bounded: rows only wait for their own summary
                self._idsr_pending.pop(k, None)
            if self.gnss_integrity and (self.gnss_integrity["boot"], self.gnss_integrity["seq"]) == key:
                self.gnss_integrity["horizons"][row["index"]] = row   # late row for an already-seen summary
            return []
        if key in self._idsg_seen:
            return []   # same evaluation replayed (duplicate log import)
        self._idsg_seen.add(key)
        if len(self._idsg_seen) > 20000:
            self._idsg_seen = {k for k in self._idsg_seen if k[0] == key[0]}
        rec = decode_idsg(f)
        rec["t"] = ctx.t
        rec["horizons"] = self._idsr_pending.pop(key, {})
        prev = self.gnss_integrity
        self.gnss_integrity = rec
        self.gnss_integrity_history.append({k: rec[k] for k in ("t", "seq", "state", "confidence", "warn", "alarm", "valid")})
        del self.gnss_integrity_history[:-600]
        st, pst = rec["state"], (prev or {}).get("state")
        if st == pst:
            return []
        inputs = {"detector": "GPS", "engine": "GNSSIntegrity", "gnss_integrity_state": st, "boot": rec["boot"],
                  "seq": rec["seq"], "armed_horizons_s": rec["armed"], "valid_horizons_s": rec["valid"],
                  "warn_horizons_s": rec["warn"], "alarm_horizons_s": rec["alarm"], "flags": rec["flags"],
                  "delta_speed_residual_mps": rec["delta_speed_residual_mps"], "baro_residual_m": rec["baro_residual_m"],
                  "accel_bias_norm_mps2": rec["accel_bias_norm_mps2"], "fix_age_ms": rec["fix_age_ms"],
                  "applied_lag_ms": rec["applied_lag_ms"], "idsg": dict(f)}
        horizon_lines = [f"{h['duration_s']} s horizon: {','.join(h['status']) or 'idle'}; |r_p| {h['position_residual_m']:.1f} m "
                         f"(D2 {h['position_test']:.1f}), |r_v| {h['velocity_residual_mps']:.2f} m/s (D2 {h['velocity_test']:.1f}), "
                         f"speed-change D2 {h['delta_speed_test']:.1f}; reason {h['reason']}"
                         for _, h in sorted(rec["horizons"].items())]
        limits = list(self.GNSSINT_LIMITATIONS)
        if not rec["version_supported"]:
            limits.append(f"IDSG record version {rec['version']} is not the version this GCS decodes")
        if st in ("WARNING", "ALARM"):
            ins = bool(rec["warn"] or rec["alarm"] or st == "ALARM")
            baro = "BARO_WARN" in rec["flags"]
            ground = "GROUND_WARN" in rec["flags"]
            if ins:
                method = "IMU-propagated GNSS integrity + baro (IDSG)" if baro else "IMU-propagated GNSS integrity (IDSG)"
            elif ground:
                method = "GNSS stationary-ground constraint (IDSG)"
            else:
                method = "GNSS/baro altitude-change cross-check (IDSG)"
            which = ", ".join(f"{d} s" for d in (rec["alarm"] or rec["warn"]))
            if not which:
                which = "barometer" if baro else ("ground" if ground else "latched")
            state = "SUSPECTED" if st == "ALARM" else "ANOMALOUS"
            why = (f"The onboard GNSSIntegrity engine reported {st}: a GNSS fix failed the uncertainty-aware residual test "
                   f"against an inertial prediction that GNSS cannot correct during the horizon. Joint confidence "
                   f"{rec['confidence']:.2f} (FC-reported).")
            return [self.result(ctx, state, f"FC GNSS integrity {st}: GNSS disagrees with the IMU-only prediction ({which})",
                                ev=ev, source="FC", domain="GPS_INTEGRITY", confidence=rec["confidence"], inputs=inputs,
                                method=method, why=why,
                                evidence=[f"IDSG Boot {rec['boot']} Seq {rec['seq']}: state {st}, flags {','.join(rec['flags'])}"]
                                + horizon_lines,
                                contributors=[{"label": "FC GNSSIntegrity (IDSG)", "value": rec["confidence"]}],
                                limitations=limits)]
        if pst in ("WARNING", "ALARM"):
            return [self.result(ctx, "OBSERVED", f"FC GNSS integrity returned to {st}", kind="recovery", ev=ev, source="FC",
                                domain="GPS_INTEGRITY", confidence=rec["confidence"], inputs=inputs,
                                method="IMU-propagated GNSS integrity (IDSG)", evidence=horizon_lines,
                                why="The engine's sensitivity-aware clearing rule passed, or an independent reseed occurred.",
                                limitations=limits)]
        if st in ("DEGRADED", "HEADING_UNOBSERVABLE", "NO_TRUSTED_SEED"):
            reasons = sorted({h["reason"] for h in rec["horizons"].values() if h["reason"] not in ("NONE", "EXPIRED")})
            detail = f" ({', '.join(reasons)})" if reasons else ""
            return [self.result(ctx, "OBSERVED", f"FC GNSS integrity {st} (reduced coverage, not spoofing evidence)",
                                kind="health", severity="LOW", ev=ev, source="FC", domain="GPS_INTEGRITY", inputs=inputs,
                                method="IMU-propagated GNSS integrity (IDSG)", evidence=horizon_lines,
                                why=f"The inertial prediction cannot currently support a reliable comparison{detail}. "
                                    "Degraded is never reported as an attack.",
                                limitations=limits)]
        return []

    def gnss_integrity_status(self) -> Optional[dict]:
        g = self.gnss_integrity
        if g is None:
            return None
        horizons = [g["horizons"].get(i) or {"index": i, "duration_s": d, "status": [], "reason": "NO_RECORD"}
                    for i, d in enumerate(GNSSINT_HORIZONS_S)]
        out = {k: g[k] for k in ("t", "boot", "seq", "version", "state", "confidence", "armed", "valid", "warn", "alarm",
                                 "flags", "fix_age_ms", "applied_lag_ms", "delta_speed_residual_mps", "baro_residual_m",
                                 "accel_bias_norm_mps2")}
        out["horizons"] = horizons
        out["history"] = self.gnss_integrity_history[-120:]
        return out

    def _delivery(self, rec: dict, ctx, ev, refs) -> list:
        """Bridge protocol v2 bookkeeping: reboots, missed/duplicate events (GAP-07)."""
        d, kind = self.delivery, rec["kind"]
        if kind == "BRIDGE":
            d.on_bridge(rec)
            return []
        if kind == "STATEMAP":
            d.on_statemap(rec)
            if d.state_map_matches_assumed is False:
                return [self.result(ctx, "OBSERVED", "Bridge state map differs from GCS assumption", kind="health", severity="MEDIUM",
                                    ev=ev, refs=refs, source="LUA", domain="PUSHPAK", method="bridge STATEMAP",
                                    inputs={"announced": d.state_map}, why="Lua PIDS states are decoded with the announced map.")]
            return []
        if kind == "SYNC":
            r = d.on_sync(rec)
            out = []
            if r["new_ring_drops"]:
                out.append(self.result(ctx, "OBSERVED", f"AP_IDS event ring overflow: {r['new_ring_drops']} event(s) dropped on board",
                                       kind="health", severity="MEDIUM", ev=ev, refs=refs, source="LUA", domain="PUSHPAK",
                                       method="bridge SYNC drop counter", inputs=d.status(),
                                       why="The native IDS overwrote events before they were reported; check DataFlash IDSE records."))
            if r["reboot"]:
                out.append(self.result(ctx, "OBSERVED", "Flight controller reboot detected (bridge uptime reset)", kind="observation",
                                       severity="HIGH" if ctx.airborne else "MEDIUM", ev=ev, refs=refs, source="LUA",
                                       domain="PUSHPAK", method="bridge SYNC uptime", inputs={"uptime_s": rec["uptime_s"],
                                       "boot_epoch": d.boot_epoch}, why="SYNC uptime went backwards; event sequence numbering restarted."))
            if r["new_missing"]:
                out.append(self.result(ctx, "OBSERVED", f"PUSHPAK event delivery gap: {r['new_missing']} FC_EVENT line(s) missed",
                                       kind="health", severity="MEDIUM", ev=ev, refs=refs, source="LUA", domain="PUSHPAK",
                                       method="bridge SYNC count vs received", inputs=d.status(),
                                       why=f"The bridge reports {rec['events_sent']} FC_EVENT lines this boot; this GCS received "
                                           f"{d.received} after its first SYNC baseline. Recover the events from onboard logs.",
                                       limitations=["One-way telemetry: missing lines cannot be re-requested over MAVLink."]))
            return out
        d.on_fc_event(rec)  # duplicates are counted and ignored; FC_EVENT itself never opens incidents
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
                        "lua_scripts": self.lua_health, "records": len(self.records), "unparsed_lua": self.unparsed,
                        "event_delivery": self.delivery.status(),
                        "gnss_integrity_state": (self.gnss_integrity or {}).get("state")}
        return []

    def table(self) -> dict:
        return {"fc": self.fc, "lua": self.lua, "lua_health": self.lua_health, "known_detectors": PIDS_DETECTORS,
                "event_delivery": self.delivery.status(), "gnss_integrity": self.gnss_integrity_status(),
                "recent": self.records[-100:]}
