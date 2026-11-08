"""MAVLink-layer detectors (spec §19, §20): heartbeat, sequence, source identity,
rate and signing. Tracked per SYSID + COMPID + link."""
from __future__ import annotations

import hashlib
from collections import Counter, defaultdict, deque
from typing import Optional

from ..models.events import TelemetryEvent
from .base import AnalysisContext, Detector
from .stats import CUSUM, EWMA, clamp01, shannon_entropy

CONTROL_PLANE = {
    "COMMAND_LONG", "COMMAND_INT", "PARAM_SET", "PARAM_EXT_SET", "MISSION_COUNT", "MISSION_ITEM",
    "MISSION_ITEM_INT", "MISSION_CLEAR_ALL", "MISSION_SET_CURRENT", "SET_MODE", "SET_POSITION_TARGET_LOCAL_NED",
    "SET_POSITION_TARGET_GLOBAL_INT", "SET_ATTITUDE_TARGET", "MANUAL_CONTROL", "RC_CHANNELS_OVERRIDE",
    "SET_HOME_POSITION", "FILE_TRANSFER_PROTOCOL", "SETUP_SIGNING",
}


class HeartbeatDetector(Detector):
    detector_id = "HEARTBEAT"
    name = "Heartbeat"
    domain = "LINK"
    data_sources = ("HEARTBEAT",)
    methods = ("heartbeat gap timing", "loss/recovery state machine", "intermittency count")
    description = "Vehicle heartbeat gaps, loss and recovery (monotonic time)."
    limitations = ("Heartbeat gaps also occur with benign range loss or cable faults.",)

    def __init__(self, cfg, stale_s: float = 3.0, loss_s: float = 6.0):
        super().__init__(cfg)
        self.stale_s = stale_s
        self.loss_s = loss_s
        self.last_hb: Optional[float] = None
        self.phase = "WAITING"          # WAITING | OK | STALE | LOST
        self.loss_started: Optional[float] = None
        self.losses: deque[float] = deque(maxlen=50)
        self.intervals = EWMA(0.1)

    def process(self, ev: TelemetryEvent, ctx: AnalysisContext):
        if not ctx.is_vehicle(ev):
            return []
        self.mark_data(ctx)
        out = []
        if self.last_hb is not None:
            self.intervals.update(ctx.mono - self.last_hb)
        if self.phase in ("STALE", "LOST") and self.loss_started is not None:
            gap = ctx.mono - (self.last_hb or ctx.mono)
            out.append(self.result(ctx, "OBSERVED", "Heartbeat recovery", kind="recovery", ev=ev,
                                   inputs={"gap_s": round(gap, 2), "previous_phase": self.phase},
                                   method="heartbeat gap timing", why=f"Vehicle heartbeat resumed after {gap:.1f} s."))
        self.phase = "OK"
        self.last_hb = ctx.mono
        self.loss_started = None
        self.metrics = {"phase": self.phase, "mean_interval_s": round(self.intervals.mean or 0, 3),
                        "losses_60s": sum(1 for x in self.losses if ctx.mono - x < 60)}
        return out

    def tick(self, ctx: AnalysisContext):
        if self.last_hb is None:
            return []
        gap = ctx.mono - self.last_hb
        out = []
        params = {"stale_s": self.stale_s, "loss_s": self.loss_s}
        if gap > self.loss_s and self.phase != "LOST":
            self.phase = "LOST"
            self.loss_started = ctx.mono
            self.losses.append(ctx.mono)
            recent = sum(1 for x in self.losses if ctx.mono - x < 60)
            intermittent = recent >= 3
            out.append(self.result(ctx, "SUSPECTED" if intermittent else "ANOMALOUS",
                                   "Intermittent heartbeat loss" if intermittent else "Heartbeat loss",
                                   method="heartbeat gap timing", parameters=params, score=gap, threshold=self.loss_s,
                                   inputs={"gap_s": round(gap, 2), "losses_last_60s": recent},
                                   confidence=clamp01(0.4 + 0.15 * recent),
                                   why=f"No vehicle HEARTBEAT for {gap:.1f} s (> {self.loss_s} s)."
                                       + (f" {recent} losses in the last 60 s." if intermittent else "")))
        elif self.stale_s < gap <= self.loss_s and self.phase == "OK":
            self.phase = "STALE"
            out.append(self.result(ctx, "ANOMALOUS", "Heartbeat stale", severity="LOW", method="heartbeat gap timing",
                                   parameters=params, score=gap, threshold=self.stale_s, inputs={"gap_s": round(gap, 2)},
                                   why=f"Vehicle heartbeat late by {gap:.1f} s."))
        self.metrics["phase"] = self.phase
        self.metrics["heartbeat_age_s"] = round(gap, 2)
        return out


class MavlinkSequenceDetector(Detector):
    detector_id = "MAVLINK_SEQUENCE"
    name = "MAVLink Sequence"
    domain = "LINK"
    methods = ("per-source sequence continuity", "duplicate frame matching", "out-of-order window", "windowed loss ratio")
    description = "Sequence gaps, duplicates and out-of-order frames per SYSID/COMPID/link."
    limitations = ("MAVLink routers that merge links can reorder or duplicate frames legitimately.",
                   "Loss estimates are only meaningful per link.")

    def __init__(self, cfg):
        super().__init__(cfg)
        self.loss_thr = float(self.cfg.get("loss_ratio_threshold", 0.1))
        self.min_pkts = int(self.cfg.get("min_window_packets", 50))
        self.window_s = float(self.cfg.get("window_s", 10))
        self.dup_window = float(self.cfg.get("duplicate_window_s", 2.0))
        self.reorder_tol = int(self.cfg.get("reorder_tolerance", 16))
        self.st: dict[tuple, dict] = {}
        self.cool: dict[tuple, float] = {}

    def accepts(self, ev):
        return ev.sequence is not None and ev.msg_name != "BAD_DATA" and ev.sysid is not None

    def _cool(self, key, ctx, s=5.0) -> bool:
        if ctx.mono - self.cool.get(key, -1e9) < s:
            return False
        self.cool[key] = ctx.mono
        return True

    def process(self, ev: TelemetryEvent, ctx: AnalysisContext):
        self.mark_data(ctx)
        key = (ev.link, ev.sysid, ev.compid)
        s = self.st.get(key)
        digest = hashlib.blake2b(ev.raw or b"", digest_size=8).digest() if ev.raw else None
        if s is None:
            s = self.st[key] = {"last": ev.sequence, "recv": 1, "lost": 0, "dup": 0, "reorder": 0,
                                "win": deque(), "recent": deque(maxlen=512)}
            s["recent"].append((ctx.mono, ev.sequence, digest))
            return []
        out = []
        s["recv"] += 1
        diff = (ev.sequence - s["last"]) % 256
        lost_inc = 0
        dup_hit = digest is not None and any(d == digest and seq == ev.sequence and ctx.mono - t <= self.dup_window
                                             for t, seq, d in s["recent"])
        if dup_hit:
            s["dup"] += 1
            if self._cool((key, "dup"), ctx):
                out.append(self.result(ctx, "ANOMALOUS", "Duplicate MAVLink frame (replay-like)", ev=ev,
                                       domain="MAVLINK_SECURITY", method="duplicate frame matching",
                                       parameters={"window_s": self.dup_window},
                                       inputs={"sysid": ev.sysid, "compid": ev.compid, "link": ev.link, "seq": ev.sequence,
                                               "msg": ev.msg_name, "duplicates_total": s["dup"]},
                                       confidence=clamp01(0.3 + 0.1 * s["dup"]),
                                       why="An identical frame (same sequence and bytes) was received again within the duplicate window."))
        elif diff == 0:
            pass  # same seq, different bytes: counts as neither
        elif diff > 256 - self.reorder_tol:
            s["reorder"] += 1
            if s["lost"] > 0:
                s["lost"] -= 1
                lost_inc = -1
            if self._cool((key, "reorder"), ctx):
                out.append(self.result(ctx, "ANOMALOUS", "Out-of-order MAVLink frame", ev=ev, severity="LOW",
                                       domain="MAVLINK_SECURITY", method="out-of-order window",
                                       parameters={"reorder_tolerance": self.reorder_tol},
                                       inputs={"expected_after": s["last"], "got": ev.sequence, "reordered_total": s["reorder"]},
                                       why="Sequence number went backwards within the reorder tolerance."))
        elif diff > 1:
            lost_inc = diff - 1
            s["lost"] += lost_inc
        if not dup_hit and diff != 0 and not (diff > 256 - self.reorder_tol):
            s["last"] = ev.sequence
        s["recent"].append((ctx.mono, ev.sequence, digest))
        win = s["win"]
        win.append((ctx.mono, 1, lost_inc))
        while win and ctx.mono - win[0][0] > self.window_s:
            win.popleft()
        recv = sum(w[1] for w in win)
        lost = max(0, sum(w[2] for w in win))
        ratio = lost / (recv + lost) if recv + lost else 0.0
        s["ratio"] = ratio
        if recv + lost >= self.min_pkts and ratio > self.loss_thr and self._cool((key, "loss"), ctx, 10):
            out.append(self.result(ctx, "ANOMALOUS", "MAVLink packet loss", ev=ev, method="windowed loss ratio",
                                   parameters={"window_s": self.window_s, "threshold": self.loss_thr},
                                   score=ratio, threshold=self.loss_thr, confidence=clamp01(ratio * 2),
                                   inputs={"link": ev.link, "sysid": ev.sysid, "compid": ev.compid,
                                           "received": recv, "lost": lost, "loss_ratio": round(ratio, 3)},
                                   why=f"{lost} frames missing out of {recv + lost} expected in {self.window_s:.0f} s."))
        return out

    def summary(self) -> list[dict]:
        rows = []
        for (link, sysid, compid), s in self.st.items():
            total = s["recv"] + s["lost"]
            rows.append({"link": link, "sysid": sysid, "compid": compid, "received": s["recv"], "lost": s["lost"],
                         "duplicates": s["dup"], "reordered": s["reorder"],
                         "loss_pct": round(100 * s["lost"] / total, 2) if total else 0.0,
                         "window_loss_pct": round(100 * s.get("ratio", 0), 2)})
        return rows

    def tick(self, ctx):
        self.metrics = {"sources": len(self.st), "total_lost": sum(s["lost"] for s in self.st.values()),
                        "total_duplicates": sum(s["dup"] for s in self.st.values())}
        return []


class SourceIdentityDetector(Detector):
    detector_id = "SOURCE_IDENTITY"
    name = "Source Identity"
    domain = "MAVLINK_SECURITY"
    methods = ("baseline source learning", "control-plane provenance", "vehicle identity/link consistency")
    description = "New SYSID/COMPID sources, unexpected control-plane senders, identity changes."
    limitations = ("A new source can be a legitimate companion computer or second GCS.",)

    def __init__(self, cfg):
        super().__init__(cfg)
        self.baseline_s = float(self.cfg.get("baseline_seconds", 20))
        self.sources: dict[tuple, dict] = {}
        self.vehicle_identity: Optional[tuple] = None
        self.vehicle_links: set[str] = set()
        self.cool: dict = {}

    def accepts(self, ev):
        return ev.sysid is not None and ev.msg_name != "BAD_DATA"

    def process(self, ev: TelemetryEvent, ctx: AnalysisContext):
        self.mark_data(ctx)
        key = (ev.sysid, ev.compid)
        out = []
        src = self.sources.get(key)
        in_baseline = ctx.elapsed < self.baseline_s
        if src is None:
            src = self.sources[key] = {"first_seen": ctx.t, "first_mono": ctx.mono, "count": 0, "msgs": Counter(),
                                       "links": set(), "baseline": in_baseline}
            trusted = ctx.is_trusted_gcs(ev.sysid) or ev.sysid == ctx.vehicle_sysid
            out.append(self.result(ctx, "OBSERVED", "NEW SOURCE OBSERVED" if not in_baseline else "Source learned (baseline)",
                                   kind="observation" if (in_baseline or trusted) else "alert", ev=ev,
                                   severity="LOW" if not in_baseline and not trusted else "INFO",
                                   method="baseline source learning", parameters={"baseline_seconds": self.baseline_s},
                                   inputs={"sysid": ev.sysid, "compid": ev.compid, "link": ev.link, "first_message": ev.msg_name,
                                           "trusted_gcs": ctx.is_trusted_gcs(ev.sysid), "during_baseline": in_baseline},
                                   why="A SYSID/COMPID pair not previously seen on any link started transmitting. "
                                       "This is recorded as context only; it is not classified as malicious by itself."))
        src["count"] += 1
        src["msgs"][ev.msg_name] += 1
        src["links"].add(ev.link)
        # control-plane traffic from an untrusted, non-vehicle source
        if ev.msg_name in CONTROL_PLANE and ev.sysid != ctx.vehicle_sysid and not ctx.is_trusted_gcs(ev.sysid):
            ck = ("ctl", key, ev.msg_name)
            if ctx.mono - self.cool.get(ck, -1e9) > 10:
                self.cool[ck] = ctx.mono
                out.append(self.result(ctx, "SUSPECTED", "Untrusted source sending control-plane messages", ev=ev,
                                       method="control-plane provenance", confidence=0.55,
                                       inputs={"sysid": ev.sysid, "compid": ev.compid, "message": ev.msg_name,
                                               "trusted_gcs_sysids": sorted(ctx.trusted_gcs), "source_age_s": round(ctx.mono - src["first_mono"], 1)},
                                       why=f"SYSID {ev.sysid} is not a configured trusted GCS and sent {ev.msg_name}.",
                                       contributors=[{"label": "untrusted control-plane sender", "value": 0.55}]))
        # vehicle identity consistency
        if ev.msg_name == "HEARTBEAT" and ev.sysid == ctx.vehicle_sysid and ev.compid == 1:
            ident = (ev.fields.get("type"), ev.fields.get("autopilot"))
            if self.vehicle_identity is None:
                self.vehicle_identity = ident
            elif ident != self.vehicle_identity and ctx.mono - self.cool.get("ident", -1e9) > 10:
                self.cool["ident"] = ctx.mono
                out.append(self.result(ctx, "SUSPECTED", "Vehicle identity changed (possible masquerade)", ev=ev,
                                       method="vehicle identity/link consistency", confidence=0.6,
                                       inputs={"baseline_type_autopilot": self.vehicle_identity, "observed": ident},
                                       why="A HEARTBEAT using the vehicle SYSID reports a different MAV_TYPE/autopilot."))
        if ev.sysid == ctx.vehicle_sysid and ev.compid == 1:
            if not self.vehicle_links:
                self.vehicle_links.add(ev.link)
            elif ev.link not in self.vehicle_links and ctx.mono - self.cool.get(("link", ev.link), -1e9) > 30:
                self.cool[("link", ev.link)] = ctx.mono
                self.vehicle_links.add(ev.link)
                out.append(self.result(ctx, "OBSERVED", "Vehicle identity seen on an additional link", ev=ev,
                                       severity="LOW", method="vehicle identity/link consistency",
                                       inputs={"link": ev.link, "known_links": sorted(self.vehicle_links)},
                                       why="Frames with the vehicle SYSID/COMPID arrived on a link not used before."))
        return out

    def tick(self, ctx):
        self.metrics = {"sources": len(self.sources),
                        "untrusted": sum(1 for (s, _c) in self.sources if s != ctx.vehicle_sysid and not ctx.is_trusted_gcs(s))}
        return []

    def table(self, ctx) -> list[dict]:
        return [{"sysid": s, "compid": c, "count": v["count"], "first_seen": v["first_seen"],
                 "links": sorted(v["links"]), "top_messages": v["msgs"].most_common(6),
                 "role": "VEHICLE" if s == ctx.vehicle_sysid else ("TRUSTED_GCS" if ctx.is_trusted_gcs(s) else "UNKNOWN"),
                 "learned_in_baseline": v["baseline"]} for (s, c), v in self.sources.items()]


class MavlinkRateDetector(Detector):
    detector_id = "MAVLINK_RATE"
    name = "MAVLink Rate"
    domain = "MAVLINK_SECURITY"
    methods = ("per-message EWMA baseline", "burst factor", "CUSUM on total rate", "message-mix entropy")
    description = "Message bursts, rate deviations and message-mix changes versus a learned baseline."
    limitations = ("Stream-rate changes requested by a GCS (SRx_ params) change rates legitimately.",)

    def __init__(self, cfg):
        super().__init__(cfg)
        self.factor = float(self.cfg.get("burst_factor", 4.0))
        self.min_hz = float(self.cfg.get("min_baseline_hz", 0.5))
        self.baseline_s = float(self.cfg.get("baseline_seconds", 30))
        self.counts: Counter = Counter()
        self.base: dict[str, EWMA] = defaultdict(lambda: EWMA(0.05))
        self.total = EWMA(0.05)
        self.cusum = CUSUM(float(self.cfg.get("cusum_k", 0.5)), float(self.cfg.get("cusum_h", 8.0)))
        self.low: Counter = Counter()
        self.presence: dict = defaultdict(lambda: deque(maxlen=20))
        self.entropy_base = EWMA(0.05)
        self.cool: dict = {}
        self.last_rates: dict = {}

    def accepts(self, ev):
        return ev.msg_name != "BAD_DATA"

    def process(self, ev, ctx):
        self.mark_data(ctx)
        self.counts[(ev.sysid, ev.msg_name)] += 1
        return []

    def tick(self, ctx):
        out = []
        counts, self.counts = self.counts, Counter()
        learning = ctx.elapsed < self.baseline_s
        total = sum(counts.values())
        mix = Counter({k[1]: v for k, v in counts.items()})
        ent = shannon_entropy(mix)
        self.last_rates = {f"{s}:{m}": c for (s, m), c in counts.items()}
        seen = set(counts) | {k for k in self.base}
        for key in seen:
            c = counts.get(key, 0)
            b = self.base[key]
            pres = self.presence[key]
            steady = len(pres) == pres.maxlen and sum(1 for x in pres if x > 0) >= 18
            pres.append(c)
            if not learning and b.mean is not None and b.n >= 10:
                if c > max(5, self.factor * max(b.mean, self.min_hz)) and self._cool(("burst", key), ctx):
                    out.append(self.result(ctx, "ANOMALOUS", "Message burst", method="per-message EWMA baseline",
                                           parameters={"burst_factor": self.factor}, score=c, threshold=round(self.factor * b.mean, 2),
                                           inputs={"sysid": key[0], "message": key[1], "rate_hz": c, "baseline_hz": round(b.mean, 2)},
                                           confidence=clamp01(c / (self.factor * max(b.mean, 1)) - 0.5),
                                           why=f"{key[1]} from SYSID {key[0]} arrived at {c}/s vs baseline {b.mean:.1f}/s."))
                if steady and b.mean >= self.min_hz * 2 and c < b.mean / self.factor:
                    self.low[key] += 1
                    if self.low[key] == 3 and key[0] == ctx.vehicle_sysid:
                        out.append(self.result(ctx, "ANOMALOUS", "Message rate drop", domain="LINK", severity="LOW",
                                               method="per-message EWMA baseline", score=c, threshold=round(b.mean / self.factor, 2),
                                               inputs={"sysid": key[0], "message": key[1], "rate_hz": c, "baseline_hz": round(b.mean, 2)},
                                               why=f"{key[1]} rate below 1/{self.factor:.0f} of baseline for 3 s."))
                else:
                    self.low[key] = 0
            # only learn from non-burst seconds
            if learning or b.mean is None or c <= self.factor * max(b.mean, self.min_hz):
                b.update(c)
        if not learning and self.total.n >= 10:
            z = self.total.z(total) or 0.0
            self.cusum.update(abs(z))
            if self.cusum.alarm and self._cool("cusum", ctx, 20):
                out.append(self.result(ctx, "ANOMALOUS", "Total packet-rate deviation (CUSUM)", severity="LOW",
                                       method="CUSUM on total rate", parameters=self.cusum.describe(), score=round(self.cusum.s, 2),
                                       threshold=self.cusum.h, inputs={"total_rate_hz": total, "baseline_hz": round(self.total.mean, 1)},
                                       why="Accumulated deviation of the total packet rate exceeded the CUSUM limit."))
                self.cusum.reset()
            ez = self.entropy_base.z(ent)
            if ez is not None and abs(ez) > 6 and self._cool("entropy", ctx, 30):
                out.append(self.result(ctx, "OBSERVED", "Message-mix entropy change", severity="LOW", kind="observation",
                                       method="message-mix entropy", score=round(ez, 2), threshold=6,
                                       inputs={"entropy_bits": round(ent, 3), "baseline_bits": round(self.entropy_base.mean, 3)},
                                       why="The distribution of message types changed markedly versus baseline."))
        if learning or total <= self.factor * max(self.total.mean or total, 1):
            self.total.update(total)
        if learning or ent:
            self.entropy_base.update(ent)
        self.metrics = {"total_rate_hz": total, "baseline_total_hz": round(self.total.mean or 0, 1),
                        "entropy_bits": round(ent, 3), "learning": learning}
        return out

    def _cool(self, key, ctx, s=10.0) -> bool:
        if ctx.mono - self.cool.get(key, -1e9) < s:
            return False
        self.cool[key] = ctx.mono
        return True


class SigningDetector(Detector):
    detector_id = "MAVLINK_SIGNING"
    name = "MAVLink Signing"
    domain = "MAVLINK_SECURITY"
    methods = ("signature flag tracking", "signature validation (when key configured)", "downgrade detection")
    description = "MAVLink 2 signing state per source. Signing authenticates frames; it does NOT encrypt telemetry."
    limitations = ("Without the secret key the GCS can observe that frames are signed but cannot validate them.",
                   "Signing provides authentication metadata only, not confidentiality.")

    def __init__(self, cfg, expected: bool = False, key_configured: bool = False):
        super().__init__(cfg)
        self.expected = expected
        self.key_configured = key_configured
        self.src: dict[tuple, dict] = {}
        self.cool: dict = {}

    def accepts(self, ev):
        return ev.sysid is not None

    def process(self, ev: TelemetryEvent, ctx):
        self.mark_data(ctx)
        key = (ev.sysid, ev.compid)
        s = self.src.setdefault(key, {"signed": 0, "unsigned": 0, "invalid": 0, "was_signed": False})
        out = []
        if ev.msg_name == "BAD_DATA":
            if ev.signature_status == "INVALID":
                s["invalid"] += 1
                if self._cool(("inv", key), ctx):
                    out.append(self.result(ctx, "SUSPECTED", "Invalid MAVLink signature", ev=ev, confidence=0.7,
                                           method="signature validation (when key configured)",
                                           inputs={"sysid": ev.sysid, "compid": ev.compid, "invalid_total": s["invalid"],
                                                   "parse_error": ev.parse_error},
                                           why="A signed frame failed signature validation with the configured key."))
            return out
        if ev.mavlink_version == 1:
            s["unsigned"] += 1
        elif ev.signed:
            s["signed"] += 1
            s["was_signed"] = True
        else:
            s["unsigned"] += 1
            if s["was_signed"] and self._cool(("down", key), ctx, 30):
                out.append(self.result(ctx, "SUSPECTED", "Signing downgrade (signed source sent unsigned frame)", ev=ev,
                                       confidence=0.6, method="downgrade detection",
                                       inputs={"sysid": ev.sysid, "compid": ev.compid, "msg": ev.msg_name,
                                               "signed_before": s["signed"]},
                                       why="This source previously signed its frames and has now sent an unsigned frame."))
            elif self.expected and (ev.sysid == ctx.vehicle_sysid or ctx.is_trusted_gcs(ev.sysid)) and self._cool(("uns", key), ctx, 60):
                out.append(self.result(ctx, "ANOMALOUS", "Unsigned traffic while signing is expected", ev=ev,
                                       method="signature flag tracking", inputs={"sysid": ev.sysid, "compid": ev.compid, "msg": ev.msg_name},
                                       why="Configuration says signing is expected, but this frame is unsigned."))
        return out

    def state_for(self, key) -> str:
        s = self.src.get(key)
        if not s:
            return "SIGNING UNKNOWN"
        if s["invalid"]:
            return "INVALID SIGNATURE"
        if s["signed"] and not s["unsigned"]:
            return "VALID SIGNATURE" if self.key_configured else "SIGNED"
        if self.expected and s["unsigned"]:
            return "SIGNING EXPECTED"
        return "UNSIGNED" if s["unsigned"] else "SIGNING UNKNOWN"

    def table(self) -> list[dict]:
        return [{"sysid": k[0], "compid": k[1], **{kk: vv for kk, vv in v.items()}, "state": self.state_for(k)}
                for k, v in self.src.items()]

    def tick(self, ctx):
        self.metrics = {"expected": self.expected, "key_configured": self.key_configured,
                        "states": Counter(self.state_for(k) for k in self.src)}
        return []

    def _cool(self, key, ctx, s=10.0):
        if ctx.mono - self.cool.get(key, -1e9) < s:
            return False
        self.cool[key] = ctx.mono
        return True
