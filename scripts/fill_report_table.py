#!/usr/bin/env python3
"""Fill the TC-01..TC-06 table of the Stage-1 report template from validation/results.json.
Writes a NEW file next to the template (the template is never modified) and validation/summary.md."""
import json
import statistics
import sys
from pathlib import Path

from docx import Document
from docx.shared import Pt

ROOT = Path(__file__).resolve().parents[1]
res = json.loads((ROOT / "validation" / "results.json").read_text())
template = Path(sys.argv[1] if len(sys.argv) > 1 else "/Users/arbaazdhillon/Desktop/GC-3_Security_Objective 2_Report_Template.docx")
out_path = template.with_name(template.stem + " - TC filled.docx")


def rng(d):
    return f"median {d['median']} s (range {d['min']}–{d['max']} s)" if d else "N/A"


def verdict(t):
    s, runs = t["summary"], t["runs"]
    n = len(runs)
    if t["benign"]:
        return s["pass"], (f"Result ({n} varied simulated runs): {s['ground_false_positive_alerts']} ground false alerts, "
                           f"{s['false_incidents']} incidents, {s['lua_false_alarms']} Lua SUSPECTED/CONFIRMED.")
    inc_lat = [r["incident"]["latency_s"] for r in runs if r["incident"]]
    det = sum(r["ground_detected"] for r in runs)
    inc = sum(1 for r in runs if r["incident"])
    lua_c = sum(1 for r in runs if r["lua_state"] == "CONFIRMED")
    lua_d = sum(1 for r in runs if r["lua_state"])
    tid = t["id"]
    if tid == "TC-02":
        ok = det == n and inc == n and lua_c == n and max(r["ground_latency_s"] for r in runs) <= 5
    elif tid == "TC-03":
        ok = det == n and all(r["incident"] and r["incident"]["state"] == "CONFIRMED" and r["incident"]["latency_s"] <= 5 for r in runs) and lua_d == n
    elif tid in ("TC-04", "TC-06"):
        ok = det == n and inc == n and lua_c == n and max(r["ground_latency_s"] for r in runs) <= 2 + 2  # attack starts at +2 s
    elif tid == "TC-05":
        ok = det == n and lua_c == n and max(r["ground_latency_s"] for r in runs) < 26 and max(r["lua_latency_s"] for r in runs) <= 50
    else:
        ok = det == n
    states = ", ".join(f"{k} {v}" for k, v in sorted(s["incident_states"].items()))
    lua_txt = f"Lua {t['lua']} CONFIRMED {lua_c}/{n}" + (f" (≥SUSPECTED {lua_d}/{n})" if lua_c < n else "")
    txt = (f"Result ({n} varied simulated runs, magnitude m∈[0.6,1.4], injection 35–60 s): ground detection {det}/{n}, "
           f"first alert {rng(s['ground_latency_s'])} after injection; incident {inc}/{n} ({states}), "
           f"incident latency median {round(statistics.median(inc_lat), 2) if inc_lat else 'N/A'} s; {lua_txt}, {rng(s['lua_latency_s'])}; "
           f"Lua output received by GCS as MAVLink STATUSTEXT; false alerts before injection: {s['false_alerts_before_injection']}.")
    return ok, txt


doc = Document(str(template))
tbl = doc.tables[1]
md = ["# Stage-1 attack / validation table (SIMULATED data)", "",
      f"Generated {res['generated']} by `scripts/run_validation.py` ({res['runs_per_test']} runs per test, master seed {res['master_seed']}).", "",
      "| Test ID | Attack Scenario | Data Source | Expected IDS Observation | Detection Indicator / Success Criteria | Verdict |",
      "|---|---|---|---|---|---|"]
for i, t in enumerate(res["tests"], start=1):
    ok, result = verdict(t)
    cells = tbl.rows[i].cells
    cells[0].text = t["id"]
    cells[1].text = t["attack"]
    cells[2].text = t["sources"]
    cells[3].text = t["expected"]
    cells[4].text = f"Criteria: {t['criteria']}.\n{result}\nVerdict: {'PASS' if ok else 'FAIL'} (simulated)."
    for c in cells:
        for p in c.paragraphs:
            for r in p.runs:
                r.font.size = Pt(8)
    md.append(f"| {t['id']} | {t['attack']} | {t['sources']} | {t['expected']} | {t['criteria']}. {result} | {'PASS' if ok else 'FAIL'} |")

note = doc.add_paragraph()
note.add_run("Note on TC-01 to TC-06: ").bold = True
note.add_run(
    "Results above are from SIMULATED data, not flight or HIL tests. Each test case was run 10 times with a different random seed "
    "(sensor noise), attack magnitude m drawn from U(0.6, 1.4) and injection time from U(35 s, 60 s). Synthetic MAVLink v2 frames were "
    "generated with pymavlink for an ArduCopter vehicle, a GCS and an attacker (SYSID 42). The eight PUSHPAK Lua confirmation scripts "
    "(corrected for the ArduCopter 4.7.1 dbe79216 Pixhawk 6C binding) ran under Lua 5.4 against the simulated vehicle state, using only "
    "binding methods present in the firmware. Their gcs:send_text() output was encoded as MAVLink STATUSTEXT from the vehicle, so Lua "
    "detections reached the ground IDS exactly as on hardware. The ground IDS (17 detectors, 4 published rules, correlation engine) "
    "analysed the combined stream. Latencies are measured from the scenario injection point in simulation time; in TC-03, TC-04 and TC-06 the attacker's first packet is sent 2 s after that point, and in TC-05 the RC receiver losses occur at +26, +36 and +46 s. TC-03: Lua cannot see packet "
    "provenance on this firmware, so it reports SUSPECTED from mode-change context and rate, while the ground IDS confirms. "
    "Raw evidence: validation/results.json; replayable captures data/captures/VAL-TC-0x.tlog.")
tbl._element.addnext(note._element)
doc.save(str(out_path))
(ROOT / "validation" / "summary.md").write_text("\n".join(md) + "\n")
print(out_path)
