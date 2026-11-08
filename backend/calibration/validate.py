"""Run one candidate on a fresh held-out flight seed range."""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from .sweep import make_jobs, parse_set, run_jobs, summarize


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--benign", type=int, default=500)
    ap.add_argument("--attack", type=int, default=40)
    ap.add_argument("--seed", type=int, required=True, help="fresh root seed in the held-out range")
    ap.add_argument("--harsh", type=float, required=True)
    ap.add_argument("--workers", type=int, default=14)
    ap.add_argument("--extended", action="store_true")
    ap.add_argument("--boundary-attacks", action="store_true", help="use boundary-strength attacks for ROC data")
    ap.add_argument("--duration-min", type=int, default=120)
    ap.add_argument("--duration-max", type=int, default=300)
    ap.add_argument("--set", nargs="*", default=[], help="candidate config override dotted.key=value")
    ap.add_argument("--patches", nargs="*",
                    choices=("rc_radio", "gps_cusum_clip", "trusted_cmd_rule", "trusted_edits_observed"), default=[])
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    overrides = parse_set(args.set)
    jobs = make_jobs(args.benign, args.attack, args.seed, overrides, args.harsh,
                     patches=args.patches, duration_range=(args.duration_min, args.duration_max),
                     extended=args.extended, boundary_attacks=args.boundary_attacks)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    checkpoint = out_path.with_name(f"{out_path.name}.{time.time_ns()}.partial.jsonl")
    started = time.time()
    results = run_jobs(jobs, args.workers, checkpoint)
    summary = summarize(results)
    summary["meta"] = {"runs": len(jobs), "seconds": round(time.time() - started, 1), "overrides": overrides,
                        "patches": args.patches, "seed": args.seed, "harsh": args.harsh,
                        "extended": args.extended, "boundary_attacks": args.boundary_attacks,
                        "duration_range": [args.duration_min, args.duration_max],
                        "validation": "held-out"}
    out_path.write_text(json.dumps({"summary": summary, "results": results}, default=list, indent=1), encoding="utf-8")
    checkpoint.unlink(missing_ok=True)
    print(json.dumps(summary, default=list, indent=1), flush=True)


if __name__ == "__main__":
    main()
