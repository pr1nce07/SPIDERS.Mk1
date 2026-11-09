#!/usr/bin/env python3
"""Evaluate SPIDERS detectors on a labelled flight corpus (GAP-02).

    python scripts/evaluate_detectors.py corpus.json --partition tune validation --out reports/eval

The locked test partition is refused unless --frozen-config matches the current
detector configuration fingerprint (print it with --fingerprint). Freeze the
configuration first, record the fingerprint, then run the locked set once.
See docs/validation/dataset_card_template.md for the corpus manifest format.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.config import Config  # noqa: E402
from app.evaluation import PARTITIONS, config_fingerprint, load_corpus, markdown, replay, score  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("corpus", nargs="?", help="corpus manifest JSON")
    ap.add_argument("--partition", nargs="+", default=["tune", "validation"], choices=PARTITIONS)
    ap.add_argument("--frozen-config", help="required for --partition locked: the frozen config fingerprint")
    ap.add_argument("--fingerprint", action="store_true", help="print the current config fingerprint and exit")
    ap.add_argument("--tolerance", type=float, default=2.0, help="seconds of slack around attack windows")
    ap.add_argument("--out", default="reports/evaluation", help="output prefix (writes .json and .md)")
    a = ap.parse_args()

    cfg = Config.load()
    fp = config_fingerprint(cfg)
    if a.fingerprint:
        print(fp)
        return 0
    if not a.corpus:
        ap.error("corpus manifest required")
    if "locked" in a.partition and a.frozen_config != fp:
        print("refusing to evaluate the locked partition: --frozen-config does not match the current configuration "
              f"fingerprint {fp}. Freeze thresholds/rules first; never tune on the locked set.", file=sys.stderr)
        return 2
    doc, runs = load_corpus(Path(a.corpus))
    runs = [r for r in runs if r.partition in a.partition]
    if not runs:
        print("no runs in the selected partitions", file=sys.stderr)
        return 1
    results = []
    for r in runs:
        print(f"replaying {r.run_id} ({r.label}, {r.partition}) …", file=sys.stderr)
        results.append(replay(r, cfg))
    report = {"corpus": doc.get("corpus_id", Path(a.corpus).name), "dataset_card": doc.get("dataset_card"),
              "generated_at": datetime.now(timezone.utc).isoformat(), "partitions": a.partition,
              "config_fingerprint": fp, "score": score(results, a.tolerance)}
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.with_suffix(".json").write_bytes(json.dumps(report, indent=2, default=str).encode("utf-8"))
    out.with_suffix(".md").write_bytes(markdown(report).encode("utf-8"))
    print(f"wrote {out.with_suffix('.json')} and {out.with_suffix('.md')}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
