"""chainhunter CLI: ingest -> detect -> correlate -> report."""
from __future__ import annotations

import argparse
from datetime import timedelta
from pathlib import Path

from . import __version__
from .correlate import correlate
from .detect import load_rules, run
from .ingest import load
from .report import html_report, markdown_report, navigator_layer

DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="chainhunter", description=__doc__)
    p.add_argument("inputs", nargs="+", type=Path, help="EVTX / JSON / JSONL files or directories")
    p.add_argument("-r", "--rules", type=Path, default=DEFAULT_RULES, help="rules directory")
    p.add_argument("-o", "--out", type=Path, default=Path("out"), help="output directory")
    p.add_argument("-w", "--window", type=float, default=6, help="correlation window in hours")
    p.add_argument("--title", default="Security Incident Report")
    p.add_argument("--version", action="version", version=__version__)
    a = p.parse_args(argv)

    events = load(a.inputs)
    rules = load_rules(a.rules)
    detections = run(rules, events)
    chains = correlate(detections, timedelta(hours=a.window))

    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "report.md").write_text(markdown_report(chains, a.title), encoding="utf-8")
    (a.out / "timeline.html").write_text(html_report(chains), encoding="utf-8")
    (a.out / "attack_layer.json").write_text(navigator_layer(chains), encoding="utf-8")

    print(f"[+] {len(events)} events | {len(rules)} rules | {len(detections)} detections | {len(chains)} chain(s)")
    for i, c in enumerate(chains, 1):
        print(f"    Incident {i}: {c.severity:<8} score={c.score:<3} {' -> '.join(c.phases)}")
    print(f"[+] Wrote {a.out / 'report.md'}, timeline.html, attack_layer.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
