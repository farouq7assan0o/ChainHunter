"""chainhunter — correlated attack-chain detection for Windows logs.

  chainhunter hunt <logs...>        ingest -> detect -> sequence -> anomaly -> correlate -> report
  chainhunter validate              lint rules, run embedded tests, show ATT&CK coverage
  chainhunter convert --to eql      compile rules to KQL / SPL / EQL
"""
from __future__ import annotations

import argparse
import sys
from datetime import timedelta
from pathlib import Path

from . import __version__
from .anomaly import detect_anomalies
from .convert import Unsupported, compile_rule
from .correlate import correlate
from .detect import load_rules, run
from .ingest import load
from .report import coverage_layer, html_report, json_export, markdown_report, navigator_layer
from .sequence import run_sequences
from .validate import coverage, validate

DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules"
COMMANDS = {"hunt", "validate", "convert"}


def _rules(args):
    return load_rules(*(args.rules or [DEFAULT_RULES]))


def cmd_hunt(a) -> int:
    events = load(a.inputs)
    rules = _rules(a)
    registry = {r.id: r for r in rules}
    signatures = run(rules, events)
    sequences = run_sequences(rules, signatures, events)
    anomalies = [] if a.no_anomaly else detect_anomalies(events, a.baseline)
    detections = signatures + sequences + anomalies
    chains = [c for c in correlate(detections, timedelta(hours=a.window)) if c.score >= a.min_score]

    stats = {"events": len(events), "detections": len(signatures), "sequences": len(sequences), "anomalies": len(anomalies)}
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "report.md").write_text(markdown_report(chains, registry, a.title), encoding="utf-8")
    (a.out / "report.html").write_text(html_report(chains, registry, stats), encoding="utf-8")
    (a.out / "attack_layer.json").write_text(navigator_layer(chains), encoding="utf-8")
    (a.out / "incidents.json").write_text(json_export(chains), encoding="utf-8")

    print(f"[+] {len(events)} events | {len(rules)} rules | {len(signatures)} signature hits | "
          f"{len(sequences)} sequences | {len(anomalies)} anomalies | {len(chains)} incident(s)")
    for i, c in enumerate(chains, 1):
        print(f"    Incident {i}: {c.severity:<8} score={c.score:<4} {' -> '.join(c.phases)}")
        for r in (r for r in c.risk if r.flagged):
            print(f"      ! {r.kind:<7} {r.value:<40} risk={r.score:<4} {', '.join(sorted(r.techniques))}")
    print(f"[+] Wrote {a.out}/report.md, report.html, attack_layer.json, incidents.json")
    return 0


def cmd_validate(a) -> int:
    rules = _rules(a)
    results = validate(rules)
    bad = 0
    for r in results:
        status = "FAIL" if r.errors else "ok  "
        bad += bool(r.errors)
        print(f"[{status}] {r.rule.id:<9} {r.rule.kind:<9} tests {r.passed}/{r.passed + r.failed}  {r.rule.title}")
        for msg in r.errors:
            print(f"         x {msg}")
        if a.verbose:
            for msg in r.warnings:
                print(f"         ~ {msg}")
    print("\nATT&CK coverage:")
    for tactic, techs in coverage(rules).items():
        print(f"  {tactic:<22} {', '.join(techs)}")
    if a.navigator:
        a.navigator.write_text(coverage_layer(rules), encoding="utf-8")
        print(f"\n[+] Coverage layer -> {a.navigator}")
    tests = sum(r.passed + r.failed for r in results)
    print(f"\n{len(results) - bad}/{len(results)} rules valid · {sum(r.passed for r in results)}/{tests} tests passed")
    return 1 if bad else 0


def cmd_convert(a) -> int:
    rules = _rules(a)
    registry = {r.id: r for r in rules}
    for r in rules:
        if a.id and r.id not in a.id:
            continue
        try:
            q = compile_rule(r, a.to, registry)
        except Unsupported as e:
            q = f"-- not translatable: {e}"
        print(f"# {r.id} — {r.title}\n{q}\n")
    return 0


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in COMMANDS and not argv[0].startswith("-"):
        argv.insert(0, "hunt")  # `chainhunter logs/` still works

    p = argparse.ArgumentParser(prog="chainhunter", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-r", "--rules", type=Path, action="append", help="rules dir (repeatable; e.g. add SigmaHQ rules/windows)")

    h = sub.add_parser("hunt", parents=[common], help="analyse logs")
    h.add_argument("inputs", nargs="+", type=Path, help="EVTX / JSON / JSONL files or directories")
    h.add_argument("-o", "--out", type=Path, default=Path("out"))
    h.add_argument("-w", "--window", type=float, default=6, help="correlation window, hours")
    h.add_argument("--baseline", type=float, default=0.25, help="fraction of time span used as UEBA baseline")
    h.add_argument("--no-anomaly", action="store_true")
    h.add_argument("--min-score", type=int, default=0, help="suppress incidents below this score")
    h.add_argument("--title", default="Security Incident Report")
    h.set_defaults(fn=cmd_hunt)

    v = sub.add_parser("validate", parents=[common], help="lint + test rules, ATT&CK coverage")
    v.add_argument("-v", "--verbose", action="store_true", help="show warnings")
    v.add_argument("--navigator", type=Path, help="write coverage Navigator layer")
    v.set_defaults(fn=cmd_validate)

    c = sub.add_parser("convert", parents=[common], help="compile rules to SIEM queries")
    c.add_argument("--to", choices=["kql", "spl", "eql"], required=True)
    c.add_argument("--id", action="append", help="only these rule ids")
    c.set_defaults(fn=cmd_convert)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
