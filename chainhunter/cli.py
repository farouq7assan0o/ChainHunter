"""chainhunter — correlated attack-chain detection for Windows logs.

  chainhunter hunt <logs...>        ingest -> detect -> sequence -> anomaly -> correlate -> report
  chainhunter validate              lint rules, run embedded tests, show ATT&CK coverage
  chainhunter convert --to eql      compile rules to KQL / SPL / EQL
  chainhunter bench                 score rules against real attack recordings (datasets/)
  chainhunter blindspot <logs...>   which rules can actually fire on your telemetry, and what to enable
  chainhunter lake <logs...> -o DIR ingest into a Parquet lake; then `hunt --lake DIR` / `blindspot --lake DIR`
  chainhunter suppress add|list     analyst false-positive suppressions (scoped, expiring, audited)
  hunt ... --ai ollama:qwen2.5:3b   grounded AI draft (local); --ai claude for the Claude API
"""
from __future__ import annotations

import argparse
import sys
from datetime import timedelta
from pathlib import Path

from . import __version__
from .anomaly import detect_anomalies
from .bench import bench, markdown, summary, terminal
from .blindspot import analyse
from .blindspot import html_page as blindspot_html
from .blindspot import markdown as blindspot_md
from .convert import Unsupported, compile_rule
from .correlate import correlate
from .detect import load_rules, run
from .ingest import load
from .report import coverage_layer, html_report, json_export, markdown_report, navigator_layer
from .sequence import run_sequences
from .validate import coverage, validate

DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules"
COMMANDS = {"hunt", "validate", "convert", "bench", "blindspot", "lake", "suppress", "rulehealth", "watch"}


def _rules(args):
    return load_rules(*(args.rules or [DEFAULT_RULES]), verbose=args.list_skipped)


def _aux_eids(rules) -> set[int]:
    """Event types the non-signature stages need as raw events: anomaly auth events, Sysmon 1 for the process
    tree, and whatever inline sequence steps match on."""
    from .anomaly import AUTH_EVENTS
    from .detect import candidate_eids
    from .sequence import _inline_rule
    eids = set(AUTH_EVENTS) | {1}
    for r in rules:
        for step in r.meta.get("sequence", {}).get("steps", []) if r.kind == "sequence" else []:
            if "detection" in step:
                eids |= candidate_eids(_inline_rule(r, step)) or set()
    return eids


def cmd_hunt(a) -> int:
    rules = _rules(a)
    registry = {r.id: r for r in rules}
    if a.lake:
        import time
        from .lake import Lake, run_lake, run_lake_parallel
        t0 = time.time()
        lake = Lake(a.lake)
        total = lake.count()
        if a.workers > 1:
            signatures, lst = run_lake_parallel(rules, a.lake, a.workers, verbose=a.list_skipped)
        else:
            signatures, lst = run_lake(rules, lake, verbose=a.list_skipped)
        # only the event types and columns sequences/anomalies/process tree need - not full-width rows
        from .lake import CORE_FIELDS, rule_fields
        aux_fields = set(CORE_FIELDS)
        for r in rules:
            if r.kind == "sequence":
                for step in r.meta["sequence"]["steps"]:
                    if "detection" in step:
                        from .sequence import _inline_rule
                        aux_fields |= rule_fields(_inline_rule(r, step)) or set()
        events = lake.events_for_eids(_aux_eids(rules), aux_fields)
        print(f"[i] lake: {total:,} events | {lst['sql_rules']:,} rules as SQL, {lst['pruned_rules']:,} pruned (event "
              f"types absent), {lst['fallback_rules']} via Python fallback, {lst['skipped_rules']} skipped | "
              f"{lst['rows_returned']:,} candidate rows | "
              f"{time.time() - t0:.1f}s", file=sys.stderr)
    else:
        if not a.inputs:
            raise SystemExit("[x] give log files/folders, or --lake <dir>")
        events = load(a.inputs)
        total = len(events)
        signatures = run(rules, events)
    # sequences see every signature hit, *before* suppression: muting a noisy step can't hide the chain
    sequences = run_sequences(rules, signatures, events)
    suppressed = []
    if a.suppress:
        from . import suppress
        sups = suppress.load(a.suppress)
        signatures, suppressed = suppress.apply(signatures, sups)
        for line in suppress.summary(sups):
            print(line, file=sys.stderr)
    anomalies = [] if a.no_anomaly else detect_anomalies(events, a.baseline)
    detections = signatures + sequences + anomalies
    chains = [c for c in correlate(detections, timedelta(hours=a.window)) if c.score >= a.min_score]

    stats = {"events": total, "detections": len(signatures), "sequences": len(sequences), "anomalies": len(anomalies)}
    if suppressed:
        stats["suppressed"] = len(suppressed)
    ai_html = {}
    a.out.mkdir(parents=True, exist_ok=True)
    if a.ai and chains:
        from . import ai
        print(f"[i] AI analyst: drafting with {a.ai} (top {a.ai_top} incident(s))...", file=sys.stderr)
        analyses = ai.analyse(chains, a.ai, a.ai_top)
        (a.out / "ai_summary.md").write_text(ai.markdown(analyses), encoding="utf-8")
        for an in analyses:
            ai_html[an.chain_index] = ai.html_section(an)
            if an.error:
                print(f"[!] AI analyst: {an.error}", file=sys.stderr)
            else:
                ok, n = ai.score(an.verified)
                print(f"[+] AI analyst: incident {an.chain_index + 1}: {ok}/{n} claims grounded in cited evidence",
                      file=sys.stderr)
    (a.out / "report.md").write_text(markdown_report(chains, registry, a.title), encoding="utf-8")
    (a.out / "report.html").write_text(html_report(chains, registry, stats, events, ai_html), encoding="utf-8")
    (a.out / "attack_layer.json").write_text(navigator_layer(chains), encoding="utf-8")
    (a.out / "incidents.json").write_text(json_export(chains), encoding="utf-8")

    print(f"[+] {total:,} events | {len(rules)} rules | {len(signatures)} signature hits | "
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


def _analysis_input(a, rules):
    """(events, signatures, profile, total) from raw logs, or from a lake (signatures via DuckDB)."""
    if getattr(a, "lake", None):
        from .lake import Lake, lake_profile, run_lake
        lake = Lake(a.lake)
        sigs, _ = run_lake(rules, lake)
        return lake.events_for_eids(_aux_eids(rules)), sigs, lake_profile(lake), lake.count()
    if not a.inputs:
        raise SystemExit("[x] give log files/folders, or --lake <dir>")
    events = load(a.inputs)
    return events, None, None, len(events)


def cmd_rulehealth(a) -> int:
    from .impact import health_markdown, rule_health
    rules = _rules(a)
    events, sigs, prof, total = _analysis_input(a, rules)
    bench_results = bench(rules, a.manifest) if a.bench else None
    rows = rule_health(rules, events, bench_results, a.loud, prof, sigs)
    md = health_markdown(rows, total)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(md, encoding="utf-8")
    from collections import Counter
    c = Counter(h.verdict for h in rows)
    print(f"[+] {len(rows):,} rules on {total:,} events: {c['TRUST']} TRUST | {c['TUNE']} TUNE | {c['DEAD']} DEAD | "
          f"{c['UNPROVEN']} UNPROVEN")
    for h in [h for h in rows if h.verdict == "TUNE"][:10]:
        print(f"    TUNE  {h.rule.title}: {h.why}")
    print(f"[+] Wrote {a.out}")
    return 0


def cmd_suppress(a) -> int:
    from . import suppress
    if a.action == "impact":
        from .impact import impact_text, simulate
        if a.rule:
            cand = [suppress.Suppression("candidate", a.rule, dict(w.partition("=")[::2] for w in (a.where or [])),
                                         a.reason or "(candidate)", "", "", None, a.allow_critical)]
        else:
            cand = suppress.load(a.file)
        rules = _rules(a)
        events, sigs, _, _ = _analysis_input(a, rules)
        rep = simulate(rules, events, cand, signatures=sigs)
        print(impact_text(rep, cand))
        return 1 if rep.verdict == "RISKY" else 0
    if a.action == "add":
        if not (a.rule and a.reason):
            raise SystemExit("[x] suppress add needs --rule and --reason")
        s = suppress.add(a.file, a.rule, a.where or [], a.reason, a.expires, a.allow_critical)
        print(f"[+] {s.id} added to {a.file}: {s.rule} where {s.where or '{}'} (expires {s.expires or 'never'})")
        if not s.expires:
            print("[!] no --expires: suppressions without an end date tend to outlive the reason for them")
        return 0
    for s in suppress.load(a.file):
        state = "IGNORED" if s.problems else "expired" if s.expired else "active"
        print(f"{s.id}  {state:<8} {s.rule}  where={s.where}  by {s.author} {s.created} -> {s.expires or 'never'}  "
              f"[{s.reason}]" + (f"  ({'; '.join(s.problems)})" if s.problems else ""))
    return 0


def cmd_watch(a) -> int:
    from .watch import DEFAULT_CHANNELS, Engine, ReplaySource, WindowsSource, watch
    rules = _rules(a)
    if a.replay:
        src = ReplaySource(a.replay, a.interval, a.speed)
        print(f"[i] replaying {len(src.events):,} events at {a.speed:g}x (Ctrl+C to stop)")
    else:
        src = WindowsSource(a.channel or DEFAULT_CHANNELS, a.backfill)
        ok = [c for c in src.channels if c not in src.problems]
        print(f"[i] watching {len(ok)} channel(s): {', '.join(ok) or 'none'} every {a.interval:g}s (Ctrl+C to stop)")
    eng = Engine(rules, timedelta(hours=a.window), a.min_level)
    c = watch(src, eng, 0 if a.replay else a.interval, a.alerts)
    print(f"[+] {c['events']:,} events, {c['alerts']} alerts, {c['incidents']} incident(s)")
    return 0


def cmd_lake(a) -> int:
    from .lake import build_lake
    s = build_lake(a.inputs, a.out, chunk=a.chunk)
    print(f"[+] lake: {s['events']:,} events from {s['files']} file(s) -> {s['chunks']} Parquet chunk(s), "
          f"{s['bytes'] / 1048576:.1f} MB (zstd) in {s['seconds']}s")
    print(f"    hunt it:      python -m chainhunter hunt --lake {a.out} -r rules")
    print(f"    blindspot it: python -m chainhunter blindspot --lake {a.out} -r rules")
    return 0


def cmd_blindspot(a) -> int:
    if a.lake:
        from .lake import Lake, lake_profile
        p = lake_profile(Lake(a.lake))
        res = analyse(_rules(a), [], p)
        total = p.events
    else:
        if not a.inputs:
            raise SystemExit("[x] give log files/folders, or --lake <dir>")
        events = load(a.inputs)
        res = analyse(_rules(a), events)
        total = len(events)
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "blindspot.md").write_text(blindspot_md(res), encoding="utf-8")
    (a.out / "blindspot.html").write_text(blindspot_html(res), encoding="utf-8")
    live_t, unv_t, blind_t = res.techniques
    n = max(len(res.viability), 1)
    print(f"[+] {total:,} events profiled | {len(res.viability):,} rules")
    print(f"    can fire {len(res.live):,} ({len(res.live) / n:.0%}) | unverified {len(res.unobserved):,} | "
          f"dead: source missing {len(res.dead_events):,} | dead: field empty {len(res.dead_fields):,}")
    print(f"    ATT&CK techniques: {len(live_t)} detectable | {len(unv_t)} unverified | {len(blind_t)} blind")
    print("    Top telemetry fixes (proven gaps):")
    for i, r in enumerate(res.recs[:5], 1):
        print(f"      {i}. {r.action}  -> +{len(r.revives)} rules, +{len(r.techniques - live_t)} techniques")
    for issue in res.issues[:8]:
        print(f"    ! {issue.kind}: {issue.host} {issue.channel} - {issue.detail}")
    print(f"[+] Wrote {a.out / 'blindspot.html'} and blindspot.md")
    return 0


def cmd_bench(a) -> int:
    results = bench(_rules(a), a.manifest)
    md = markdown(results)
    print(terminal(results))
    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(md, encoding="utf-8")
        print(f"[+] Wrote {a.out}")
    s = summary(results)
    return 1 if s["errors"] or s["labelled_hits"] < s["labelled_expectations"] or s["benign_with_fp"] else 0


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
    common.add_argument("--list-skipped", action="store_true", help="list each rule skipped for unsupported features")

    h = sub.add_parser("hunt", parents=[common], help="analyse logs")
    h.add_argument("inputs", nargs="*", type=Path, help="EVTX / JSON / JSONL files or directories")
    h.add_argument("--lake", type=Path, help="hunt a Parquet lake (built with `chainhunter lake`) via DuckDB")
    h.add_argument("--workers", type=int, default=1, help="lake mode: fan lake files out to N processes")
    h.add_argument("-o", "--out", type=Path, default=Path("out"))
    h.add_argument("-w", "--window", type=float, default=6, help="correlation window, hours")
    h.add_argument("--baseline", type=float, default=0.25, help="fraction of time span used as UEBA baseline")
    h.add_argument("--no-anomaly", action="store_true")
    h.add_argument("--min-score", type=int, default=0, help="suppress incidents below this score")
    h.add_argument("--title", default="Security Incident Report")
    h.add_argument("--ai", metavar="BACKEND", help="grounded AI draft: ollama:qwen2.5:3b (local) or claude[:MODEL]")
    h.add_argument("--ai-top", type=int, default=3, help="how many top incidents the AI drafts (default 3)")
    h.add_argument("--suppress", type=Path, metavar="FILE", help="analyst false-positive suppressions (YAML)")
    h.set_defaults(fn=cmd_hunt)

    v = sub.add_parser("validate", parents=[common], help="lint + test rules, ATT&CK coverage")
    v.add_argument("-v", "--verbose", action="store_true", help="show warnings")
    v.add_argument("--navigator", type=Path, help="write coverage Navigator layer")
    v.set_defaults(fn=cmd_validate)

    c = sub.add_parser("convert", parents=[common], help="compile rules to SIEM queries")
    c.add_argument("--to", choices=["kql", "spl", "eql"], required=True)
    c.add_argument("--id", action="append", help="only these rule ids")
    c.set_defaults(fn=cmd_convert)

    s = sub.add_parser("blindspot", parents=[common], help="which rules can actually fire on your telemetry")
    s.add_argument("inputs", nargs="*", type=Path, help="EVTX / JSON / JSONL files or directories")
    s.add_argument("--lake", type=Path, help="profile a Parquet lake inside DuckDB instead of loading raw logs")
    s.add_argument("-o", "--out", type=Path, default=Path("out/blindspot"))
    s.set_defaults(fn=cmd_blindspot)

    sp = sub.add_parser("suppress", parents=[common], help="manage analyst false-positive suppressions")
    sp.add_argument("action", choices=["add", "list", "impact"])
    sp.add_argument("inputs", nargs="*", type=Path, help="impact: logs to replay against")
    sp.add_argument("--lake", type=Path, help="impact: replay against a Parquet lake")
    sp.add_argument("-f", "--file", type=Path, default=Path("suppressions.yml"))
    sp.add_argument("--rule", help="rule id or exact title")
    sp.add_argument("--where", action="append", help="condition key=value (wildcards ok); host/actor/source or any field")
    sp.add_argument("--reason")
    sp.add_argument("--expires", help="YYYY-MM-DD or Nd (e.g. 90d)")
    sp.add_argument("--allow-critical", action="store_true", help="permit suppressing a critical-severity rule")
    sp.set_defaults(fn=cmd_suppress)

    w = sub.add_parser("watch", parents=[common], help="live mode: detect and correlate as events arrive")
    w.add_argument("--channel", action="append", help="Windows channel to watch (repeatable)")
    w.add_argument("--interval", type=float, default=10, help="seconds between polls")
    w.add_argument("--backfill", type=int, default=0, help="also process the last N minutes on start")
    w.add_argument("--replay", type=Path, nargs="+", help="stream a recording instead of live logs")
    w.add_argument("--speed", type=float, default=60, help="replay speed multiplier")
    w.add_argument("--window", type=float, default=6, help="correlation window, hours")
    w.add_argument("--min-level", default="medium", choices=["informational", "low", "medium", "high", "critical"])
    w.add_argument("--alerts", type=Path, help="append alerts as JSON lines to this file")
    w.set_defaults(fn=cmd_watch)

    rh = sub.add_parser("rulehealth", parents=[common], help="per-rule verdict: TRUST / TUNE / DEAD / UNPROVEN")
    rh.add_argument("inputs", nargs="*", type=Path, help="logs (ideally normal activity) to measure noise on")
    rh.add_argument("--lake", type=Path)
    rh.add_argument("--bench", action="store_true", help="also replay the real attack recordings for evidence")
    rh.add_argument("--manifest", type=Path, default=DEFAULT_RULES.parent / "datasets" / "manifest.yml")
    rh.add_argument("--loud", type=float, default=500.0, help="alerts per million events that counts as noisy")
    rh.add_argument("-o", "--out", type=Path, default=Path("out/rulehealth.md"))
    rh.set_defaults(fn=cmd_rulehealth)

    lk = sub.add_parser("lake", help="ingest logs into a Parquet lake for DuckDB-scale hunting")
    lk.add_argument("inputs", nargs="+", type=Path, help="EVTX / JSON / JSONL files or directories")
    lk.add_argument("-o", "--out", type=Path, default=Path("lake"))
    lk.add_argument("--chunk", type=int, default=250_000, help="events per Parquet chunk (bounds memory)")
    lk.set_defaults(fn=cmd_lake)

    b = sub.add_parser("bench", parents=[common], help="score rules against real attack recordings")
    b.add_argument("--manifest", type=Path, default=DEFAULT_RULES.parent / "datasets" / "manifest.yml")
    b.add_argument("-o", "--out", type=Path, help="write the markdown results here")
    b.set_defaults(fn=cmd_bench)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
