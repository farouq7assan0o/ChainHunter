"""Public Sigma benchmark: run SigmaHQ against real attack recordings on a schedule and publish the trend.

    chainhunter dashboard --sigma path/to/sigma --history benchmark/history --site site

Each run:
  * loads ChainHunter's rules + SigmaHQ's Windows and cloud rules
  * replays every per-technique recording in datasets/manifest.yml (detected = a medium+ alert fired)
  * replays every campaign (APT29, Golden SAML, ...): detections, incidents, top severity, sequences
  * writes benchmark/history/<date>_<sigma-version>.json
Then the static site is rebuilt from the *whole* history: detection rate over SigmaHQ versions, regressions
(rules that fired on a recording last run and don't now), new detections, per-recording and campaign tables.

A detection-rule regression is invisible in a rule repo's own CI (rules still parse, tests still pass); it only
shows up when the rules are replayed against real attack telemetry. That's what this tracks.
"""
from __future__ import annotations

import html
import json
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .bench import ALERT_LEVELS, _data_files, bench
from .correlate import correlate
from .detect import load_rules, run
from .ingest import load
from .sequence import run_sequences


def sigma_version(sigma: Path) -> str:
    try:
        out = subprocess.run(["git", "-C", str(sigma), "describe", "--tags", "--always"], capture_output=True,
                             text=True, timeout=30)
        return out.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _campaigns(manifest: Path) -> dict[str, list[Path]]:
    doc = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    groups: dict[str, list[Path]] = {}
    for e in doc["samples"]:
        if e.get("campaign"):
            parts = Path(e["path"]).parts
            name = ("/".join(parts[parts.index("compound") + 1:-1]) if "compound" in parts else Path(e["path"]).stem)
            groups.setdefault(name, []).extend(f for f in _data_files(manifest, e) if f.exists())
    return {k: v for k, v in groups.items() if v}


def run_campaign(rules, files: list[Path]) -> dict:
    size = sum(f.stat().st_size for f in files)
    if size > 50 * 1024 * 1024:  # big campaigns (APT29): DuckDB lake, same results as in-memory (parity-tested)
        import tempfile
        from .lake import Lake, build_lake, run_lake
        tmp = Path(tempfile.mkdtemp(prefix="ch-dash-"))
        build_lake(files, tmp)
        lk = Lake(tmp)
        sigs, _ = run_lake(rules, lk)
        from .cli import _aux_eids
        events, total = lk.events_for_eids(_aux_eids(rules)), lk.count()
    else:
        events = load(files)
        total = len(events)
        sigs = run(rules, events)
    seqs = run_sequences(rules, sigs, events)
    chains = correlate(sigs + seqs)
    alerting = [d for d in sigs if d.rule.level in ALERT_LEVELS]
    return {"events": total, "detections": len(alerting), "rules_fired": len({d.rule.id for d in alerting}),
            "incidents": len(chains), "top_severity": chains[0].severity if chains else "none",
            "sequences": sorted({d.rule.id for d in seqs})}


def run_dashboard(sigma: Path, manifest: Path, own_rules: Path) -> dict:
    dirs = [own_rules] + [p for p in (sigma / "rules" / "windows", sigma / "rules" / "cloud") if p.exists()]
    rules = load_rules(*dirs, quiet=True)
    results = bench(rules, manifest)
    samples = []
    for r in results:
        samples.append({"name": r.name, "events": r.events, "detected": bool(r.alerting) and not r.error,
                        "error": r.error, "rules": {rid: r.titles.get(rid, rid) for rid in sorted(r.alerting)}})
    det = sum(s["detected"] for s in samples)
    return {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sigma_version": sigma_version(sigma),
        "rules_loaded": len(rules),
        "samples": samples,
        "detected": det,
        "total": len(samples),
        "campaigns": {name: run_campaign(rules, files) for name, files in _campaigns(manifest).items()},
    }


def save(result: dict, history: Path) -> Path:
    history.mkdir(parents=True, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "-._" else "_" for c in result["sigma_version"])
    out = history / f"{result['generated'][:10]}_{safe}.json"
    out.write_text(json.dumps(result, indent=1, ensure_ascii=False), encoding="utf-8")
    return out


def load_history(history: Path) -> list[dict]:
    runs = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(history.glob("*.json"))]
    return sorted(runs, key=lambda r: r["generated"])


def diff(prev: dict, cur: dict) -> tuple[list, list]:
    """(regressions, new detections): (sample, rule id, title) fired before and not now / now and not before."""
    before = {s["name"]: s["rules"] for s in prev["samples"]}
    reg, new = [], []
    for s in cur["samples"]:
        old = before.get(s["name"], {})
        reg += [(s["name"], rid, t) for rid, t in old.items() if rid not in s["rules"]]
        new += [(s["name"], rid, t) for rid, t in s["rules"].items() if rid not in old]
    return reg, new


def render(runs: list[dict]) -> str:
    from .report import _CSS
    e = html.escape
    cur = runs[-1]
    prev = runs[-2] if len(runs) > 1 else None
    reg, new = diff(prev, cur) if prev else ([], [])
    # trend chart: detection rate per run
    W, H, L, B = 760, 220, 46, 34
    pts = [(r["detected"] / max(r["total"], 1) * 100) for r in runs]
    xs = [L + (i / max(len(runs) - 1, 1)) * (W - L - 20) for i in range(len(runs))]
    y = lambda v: H - B - v / 100 * (H - B - 16)
    poly = " ".join(f"{x:.0f},{y(v):.0f}" for x, v in zip(xs, pts))
    svg = [f"<svg viewBox='0 0 {W} {H}' class='lane' role='img' aria-label='Detection rate over SigmaHQ versions'>"]
    for v in (0, 25, 50, 75, 100):
        svg.append(f"<line class='tick' x1='{L}' x2='{W - 10}' y1='{y(v):.0f}' y2='{y(v):.0f}'/>"
                   f"<text class='ticklbl' x='{L - 8}' y='{y(v) + 4:.0f}' text-anchor='end'>{v}%</text>")
    svg.append(f"<polyline points='{poly}' fill='none' stroke='var(--host)' stroke-width='2.5'/>")
    for x, v, r in zip(xs, pts, runs):
        svg.append(f"<circle cx='{x:.0f}' cy='{y(v):.0f}' r='4.5' fill='var(--host)'><title>{e(r['sigma_version'])} · "
                   f"{e(r['generated'][:10])} · {r['detected']}/{r['total']}</title></circle>")
    svg.append(f"<text class='ticklbl' x='{L}' y='{H - 8}'>{e(runs[0]['sigma_version'])}</text>"
               f"<text class='ticklbl' x='{W - 10}' y='{H - 8}' text-anchor='end'>{e(cur['sigma_version'])}</text></svg>")
    p = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,"
         f"initial-scale=1'><title>Sigma Benchmark</title><style>{_CSS}"
         ".ok{color:var(--host);font-weight:700}.no{color:var(--crit);font-weight:700}a{color:var(--host)}"
         "</style></head><body><main>"
         f"<h1>Sigma Benchmark</h1><p class='muted'>SigmaHQ rules replayed against public recordings of real attacks, "
         f"every week, by <a href='https://github.com/farouq7assan0o/ChainHunter'>ChainHunter</a>. Latest run "
         f"{e(cur['generated'][:10])} · SigmaHQ {e(cur['sigma_version'])} · {cur['rules_loaded']:,} rules.</p><div class='stats'>"]
    for label, val in (("Recordings detected", f"{cur['detected']}/{cur['total']}"),
                       ("Detection rate", f"{cur['detected'] / max(cur['total'], 1):.0%}"),
                       ("Regressions vs last run", len(reg)), ("New detections vs last run", len(new)),
                       ("Runs tracked", len(runs))):
        p.append(f"<div class='stat'><b>{e(str(val))}</b><span class='muted'>{label}</span></div>")
    p.append("</div><section class='chain'><h2>Detection rate over SigmaHQ versions</h2>" + "".join(svg) + "</section>")
    p.append("<section class='chain'><h2>Changes since the previous run</h2>")
    if not prev:
        p.append("<p class='muted'>First run: changes appear from the next run on.</p>")
    elif not reg and not new:
        p.append("<p>No rule started or stopped firing on any recording.</p>")
    for title, rows, cls in (("Regressions: fired last run, not now", reg, "no"), ("New: fire now, didn't last run", new, "ok")):
        if rows:
            p.append(f"<h3>{title}</h3><div class='tbl'><table><tr><th>Recording</th><th>Rule</th></tr>"
                     + "".join(f"<tr><td>{e(s)}</td><td class='{cls}'>{e(t)}</td></tr>" for s, _, t in rows) + "</table></div>")
    p.append("</section><section class='chain'><h2>Campaigns</h2><div class='tbl'><table><tr><th>Campaign</th><th>Events</th>"
             "<th>Medium+ detections</th><th>Rules fired</th><th>Incidents</th><th>Top severity</th><th>Sequences</th></tr>")
    for name, c in cur["campaigns"].items():
        p.append(f"<tr><td>{e(name)}</td><td>{c['events']:,}</td><td>{c['detections']:,}</td><td>{c['rules_fired']}</td>"
                 f"<td>{c['incidents']}</td><td>{e(c['top_severity'])}</td><td>{e(', '.join(c['sequences']) or '-')}</td></tr>")
    p.append("</table></div></section><section class='chain'><h2>Per recording</h2><div class='tbl'><table>"
             "<tr><th>Recording</th><th>Detected</th><th>Rules that fired (medium+)</th></tr>")
    for s in cur["samples"]:
        rules = ", ".join(list(s["rules"].values())[:6]) + (f" … +{len(s['rules']) - 6}" if len(s["rules"]) > 6 else "")
        mark = "<span class='ok'>yes</span>" if s["detected"] else "<span class='no'>no</span>"
        p.append(f"<tr><td>{e(s['name'])}</td><td>{mark}</td><td class='muted'>{e(rules or s.get('error') or '-')}</td></tr>")
    p.append("</table></div></section><section class='chain'><h2>Method and caveats</h2><ul>"
             "<li>Recordings: EVTX-ATTACK-SAMPLES and OTRF Security-Datasets, fetched and SHA-256-verified at run time.</li>"
             "<li>“Detected” means at least one medium-or-higher alert fired on the recording. Some recordings were "
             "captured after the researcher cleared the logs, so a log-clearing alert can count as a detection.</li>"
             "<li>Rules run on ChainHunter's Sigma engine, with SigmaHQ Windows + cloud rules and ChainHunter's own pack. "
             "Rules needing telemetry the engine doesn't ingest (ETW) are skipped.</li>"
             "<li>A recording with 0 detections is not automatically a rule gap: some recordings capture only one "
             "side of an attack (e.g. the source host), so the evidence a rule would need isn't in them at all.</li>"
             "<li>This measures detection on attack data only. False-positive rates need labelled normal-activity data.</li>"
             "</ul></section></main></body></html>")
    return "".join(p)
