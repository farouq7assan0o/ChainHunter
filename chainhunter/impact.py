"""Tuning without going blind: suppression impact simulation and rule health.

    chainhunter suppress impact <logs> -r rules --rule "..." --where host=X    # before approving a suppression
    chainhunter suppress impact <logs> -r rules -f suppressions.yml            # audit the whole file
    chainhunter rulehealth <logs> -r rules [--bench]                           # which rules to trust / fix / delete

Suppression impact replays the full pipeline with and without the candidate suppression(s) and reports what an
analyst would lose - not just "N alerts hidden", but whether the suppression would hide an incident's earliest
alert, a host's first sign of compromise, or an entire kill-chain phase, and whether incident severity drops.

Rule health puts four signals on one row per rule:
  * can it fire here?        Blindspot viability on this telemetry
  * does it catch attacks?   hits on the real attack recordings (bench), when --bench is given
  * how loud is it?          alerts per million events on these logs
  * is it tested?            embedded match/nomatch cases
and turns them into a verdict: TRUST / TUNE / DEAD / UNPROVEN.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

from .anomaly import detect_anomalies
from .correlate import ALERT_LEVELS, Chain, correlate
from .detect import Detection, Rule, run
from .sequence import run_sequences
from .story import short_host
from . import suppress as sup


def pipeline(rules: list[Rule], events: list[dict], signatures: list[Detection] | None = None):
    sigs = signatures if signatures is not None else run(rules, events)
    return sigs, run_sequences(rules, sigs, events), detect_anomalies(events)


# ---------- suppression impact ----------

@dataclass
class IncidentImpact:
    index: int
    severity_before: str
    severity_after: str
    hidden: list[Detection]
    losses: list[str] = field(default_factory=list)


@dataclass
class ImpactReport:
    hidden_total: int
    by_suppression: Counter
    incidents: list[IncidentImpact]

    @property
    def verdict(self) -> str:
        if any(i.losses for i in self.incidents):
            return "RISKY"
        return "SAFE" if self.hidden_total else "NO EFFECT"


def simulate(rules: list[Rule], events: list[dict], sups: list[sup.Suppression],
             window: timedelta = timedelta(hours=6), signatures: list[Detection] | None = None) -> ImpactReport:
    sigs, seqs, anoms = pipeline(rules, events, signatures)
    before = correlate(sigs + seqs + anoms, window)
    kept, hidden = sup.apply(list(sigs), sups)
    hidden_ids = {id(d) for d in hidden}
    by_sup = Counter(d.extra.get("suppressed_by") for d in hidden)
    incidents = []
    for i, c in enumerate(before, 1):
        lost = [d for d in c.detections if id(d) in hidden_ids]
        if not lost:
            continue
        remaining = [d for d in c.detections if id(d) not in hidden_ids]
        after = Chain(remaining, {}, []) if remaining else None
        imp = IncidentImpact(i, c.severity, after.severity if after else "(incident disappears)", lost)
        story = [d for d in c.detections if d.rule.level in ALERT_LEVELS and d.rule.kind != "sequence"]
        if story and id(min(story, key=lambda d: d.time)) in hidden_ids:
            imp.losses.append(f"hides the incident's earliest alert ({min(story, key=lambda d: d.time).rule.title})")
        first_by_host: dict[str, Detection] = {}
        for d in sorted(story, key=lambda d: d.time):
            first_by_host.setdefault(short_host(d.host), d)
        for h, d in first_by_host.items():
            if id(d) in hidden_ids:
                imp.losses.append(f"hides the first sign of compromise on {h} ({d.rule.title})")
        phases_before = {d.rule.meta.get("kill_chain") for d in story}
        phases_after = {d.rule.meta.get("kill_chain") for d in story if id(d) not in hidden_ids}
        for ph in sorted(p for p in phases_before - phases_after if p):
            imp.losses.append(f"removes the '{ph}' phase from the incident entirely")
        if not remaining:
            imp.losses.append("the whole incident disappears")
        elif after.severity != c.severity:
            imp.losses.append(f"incident severity drops {c.severity} -> {after.severity}")
        incidents.append(imp)
    return ImpactReport(len(hidden), by_sup, incidents)


def impact_text(rep: ImpactReport, sups: list[sup.Suppression]) -> str:
    lines = [f"Suppression impact: {rep.verdict} - {rep.hidden_total} alert(s) would be hidden"]
    for s in sups:
        state = "ignored: " + "; ".join(s.problems) if s.problems else "expired" if s.expired else f"{rep.by_suppression.get(s.id, 0)} hidden"
        lines.append(f"  {s.id}  {s.rule}  where={s.where or '{}'}  -> {state}")
    for inc in rep.incidents:
        lines.append(f"  Incident {inc.index} ({inc.severity_before} -> {inc.severity_after}): {len(inc.hidden)} alert(s) hidden")
        for loss in inc.losses:
            lines.append(f"    ! {loss}")
    if rep.verdict == "RISKY":
        lines.append("  => Narrow the scope (add --where conditions) or don't approve: it hides evidence an analyst needs.")
    elif rep.verdict == "SAFE":
        lines.append("  => Hides alerts without removing an incident's first sign, a host's first sign, or a phase.")
    return "\n".join(lines)


# ---------- rule health ----------

@dataclass
class RuleHealth:
    rule: Rule
    viability: str            # LIVE / UNOBSERVED / DEAD_EVENTS / DEAD_FIELDS
    alerts: int               # on the analysed logs
    per_million: float
    hosts: int
    bench_hits: int | None    # attack recordings it fired on (None = bench not run)
    tested: bool
    verdict: str = ""
    why: str = ""


def rule_health(rules: list[Rule], events: list[dict], bench_results=None, loud_per_million: float = 500.0,
                profile=None, signatures: list[Detection] | None = None) -> list[RuleHealth]:
    from .blindspot import analyse as blindspot
    sigs = [r for r in rules if r.kind == "signature"]
    res = blindspot(sigs, events, profile)
    status = {v.rule.id: v.status for v in res.viability}
    dets = signatures if signatures is not None else run(sigs, events)
    alerts = Counter(d.rule.id for d in dets)
    hosts = defaultdict(set)
    for d in dets:
        hosts[d.rule.id].add(short_host(d.host))
    bench_hits = None
    if bench_results is not None:
        bench_hits = Counter(rid for r in bench_results if not r.benign for rid in r.fired)
    total = max(res.profile.events, 1)
    out = []
    for r in sigs:
        h = RuleHealth(r, status.get(r.id, "LIVE"), alerts.get(r.id, 0), alerts.get(r.id, 0) / total * 1e6,
                       len(hosts.get(r.id, ())), None if bench_hits is None else bench_hits.get(r.id, 0),
                       bool(r.tests.get("match")) and bool(r.tests.get("nomatch")))
        if h.viability in ("DEAD_EVENTS", "DEAD_FIELDS"):
            h.verdict, h.why = "DEAD", "cannot fire on this telemetry (see blindspot)"
        elif h.per_million >= loud_per_million and h.rule.level in ALERT_LEVELS:
            h.verdict = "TUNE"
            h.why = (f"{h.per_million:,.0f} alerts per million events on {h.hosts} host(s): scope it or add a "
                     f"reviewed suppression" + ("; it does catch real attacks, so tune, don't delete" if h.bench_hits else ""))
        elif h.bench_hits:
            h.verdict, h.why = "TRUST", f"fired on {h.bench_hits} real attack recording(s), quiet here"
        else:
            h.verdict = "UNPROVEN"
            h.why = ("no evidence yet: " + ("add embedded tests; " if not h.tested else "")
                     + ("not seen in the attack recordings" if bench_hits is not None else "run with --bench for attack evidence"))
        out.append(h)
    order = {"TUNE": 0, "DEAD": 1, "UNPROVEN": 2, "TRUST": 3}
    out.sort(key=lambda h: (order[h.verdict], -h.alerts, h.rule.title))
    return out


def health_markdown(rows: list[RuleHealth], events: int) -> str:
    c = Counter(h.verdict for h in rows)
    lines = ["# Rule health", "",
             f"{len(rows):,} signature rules on {events:,} events: **{c['TRUST']} TRUST · {c['TUNE']} TUNE · "
             f"{c['DEAD']} DEAD · {c['UNPROVEN']} UNPROVEN**", "",
             "| Verdict | Rule | Level | Alerts | /1M events | Hosts | Attack recordings | Tested | Why |",
             "|---|---|---|---|---|---|---|---|---|"]
    for h in rows:
        if h.verdict == "UNPROVEN" and not h.alerts:
            continue  # the long tail of quiet, unproven rules adds nothing to the table
        bench = "-" if h.bench_hits is None else str(h.bench_hits)
        lines.append(f"| {h.verdict} | {h.rule.title} | {h.rule.level} | {h.alerts} | {h.per_million:,.1f} | {h.hosts} | "
                     f"{bench} | {'yes' if h.tested else 'no'} | {h.why} |")
    quiet = sum(1 for h in rows if h.verdict == "UNPROVEN" and not h.alerts)
    lines += ["", f"_{quiet:,} quiet UNPROVEN rules omitted from the table._"]
    return "\n".join(lines) + "\n"
