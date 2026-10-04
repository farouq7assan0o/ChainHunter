"""Benchmark the rule set against real, public attack recordings (datasets/manifest.yml).

Each manifest sample may carry optional labels:
    expect: [ch-0004]     # rule ids that SHOULD fire (missing ones count as false negatives)
    benign: true          # control sample: anything that fires is a false positive

Without labels a sample is simply reported as detected / not detected, which is still the honest
headline number: "N of M real attack recordings produced at least one detection".
"""
from __future__ import annotations

import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .detect import Rule, run
from .ingest import load
from .sequence import run_sequences

ALERT_LEVELS = {"medium", "high", "critical"}


@dataclass
class SampleResult:
    name: str
    events: int
    fired: Counter
    expect: list[str] = field(default_factory=list)
    benign: bool = False
    error: str = ""
    levels: dict = field(default_factory=dict)
    titles: dict = field(default_factory=dict)

    def names(self) -> list[str]:
        """Human-readable alerting rule names (SigmaHQ ids are UUIDs), with hit counts."""
        return [f"{self.titles.get(k, k)}" + (f" ×{self.fired[k]}" if self.fired[k] > 1 else "")
                for k in sorted(self.alerting, key=lambda k: self.titles.get(k, k))]

    @property
    def missed(self) -> list[str]:
        return [r for r in self.expect if r not in self.fired]

    @property
    def alerting(self) -> list[str]:
        """Rules that would page an analyst: medium and above. Informational/low rules are context only."""
        return [r for r in self.fired if self.levels.get(r, "medium") in ALERT_LEVELS]

    @property
    def status(self) -> str:
        if self.error:
            return "ERROR"
        if self.benign:
            return "FP" if self.alerting else "clean"
        if self.expect:
            return "MISS" if self.missed else "pass"
        return "detected" if self.alerting else "not detected"


def _data_files(manifest: Path, entry: dict) -> list[Path]:
    p = manifest.parent / "cache" / entry["source"] / Path(entry["path"]).name
    if p.suffix.lower() == ".zip":
        return sorted(f for f in p.parent.glob(p.stem + "*") if f.suffix.lower() in {".json", ".jsonl"})
    return [p]


def bench(rules: list[Rule], manifest: Path) -> list[SampleResult]:
    doc = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    levels = {r.id: r.level for r in rules}
    titles = {r.id: r.title for r in rules}
    out = []
    for entry in doc["samples"]:
        if entry.get("campaign"):  # full multi-host campaigns are for `hunt`, not the per-technique benchmark
            continue
        name = Path(entry["path"]).name
        files = [f for f in _data_files(manifest, entry) if f.exists()]
        if not files:
            out.append(SampleResult(name, 0, Counter(), error="not downloaded (run datasets/fetch.py)"))
            continue
        try:
            events = load(files)
            sigs = run(rules, events)
            seqs = run_sequences(rules, sigs, events)
            fired = Counter(d.rule.id for d in sigs + seqs)
            out.append(SampleResult(name, len(events), fired, entry.get("expect", []), entry.get("benign", False),
                                    levels={k: levels.get(k, "medium") for k in fired},
                                    titles={k: titles.get(k, k) for k in fired}))
        except Exception as e:  # one bad sample must not sink the whole benchmark
            out.append(SampleResult(name, 0, Counter(), error=f"{e.__class__.__name__}: {e}"))
            print(f"[!] {name}: {e}", file=sys.stderr)
    return out


def summary(results: list[SampleResult]) -> dict:
    attacks = [r for r in results if not r.benign and not r.error]
    benign = [r for r in results if r.benign and not r.error]
    labelled = [r for r in attacks if r.expect]
    exp_total = sum(len(r.expect) for r in labelled)
    exp_hit = sum(len(r.expect) - len(r.missed) for r in labelled)
    return {
        "attack_samples": len(attacks),
        "attack_samples_detected": sum(bool(r.alerting) for r in attacks),
        "labelled_expectations": exp_total,
        "labelled_hits": exp_hit,
        "benign_samples": len(benign),
        "benign_with_fp": sum(bool(r.alerting) for r in benign),
        "errors": sum(bool(r.error) for r in results),
    }


def markdown(results: list[SampleResult]) -> str:
    s = summary(results)
    rate = s["attack_samples_detected"] / s["attack_samples"] * 100 if s["attack_samples"] else 0
    lines = [
        "# ChainHunter benchmark — real attack recordings", "",
        f"- **Attack samples detected (medium+ severity):** {s['attack_samples_detected']}/{s['attack_samples']} ({rate:.0f}%)",
    ]
    if s["labelled_expectations"]:
        lines.append(f"- **Labelled expectations met:** {s['labelled_hits']}/{s['labelled_expectations']}")
    if s["benign_samples"]:
        lines.append(f"- **Benign controls with false positives:** {s['benign_with_fp']}/{s['benign_samples']}")
    if s["errors"]:
        lines.append(f"- **Samples that failed to load:** {s['errors']}")
    lines += ["", "| Sample | Events | Result | Alerts raised | Missed |", "|---|---|---|---|---|"]
    for r in results:
        lines.append(f"| {r.name} | {r.events} | {r.status}{(' — ' + r.error) if r.error else ''} | "
                     f"{'<br>'.join(r.names()) or '—'} | {', '.join(r.missed) or ''} |")
    return "\n".join(lines) + "\n"


def terminal(results: list[SampleResult]) -> str:
    """Readable console view: one block per sample, rule names instead of ids."""
    s = summary(results)
    mark = {"pass": "[+]", "detected": "[+]", "clean": "[+]", "not detected": "[ ]", "MISS": "[x]", "FP": "[x]", "ERROR": "[!]"}
    out = []
    for r in results:
        out.append(f"{mark.get(r.status, '[?]')} {r.name}  ({r.status})")
        for n in r.names()[:4]:
            out.append(f"      - {n}")
        if len(r.names()) > 4:
            out.append(f"      - ... and {len(r.names()) - 4} more")
        if r.missed:
            out.append(f"      ! expected but missed: {', '.join(r.missed)}")
    rate = s["attack_samples_detected"] / s["attack_samples"] * 100 if s["attack_samples"] else 0
    out += ["", "=" * 60,
            f"RESULT: {s['attack_samples_detected']}/{s['attack_samples']} real attack recordings detected ({rate:.0f}%)",
            f"        {s['labelled_hits']}/{s['labelled_expectations']} labelled checks passed"
            + (f", {s['benign_with_fp']} false positives on benign controls" if s["benign_samples"] else ""),
            "=" * 60]
    return "\n".join(out)
