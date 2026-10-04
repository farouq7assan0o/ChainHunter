"""Analyst false-positive feedback, with guardrails.

    chainhunter suppress add --rule "Non Interactive PowerShell Process Spawned" \
        --where host=SCRANTON --where "ParentImage=*\\ccmexec.exe" --reason "SCCM client" --expires 90d
    chainhunter suppress list
    chainhunter hunt logs/ --suppress suppressions.yml

suppressions.yml entries are scoped (a rule + conditions), attributed (author, reason, created) and expiring.
Guardrails, because careless suppression is how a SOC goes blind:
  * a rule is required; `rule: "*"` needs allow_broad: true
  * critical-severity rules need allow_critical: true
  * expired entries stop applying and are reported
  * suppression hides the individual alert, never a chain: sequence rules are evaluated on the unsuppressed
    detections, so muting a noisy step cannot mute the multi-stage attack it belongs to
  * every entry reports its hit count; zero-hit entries are flagged as stale
"""
from __future__ import annotations

import fnmatch
import getpass
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import yaml

from .detect import Detection

ENTITY_KEYS = {"host", "actor", "source"}


@dataclass
class Suppression:
    id: str
    rule: str
    where: dict[str, str]
    reason: str
    author: str
    created: str
    expires: str | None
    allow_critical: bool = False
    allow_broad: bool = False
    hits: int = 0
    problems: list[str] = field(default_factory=list)

    @property
    def expired(self) -> bool:
        return bool(self.expires) and date.fromisoformat(str(self.expires)) < date.today()

    @property
    def active(self) -> bool:
        return not self.expired and not self.problems


def load(path: Path) -> list[Suppression]:
    if not path.exists():
        raise SystemExit(f"[x] suppression file not found: {path}")
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out = []
    for i, e in enumerate(doc.get("suppressions", []) or [], 1):
        s = Suppression(id=str(e.get("id", f"s-{i:03d}")), rule=str(e.get("rule", "")).strip(),
                        where={str(k): str(v) for k, v in (e.get("where") or {}).items()},
                        reason=str(e.get("reason", "")).strip(), author=str(e.get("author", "")),
                        created=str(e.get("created", "")), expires=str(e["expires"]) if e.get("expires") else None,
                        allow_critical=bool(e.get("allow_critical")), allow_broad=bool(e.get("allow_broad")))
        if not s.rule:
            s.problems.append("no rule given")
        if s.rule == "*" and not s.allow_broad:
            s.problems.append("rule '*' suppresses everything; set allow_broad: true if you really mean it")
        if not s.reason:
            s.problems.append("no reason given")
        out.append(s)
    return out


def _match(pattern: str, value) -> bool:
    return value is not None and fnmatch.fnmatchcase(str(value).lower(), pattern.lower())


def matches(s: Suppression, d: Detection) -> bool:
    if s.rule != "*" and s.rule.lower() not in (d.rule.id.lower(), d.rule.title.lower()):
        return False
    for key, pattern in s.where.items():
        if key in ENTITY_KEYS:
            if not _match(pattern, getattr(d, key)):
                return False
        elif not all(_match(pattern, ev.get(key)) for ev in d.events):  # every event must match (conservative)
            return False
    return True


def apply(detections: list[Detection], sups: list[Suppression]) -> tuple[list[Detection], list[Detection]]:
    """Returns (kept, suppressed). Critical rules are only suppressed by entries with allow_critical."""
    kept, hidden = [], []
    active = [s for s in sups if s.active]
    for d in detections:
        hit = next((s for s in active if matches(s, d) and (d.rule.level != "critical" or s.allow_critical)), None)
        if hit:
            hit.hits += 1
            d.extra["suppressed_by"] = hit.id
            hidden.append(d)
        else:
            kept.append(d)
    return kept, hidden


def summary(sups: list[Suppression]) -> list[str]:
    lines = []
    for s in sups:
        if s.problems:
            lines.append(f"[!] suppression {s.id} ignored: {'; '.join(s.problems)}")
        elif s.expired:
            lines.append(f"[!] suppression {s.id} expired {s.expires}; no longer applied ({s.rule})")
        elif s.hits == 0:
            lines.append(f"[i] suppression {s.id} matched nothing this run (stale?): {s.rule}")
        else:
            lines.append(f"[i] suppression {s.id} hid {s.hits} alert(s): {s.rule} [{s.reason}]")
    return lines


def add(path: Path, rule: str, where: list[str], reason: str, expires: str | None,
        allow_critical: bool = False) -> Suppression:
    doc = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}) if path.exists() else {}
    entries = doc.setdefault("suppressions", [])
    cond = {}
    for w in where:
        k, sep, v = w.partition("=")
        if not sep:
            raise SystemExit(f"[x] --where needs key=value, got '{w}'")
        cond[k.strip()] = v.strip()
    if expires and re.fullmatch(r"\d+d", expires):
        expires = (date.today() + timedelta(days=int(expires[:-1]))).isoformat()
    try:
        author = getpass.getuser()
    except Exception:
        author = "unknown"
    n = max([int(m.group(1)) for e in entries if (m := re.fullmatch(r"s-(\d+)", str(e.get("id", ""))))] or [0]) + 1
    entry = {"id": f"s-{n:03d}", "rule": rule, "where": cond, "reason": reason, "author": author,
             "created": datetime.now(timezone.utc).date().isoformat(), "expires": expires}
    if allow_critical:
        entry["allow_critical"] = True
    entries.append(entry)
    path.write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return load(path)[-1]
