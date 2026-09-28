"""Lightweight Sigma-subset rule engine.

Supported:
  * detection selections as maps (AND across fields, OR across list values) or lists of maps (OR)
  * modifiers: contains, startswith, endswith, re, all (and chaining e.g. |contains|all)
  * condition expressions with: and, or, not, parentheses, `1 of sel*`, `all of sel*`
  * ChainHunter extensions (under `chainhunter:` in the rule):
      kill_chain, actor_field, host_field, source_field, queries {kql, spl, eql}
      threshold {count, within_seconds, group_by}  -> fire only on bursts
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

import yaml


@dataclass
class Rule:
    id: str
    title: str
    level: str
    description: str
    tags: list[str]
    detection: dict
    meta: dict
    path: Path

    @property
    def attack_ids(self) -> list[str]:
        return [t.split(".", 1)[1].upper() for t in self.tags if t.lower().startswith("attack.t")]


@dataclass
class Detection:
    rule: Rule
    events: list[dict]
    actor: str = ""
    host: str = ""
    source: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def time(self):
        return self.events[0]["TimeCreated"]

    @property
    def end(self):
        return self.events[-1]["TimeCreated"]


def load_rules(rules_dir: Path) -> list[Rule]:
    rules = []
    for f in sorted(rules_dir.rglob("*.yml")):
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        rules.append(Rule(
            id=doc.get("id", f.stem),
            title=doc["title"],
            level=doc.get("level", "medium"),
            description=doc.get("description", "").strip(),
            tags=doc.get("tags", []),
            detection=doc["detection"],
            meta=doc.get("chainhunter", {}),
            path=f,
        ))
    return rules


# ---------- field matching ----------

def _match_value(actual, expected, mods: list[str]) -> bool:
    if actual is None:
        return expected is None
    a = str(actual)
    e = str(expected)
    if "re" in mods:
        return re.search(e, a) is not None
    a_l, e_l = a.lower(), e.lower()
    if "contains" in mods:
        return e_l in a_l
    if "startswith" in mods:
        return a_l.startswith(e_l)
    if "endswith" in mods:
        return a_l.endswith(e_l)
    if isinstance(expected, int) or (isinstance(actual, int) and e.isdigit()):
        return a == e
    return fnmatch.fnmatchcase(a_l, e_l) if ("*" in e or "?" in e) else a_l == e_l


def _match_map(event: dict, sel: dict) -> bool:
    for key, expected in sel.items():
        fname, *mods = key.split("|")
        actual = event.get(fname)
        values = expected if isinstance(expected, list) else [expected]
        hits = [_match_value(actual, v, mods) for v in values]
        if not (all(hits) if "all" in mods else any(hits)):
            return False
    return True


def _match_selection(event: dict, sel) -> bool:
    if isinstance(sel, list):
        return any(_match_map(event, s) if isinstance(s, dict) else False for s in sel)
    return _match_map(event, sel)


# ---------- condition parsing ----------

_TOKEN = re.compile(r"\(|\)|\band\b|\bor\b|\bnot\b|\b1 of\b|\ball of\b|[\w*]+", re.I)


def _eval_condition(cond: str, results: dict[str, bool]) -> bool:
    tokens = _TOKEN.findall(cond)
    pos = 0

    def peek():
        return tokens[pos].lower() if pos < len(tokens) else None

    def take():
        nonlocal pos
        pos += 1
        return tokens[pos - 1]

    def names(pattern):
        return [v for k, v in results.items() if fnmatch.fnmatchcase(k, pattern)]

    def atom():
        t = peek()
        if t == "(":
            take()
            v = expr()
            take()  # ')'
            return v
        if t == "not":
            take()
            return not atom()
        if t == "1 of":
            take()
            return any(names(take()))
        if t == "all of":
            take()
            return all(names(take()))
        return results[take()]

    def conj():
        v = atom()
        while peek() == "and":
            take()
            v = atom() and v
        return v

    def expr():
        v = conj()
        while peek() == "or":
            take()
            v = conj() or v
        return v

    return expr()


def rule_matches(rule: Rule, event: dict) -> bool:
    det = rule.detection
    results = {k: _match_selection(event, v) for k, v in det.items() if k != "condition"}
    return _eval_condition(det["condition"], results)


# ---------- running ----------

def _pick(event: dict, spec) -> str:
    for f in (spec if isinstance(spec, list) else [spec]):
        v = event.get(f)
        if v not in (None, "", "-"):
            return str(v)
    return ""


def _build(rule: Rule, events: list[dict]) -> Detection:
    m, first = rule.meta, events[0]
    return Detection(
        rule=rule,
        events=events,
        actor=_pick(first, m.get("actor_field", ["SubjectUserName", "TargetUserName", "User"])),
        host=_pick(first, m.get("host_field", "Computer")),
        source=_pick(first, m.get("source_field", ["IpAddress", "WorkstationName"])),
    )


def run(rules: list[Rule], events: list[dict]) -> list[Detection]:
    detections: list[Detection] = []
    for rule in rules:
        hits = [e for e in events if rule_matches(rule, e)]
        if not hits:
            continue
        thr = rule.meta.get("threshold")
        if not thr:
            detections.extend(_build(rule, [h]) for h in hits)
            continue
        window = timedelta(seconds=thr.get("within_seconds", 60))
        group_by = thr.get("group_by", [])
        groups: dict[tuple, list[dict]] = {}
        for h in hits:
            groups.setdefault(tuple(str(h.get(g, "")) for g in group_by), []).append(h)
        for evs in groups.values():
            i = 0
            while i < len(evs):
                burst = [e for e in evs[i:] if e["TimeCreated"] - evs[i]["TimeCreated"] <= window]
                if len(burst) >= thr["count"]:
                    detections.append(_build(rule, burst))
                    i += len(burst)
                else:
                    i += 1
    detections.sort(key=lambda d: d.time)
    return detections
