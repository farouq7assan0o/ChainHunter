"""Detection-as-code: lint rules, run their embedded tests, and report ATT&CK coverage.

Embedded tests (per rule):
    tests:
      match:   [<case>, ...]    # each must fire the rule
      nomatch: [<case>, ...]    # each must NOT fire the rule
A case is one event (map) or a list of events. `_offset` (seconds) sets relative event time;
TimeCreated defaults to case start + index seconds. Sequence rules are tested through the full
signature -> sequence pipeline, so references to other rules are exercised too.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .convert import Unsupported, compile_rule
from .detect import Rule, parse_condition, run
from .sequence import run_sequences

LEVELS = {"informational", "low", "medium", "high", "critical"}
T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


@dataclass
class Result:
    rule: Rule
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    passed: int = 0
    failed: int = 0


def _refs(node) -> set[str]:
    if node[0] == "ref":
        return {node[1]}
    if node[0] in ("any", "all"):
        return set()
    return set().union(*(_refs(n) for n in node[1:]))


def lint(rule: Rule, registry: dict[str, Rule]) -> tuple[list[str], list[str]]:
    errors, warnings = [], []
    if rule.level not in LEVELS:
        errors.append(f"invalid level '{rule.level}'")
    if not rule.attack_ids:
        errors.append("no ATT&CK technique tag (attack.tXXXX)")
    if not rule.description:
        warnings.append("missing description")
    if not rule.meta.get("kill_chain"):
        warnings.append("missing chainhunter.kill_chain")
    if not rule.tests.get("match"):
        warnings.append("no positive test cases")
    if not rule.tests.get("nomatch"):
        warnings.append("no negative test cases")
    if rule.kind == "signature":
        try:
            missing = _refs(parse_condition(rule.detection["condition"])) - set(rule.detection)
            if missing:
                errors.append(f"condition references undefined selection(s): {sorted(missing)}")
        except Exception as e:
            errors.append(f"condition does not parse: {e}")
        for lang in ("kql", "spl", "eql"):
            try:
                compile_rule(rule, lang)
            except Unsupported as e:
                warnings.append(f"no {lang.upper()} translation ({e})")
    else:
        for step in rule.meta["sequence"]["steps"]:
            ids = step.get("rule", [])
            for i in ids if isinstance(ids, list) else [ids]:
                if i not in registry:
                    errors.append(f"sequence step '{step['id']}' references unknown rule {i}")
        step_ids = {s["id"] for s in rule.meta["sequence"]["steps"]}
        for pair in rule.meta["sequence"].get("join", []):
            for side in pair:
                if side.split(".", 1)[0] not in step_ids:
                    errors.append(f"join operand '{side}' names an unknown step")
    return errors, warnings


def _events(case) -> list[dict]:
    evs = case if isinstance(case, list) else [case]
    out = []
    for i, e in enumerate(evs):
        e = dict(e)
        e.setdefault("TimeCreated", T0 + timedelta(seconds=e.pop("_offset", i)))
        e.pop("_offset", None)
        e.setdefault("Computer", "testhost")
        out.append(e)
    return sorted(out, key=lambda x: x["TimeCreated"])


def fires(rule: Rule, events: list[dict], rules: list[Rule]) -> bool:
    if rule.kind == "sequence":
        sigs = [r for r in rules if r.kind == "signature"]
        return any(d.rule.id == rule.id for d in run_sequences([rule], run(sigs, events), events))
    return bool(run([rule], events))


def validate(rules: list[Rule]) -> list[Result]:
    registry = {r.id: r for r in rules}
    results, seen = [], set()
    for r in rules:
        res = Result(r)
        if r.id in seen:
            res.errors.append(f"duplicate id {r.id}")
        seen.add(r.id)
        e, w = lint(r, registry)
        res.errors += e
        res.warnings += w
        for expect, cases in (("match", r.tests.get("match", [])), ("nomatch", r.tests.get("nomatch", []))):
            for n, case in enumerate(cases, 1):
                try:
                    ok = fires(r, _events(case), rules) == (expect == "match")
                except Exception as ex:  # a crashing test is a failing test
                    ok = False
                    res.errors.append(f"{expect}[{n}] raised {ex!r}")
                if ok:
                    res.passed += 1
                else:
                    res.failed += 1
                    res.errors.append(f"{expect}[{n}] {'did not fire' if expect == 'match' else 'fired unexpectedly'}")
        results.append(res)
    return results


def coverage(rules: list[Rule]) -> dict[str, list[str]]:
    """ATT&CK tactic -> techniques covered, from rule tags."""
    tactics: dict[str, set[str]] = {}
    for r in (r for r in rules if r.kind == "signature"):  # sequences are compositions, not new coverage
        tac = [t.split(".", 1)[1].replace("_", " ").title() for t in r.tags
               if t.startswith("attack.") and not re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)]
        for t in tac or ["Unmapped"]:
            tactics.setdefault(t, set()).update(r.attack_ids)
    return {k: sorted(v) for k, v in sorted(tactics.items())}
