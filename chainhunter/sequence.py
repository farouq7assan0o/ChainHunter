"""Ordered multi-stage (sequence) rules with entity joins.

    sequence:
      within_seconds: 7200
      steps:
        - id: roast
          rule: ch-0001                 # reference a signature rule (or a list of ids) ...
        - id: use
          detection:                    # ... or match raw events inline (Sigma selection syntax)
            selection: {EventID: 4624, LogonType: 3}
            condition: selection
          chainhunter: {actor_field: TargetUserName, source_field: IpAddress}
      join:
        - [roast.ServiceName, use.actor]   # a roasted SPN account later logs on

Join operands are `<step>.<field>` where field is actor/host/source or any raw event field; two
operands match when their normalized value sets intersect. Steps must occur in order, all within
`within_seconds` of the first step.
"""
from __future__ import annotations

import ipaddress
from datetime import timedelta

from .detect import Detection, Rule, apply_threshold, build_detection, rule_matches


HOST_FIELDS = {"host", "Computer", "WorkstationName", "Workstation"}


def norm_entity(value: str, kind: str = "") -> str:
    r"""Canonical entity form: lower-case, DOMAIN\user and user@domain reduced to user.
    Only hosts drop their DNS suffix (castelblack.north.local == CASTELBLACK); account names keep
    their dots, so jon.snow and jon.arryn stay distinct."""
    v = str(value).strip().lower()
    if v.startswith("cn="):
        return v
    v = v.split("\\")[-1].split("@")[0]
    if kind in HOST_FIELDS:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            v = v.split(".")[0]
    return v


def _inline_rule(seq: Rule, step: dict) -> Rule:
    det = dict(step["detection"])
    det.setdefault("condition", " and ".join(k for k in det))
    return Rule(id=f"{seq.id}:{step['id']}", title=f"{seq.title} [{step['id']}]", level=seq.level,
                description="", tags=[], detection=det, meta=step.get("chainhunter", {}), path=seq.path)


def _candidates(seq: Rule, step: dict, detections: list[Detection], events: list[dict]) -> list[Detection]:
    if "rule" in step:
        ids = step["rule"] if isinstance(step["rule"], list) else [step["rule"]]
        return [d for d in detections if d.rule.id in ids]
    r = _inline_rule(seq, step)
    hits = [e for e in events if rule_matches(r, e)]
    thr = step.get("chainhunter", {}).get("threshold")
    return apply_threshold(r, hits, thr) if thr else [build_detection(r, [h]) for h in hits]


def _joins_ok(joins, bound: dict[str, Detection]) -> bool:
    for left, right in joins:
        ls, lf = left.split(".", 1)
        rs, rf = right.split(".", 1)
        if ls in bound and rs in bound:
            lv = {norm_entity(v, lf) for v in bound[ls].values(lf)}
            rv = {norm_entity(v, rf) for v in bound[rs].values(rf)}
            if not lv & rv:
                return False
    return True


def run_sequences(rules: list[Rule], detections: list[Detection], events: list[dict]) -> list[Detection]:
    out: list[Detection] = []
    for seq in (r for r in rules if r.kind == "sequence"):
        spec = seq.meta["sequence"]
        steps, joins = spec["steps"], spec.get("join", [])
        window = timedelta(seconds=spec.get("within_seconds", 3600))
        cands = [sorted(_candidates(seq, s, detections, events), key=lambda d: d.time) for s in steps]

        def extend(i: int, bound: dict[str, Detection], first: Detection, last: Detection):
            if i == len(steps):
                return dict(bound)
            for c in cands[i]:
                if c.time < last.time or c.time - first.time > window:
                    continue
                bound[steps[i]["id"]] = c
                if _joins_ok(joins, bound):
                    found = extend(i + 1, bound, first, c)
                    if found:
                        return found
                del bound[steps[i]["id"]]
            return None

        for start in cands[0]:
            match = extend(1, {steps[0]["id"]: start}, start, start)
            if not match:
                continue
            ordered = [match[s["id"]] for s in steps]
            evs = sorted({id(e): e for d in ordered for e in d.events}.values(), key=lambda e: e["TimeCreated"])
            det = Detection(rule=seq, events=evs, actor=ordered[0].actor or ordered[-1].actor,
                            host=ordered[-1].host, source=ordered[0].source,
                            extra={"steps": [(s["id"], match[s["id"]]) for s in steps],
                                   "entities": [(k, getattr(d, k)) for d in ordered
                                                for k in ("actor", "host", "source") if getattr(d, k)]})
            out.append(det)
    out.sort(key=lambda d: d.time)
    return out
