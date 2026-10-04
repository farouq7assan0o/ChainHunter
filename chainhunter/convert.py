"""Compile rules into SIEM queries: Elastic KQL, Elastic EQL, Splunk SPL.

Signature rules compile from their Sigma detection logic. Sequence rules compile to a native EQL
`sequence ... by` query, the one SIEM language that expresses ordered, joined multi-event logic.
Hand-tuned queries under `chainhunter.queries` override the generated ones in reports.
"""
from __future__ import annotations

import fnmatch
import re

from .detect import Rule, parse_condition

ECS = {"EventID": "event.code", "Computer": "host.name", "Channel": "winlog.channel"}
SPL = {"EventID": "EventCode", "Computer": "host", "Channel": "LogName"}
KQL_SPECIAL = re.compile(r'([\\():<>"\s{}])')


class Unsupported(Exception):
    pass


def ecs(f: str) -> str:
    return ECS.get(f, f"winlog.event_data.{f}")


def _pattern(value, mods) -> tuple[str, bool]:
    """Return (value with * wildcards, is_wildcard)."""
    v = str(value)
    if "contains" in mods:
        return f"*{v}*", True
    if "startswith" in mods:
        return f"{v}*", True
    if "endswith" in mods:
        return f"*{v}", True
    return v, ("*" in v or "?" in v)


# ---------- per-language value/field rendering ----------

def _kql_term(f, value, mods):
    if value is None:
        return f"not {ecs(f)}:*"
    if "re" in mods:
        raise Unsupported("KQL has no regex operator")
    if "cidr" in mods or "windash" in mods:
        return f'{ecs(f)}:"{value}"'
    pat, wild = _pattern(value, mods)
    if wild:
        return f"{ecs(f)}:" + "*".join(KQL_SPECIAL.sub(r"\\\1", part) for part in pat.split("*"))
    return f'{ecs(f)}:"{pat.replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}"'


def _spl_term(f, value, mods):
    name = SPL.get(f, f)
    if value is None:
        return f"NOT {name}=*"
    if "re" in mods:
        raise Unsupported("regex needs a | regex pipe")
    if "cidr" in mods:
        return f'{name}="{value}"'  # Splunk search matches CIDR notation natively
    pat, _ = _pattern(value, mods)
    return f'{name}="{pat.replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}"'


def _eql_term(f, value, mods):
    name = ecs(f)
    if value is None:
        return f"{name} == null"
    esc = lambda s: str(s).replace("\\", "\\\\").replace('"', '\\"')
    if "re" in mods:
        return f'{name} regex~ "{esc(value)}"'
    if "cidr" in mods:
        return f'cidrmatch({name}, "{value}")'
    pat, wild = _pattern(value, mods)
    if f == "EventID":
        return f'{name} == "{pat}"'
    return f'{name} : "{esc(pat)}"'


LANGS = {
    "kql": (_kql_term, " and ", " or ", "not ", lambda k: f'"{k}"'),
    "spl": (_spl_term, " ", " OR ", "NOT ", lambda k: f'"*{k}*"'),
    "eql": (_eql_term, " and ", " or ", "not ", None),
}


def _selection(sel, lang: str) -> str:
    term, AND, OR, _, kw = LANGS[lang]
    if isinstance(sel, list):
        if sel and all(isinstance(s, (str, int)) for s in sel):
            if kw is None:
                raise Unsupported("keyword search")
            return "(" + OR.join(kw(s) for s in sel) + ")"
        return "(" + OR.join(_selection(s, lang) for s in sel) + ")"
    parts = []
    for key, expected in sel.items():
        f, *mods = key.split("|")
        vals = expected if isinstance(expected, list) else [expected]
        joiner = AND if "all" in mods else OR
        terms = [term(f, v, mods) for v in vals]
        parts.append(terms[0] if len(terms) == 1 else "(" + joiner.join(terms) + ")")
    return parts[0] if len(parts) == 1 else "(" + AND.join(parts) + ")"


def _ast(node, sels: dict[str, str], lang: str) -> str:
    _, AND, OR, NOT, _ = LANGS[lang]
    op = node[0]
    if op == "ref":
        return sels[node[1]]
    if op == "not":
        return f"{NOT}{_ast(node[1], sels, lang)}"
    if op in ("and", "or"):
        return f"({_ast(node[1], sels, lang)}{AND if op == 'and' else OR}{_ast(node[2], sels, lang)})"
    names = [k for k in sels if fnmatch.fnmatchcase(k, node[1])]
    return "(" + (OR if op == "any" else AND).join(sels[k] for k in names) + ")"


def compile_detection(rule: Rule, lang: str) -> str:
    det = rule.detection
    sels = {k: _selection(v, lang) for k, v in det.items() if k != "condition"}
    body = _ast(parse_condition(det["condition"]), sels, lang)
    has_eid = any(k.split("|")[0] == "EventID" for s in det.values() if isinstance(s, dict) for k in s)
    if rule.event_ids and not has_eid:
        term = LANGS[lang][0]
        eid = LANGS[lang][2].join(term("EventID", i, []) for i in rule.event_ids)
        body = f"({eid}){LANGS[lang][1]}{body}"
    return body


def compile_rule(rule: Rule, lang: str, registry: dict[str, Rule] | None = None) -> str:
    if rule.kind == "anomaly":
        raise Unsupported("anomaly rules are behavioural")
    if rule.kind == "sequence":
        if lang != "eql":
            raise Unsupported("sequence rules compile to EQL only")
        return compile_sequence(rule, registry)
    body = compile_detection(rule, lang)
    thr = rule.meta.get("threshold")
    if lang == "spl":
        q = f"(index=wineventlog OR index=sysmon) {body}"
        if thr:
            by = ", ".join(SPL.get(g, g) for g in thr.get("group_by", []))
            agg = f"dc({SPL.get(thr['distinct'], thr['distinct'])}) as count" if thr.get("distinct") else "count"
            q += (f" | bin _time span={thr.get('within_seconds', 60)}s | stats {agg} by _time"
                  f"{', ' + by if by else ''} | where count>={thr['count']}")
        return q
    if lang == "eql":
        return f"any where {body}"
    return body


def compile_sequence(rule: Rule, registry: dict[str, Rule] | None = None) -> str:
    spec = rule.meta["sequence"]
    steps, joins = spec["steps"], spec.get("join", [])
    by: dict[str, list[str]] = {s["id"]: [] for s in steps}
    for left, right in joins:
        for side in (left, right):
            sid, fname = side.split(".", 1)
            by[sid].append(fname)
    lines = [f"sequence with maxspan={spec.get('within_seconds', 3600)}s"]
    for s in steps:
        if "detection" in s:
            det = dict(s["detection"])
            det.setdefault("condition", " and ".join(det))
            tmp = Rule(id="", title="", level="", description="", tags=[], detection=det, meta={}, path=rule.path)
            where = compile_detection(tmp, "eql")
            meta = s.get("chainhunter", {})
        else:
            ids = s["rule"] if isinstance(s["rule"], list) else [s["rule"]]
            refs = [registry[i] for i in ids if registry and i in registry]
            if not refs:
                raise Unsupported(f"unknown rule(s) {ids}")
            where = " or ".join(f"({compile_detection(r, 'eql')})" for r in refs)
            meta = refs[0].meta
        fields = []
        for fname in by[s["id"]]:
            if fname in ("actor", "host", "source"):
                spec_f = meta.get(f"{fname}_field", {"actor": "TargetUserName", "host": "Computer", "source": "IpAddress"}[fname])
                fname = spec_f[0] if isinstance(spec_f, list) else spec_f
            fields.append(ecs(fname))
        lines.append(f"  [any where {where}]" + (f" by {', '.join(fields)}" if fields else ""))
    return "\n".join(lines)


def queries_for(rule: Rule, registry: dict[str, Rule] | None = None) -> dict[str, str]:
    """Hand-tuned overrides first, generated queries fill the gaps."""
    out = {}
    for lang in ("kql", "spl", "eql"):
        try:
            out[lang] = compile_rule(rule, lang, registry)
        except (Unsupported, KeyError):
            pass
    out.update({k: v.strip() for k, v in rule.meta.get("queries", {}).items() if v})
    return out
