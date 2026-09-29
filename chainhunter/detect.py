"""Sigma-compatible rule engine.

Supported Sigma features:
  * selections as maps (AND across fields, OR across list values), lists of maps (OR), keyword lists
  * modifiers: contains, startswith, endswith, re, cidr, all, windash (and chains e.g. |contains|all)
  * `field: null` (field absent/empty)
  * conditions: and, or, not, parentheses, `1 of x*`, `all of x*`, `1 of them`, `all of them`
  * logsource -> EventID mapping, so SigmaHQ rules written against a category (process_creation,
    process_access, ...) run against raw Sysmon / Security events

ChainHunter extensions live under `chainhunter:`:
  kill_chain, actor_field, host_field, source_field, collect_targets, risk,
  threshold {count, within_seconds, group_by}, queries {kql, spl, eql} (hand-tuned overrides)
Embedded unit tests live under `tests: {match: [...], nomatch: [...]}`.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re
import sys
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

import yaml

SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "re", "cidr", "all", "windash"}

# Sigma logsource category -> event IDs it implies (Sysmon + native Security equivalents)
LOGSOURCE_EVENTS = {
    "process_creation": [1, 4688],
    "network_connection": [3],
    "process_termination": [5],
    "driver_load": [6],
    "image_load": [7],
    "create_remote_thread": [8],
    "raw_access_thread": [9],
    "process_access": [10],
    "file_event": [11],
    "registry_add": [12],
    "registry_delete": [12],
    "registry_set": [13],
    "registry_rename": [14],
    "registry_event": [12, 13, 14],
    "create_stream_hash": [15],
    "pipe_created": [17, 18],
    "wmi_event": [19, 20, 21],
    "dns_query": [22],
    "file_delete": [23, 26],
    "ps_script": [4104],
    "ps_module": [4103],
}


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
    logsource: dict = field(default_factory=dict)
    tests: dict = field(default_factory=dict)
    kind: str = "signature"  # signature | sequence | anomaly

    @property
    def attack_ids(self) -> list[str]:
        return [t.split(".", 1)[1].upper() for t in self.tags if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t.lower())]

    @property
    def event_ids(self) -> list[int]:
        return LOGSOURCE_EVENTS.get(self.logsource.get("category", ""), [])


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

    def values(self, fname: str) -> set[str]:
        """Entity attribute (actor/host/source) or every value of an event field across the detection."""
        if fname in ("actor", "host", "source"):
            v = getattr(self, fname)
            return {v} if v else set()
        return {str(e[fname]) for e in self.events if e.get(fname) not in (None, "", "-")}


# ---------- loading ----------

def _check_modifiers(detection: dict, where: Path):
    for name, sel in detection.items():
        if name == "condition":
            continue
        for m in sel if isinstance(sel, list) else [sel]:
            if isinstance(m, dict):
                for key in m:
                    bad = set(key.split("|")[1:]) - SUPPORTED_MODIFIERS
                    if bad:
                        raise ValueError(f"unsupported modifier(s) {sorted(bad)}")


def load_rule_file(f: Path) -> Rule | None:
    doc = yaml.safe_load(f.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or "title" not in doc:
        return None
    if "sequence" in doc:
        kind, detection = "sequence", {}
    else:
        kind, detection = "signature", dict(doc["detection"])
        if isinstance(detection.get("condition"), list):
            detection["condition"] = " or ".join(f"({c})" for c in detection["condition"])
        _check_modifiers(detection, f)
    meta = doc.get("chainhunter", {})
    if kind == "sequence":
        meta = {**meta, "sequence": doc["sequence"]}
    return Rule(
        id=str(doc.get("id", f.stem)), title=doc["title"], level=doc.get("level", "medium"),
        description=str(doc.get("description", "")).strip(), tags=doc.get("tags", []),
        detection=detection, meta=meta, path=f, logsource=doc.get("logsource", {}) or {},
        tests=doc.get("tests", {}) or {}, kind=kind,
    )


def load_rules(*dirs: Path, quiet: bool = False) -> list[Rule]:
    rules, seen = [], set()
    for d in dirs:
        for f in sorted(d.rglob("*.yml")) + sorted(d.rglob("*.yaml")):
            try:
                r = load_rule_file(f)
            except Exception as e:  # skip rules using unsupported Sigma features, keep going
                if not quiet:
                    print(f"[!] skipped {f.name}: {e}", file=sys.stderr)
                continue
            if r and r.id not in seen:
                seen.add(r.id)
                rules.append(r)
    return rules


# ---------- field matching ----------

def _match_value(actual, expected, mods: list[str]) -> bool:
    if expected is None:
        return actual in (None, "", "-")
    if actual is None:
        return False
    a, e = str(actual), str(expected)
    if "re" in mods:
        return re.search(e, a) is not None
    if "cidr" in mods:
        try:
            return ipaddress.ip_address(a.strip("[]").removeprefix("::ffff:")) in ipaddress.ip_network(e, strict=False)
        except ValueError:
            return False
    a_l, e_l = a.lower(), e.lower()
    if "windash" in mods:
        variants = {e_l, e_l.replace("-", "/"), e_l.replace("/", "-")}
        return any(_match_value(a, v, [m for m in mods if m != "windash"]) for v in variants)
    if "contains" in mods:
        return e_l in a_l
    if "startswith" in mods:
        return a_l.startswith(e_l)
    if "endswith" in mods:
        return a_l.endswith(e_l)
    if "*" in e or "?" in e:
        return fnmatch.fnmatchcase(a_l, e_l)
    return a_l == e_l


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
        if sel and all(isinstance(s, (str, int)) for s in sel):  # keyword search
            blob = " ".join(str(v) for v in event.values()).lower()
            return any(str(k).lower().strip("*") in blob for k in sel)
        return any(_match_map(event, s) for s in sel if isinstance(s, dict))
    return _match_map(event, sel)


# ---------- condition parsing ----------

_TOKEN = re.compile(r"\(|\)|\band\b|\bor\b|\bnot\b|\b1 of\b|\ball of\b|[\w*]+", re.I)


def parse_condition(cond: str):
    """Parse a Sigma condition into a tiny AST: ('and'|'or', a, b) | ('not', a) | ('any'|'all', pat) | ('ref', name)."""
    tokens = _TOKEN.findall(cond)
    pos = 0

    def peek():
        return tokens[pos].lower() if pos < len(tokens) else None

    def take():
        nonlocal pos
        pos += 1
        return tokens[pos - 1]

    def atom():
        t = peek()
        if t == "(":
            take()
            v = expr()
            take()
            return v
        if t == "not":
            take()
            return ("not", atom())
        if t in ("1 of", "all of"):
            take()
            pat = take()
            return ("any" if t == "1 of" else "all", "*" if pat == "them" else pat)
        return ("ref", take())

    def conj():
        v = atom()
        while peek() == "and":
            take()
            v = ("and", v, atom())
        return v

    def expr():
        v = conj()
        while peek() == "or":
            take()
            v = ("or", v, conj())
        return v

    return expr()


def eval_ast(node, results: dict[str, bool]) -> bool:
    op = node[0]
    if op == "ref":
        return results[node[1]]
    if op == "not":
        return not eval_ast(node[1], results)
    if op == "and":
        return eval_ast(node[1], results) and eval_ast(node[2], results)
    if op == "or":
        return eval_ast(node[1], results) or eval_ast(node[2], results)
    vals = [v for k, v in results.items() if fnmatch.fnmatchcase(k, node[1])]
    return any(vals) if op == "any" else all(vals)


_AST_CACHE: dict[str, tuple] = {}


def rule_matches(rule: Rule, event: dict) -> bool:
    if rule.event_ids and not any(k.split("|")[0] == "EventID" for s in rule.detection.values() if isinstance(s, dict) for k in s):
        if event.get("EventID") not in rule.event_ids:
            return False
    det = rule.detection
    results = {k: _match_selection(event, v) for k, v in det.items() if k != "condition"}
    ast = _AST_CACHE.setdefault(det["condition"], parse_condition(det["condition"]))
    return eval_ast(ast, results)


# ---------- running ----------

def _pick(event: dict, spec) -> str:
    for f in (spec if isinstance(spec, list) else [spec]):
        v = event.get(f)
        if v not in (None, "", "-"):
            return str(v)
    return ""


def build_detection(rule: Rule, events: list[dict], meta: dict | None = None) -> Detection:
    m, first = meta if meta is not None else rule.meta, events[0]
    return Detection(
        rule=rule, events=events,
        actor=_pick(first, m.get("actor_field", ["SubjectUserName", "TargetUserName", "User"])),
        host=_pick(first, m.get("host_field", "Computer")),
        source=_pick(first, m.get("source_field", ["IpAddress", "WorkstationName"])),
    )


def apply_threshold(rule: Rule, hits: list[dict], thr: dict, meta: dict | None = None) -> list[Detection]:
    window = timedelta(seconds=thr.get("within_seconds", 60))
    groups: dict[tuple, list[dict]] = {}
    for h in hits:
        groups.setdefault(tuple(str(h.get(g, "")) for g in thr.get("group_by", [])), []).append(h)
    out = []
    for evs in groups.values():
        i = 0
        while i < len(evs):
            burst = [e for e in evs[i:] if e["TimeCreated"] - evs[i]["TimeCreated"] <= window]
            if len(burst) >= thr["count"]:
                out.append(build_detection(rule, burst, meta))
                i += len(burst)
            else:
                i += 1
    return out


def run(rules: list[Rule], events: list[dict]) -> list[Detection]:
    detections: list[Detection] = []
    for rule in rules:
        if rule.kind != "signature":
            continue
        hits = [e for e in events if rule_matches(rule, e)]
        if not hits:
            continue
        thr = rule.meta.get("threshold")
        detections.extend(apply_threshold(rule, hits, thr) if thr else (build_detection(rule, [h]) for h in hits))
    detections.sort(key=lambda d: d.time)
    return detections
