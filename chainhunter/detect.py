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
TACTICS = {t.lower().replace(" ", "_"): t for t in (
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Stealth", "Defense Impairment",  # ATT&CK v18 split DE in two
    "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact")}

# Sigma logsource service -> event log channel(s), lower-case
SERVICE_CHANNELS = {
    "security": {"security"},
    "system": {"system"},
    "application": {"application"},
    "sysmon": {"microsoft-windows-sysmon/operational"},
    "powershell": {"microsoft-windows-powershell/operational", "powershellcore/operational"},
    "powershell-classic": {"windows powershell"},
    "taskscheduler": {"microsoft-windows-taskscheduler/operational"},
    "wmi": {"microsoft-windows-wmi-activity/operational"},
    "windefend": {"microsoft-windows-windows defender/operational"},
    "dns-server": {"dns server"},
    # cloud (Microsoft Sentinel table names, lower-case; see cloud.py)
    "auditlogs": {"auditlogs"},
    "signinlogs": {"signinlogs", "aadnoninteractiveusersigninlogs"},
    "activitylogs": {"azureactivity"},
    "riskdetection": {"aaduserriskevents"},
    "pim": {"auditlogs"},
    "audit": {"officeactivity"},
    "exchange": {"officeactivity"},
    "threat_management": {"securityalert"},
    "threat_detection": {"securityalert"},
}
CLOUD_PRODUCTS = {"azure", "m365"}

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
    "ps_classic_start": [400],
    "ps_classic_provider_start": [600],
    "file_change": [2],
    "sysmon_status": [4, 16],
    "process_tampering": [25],
    "file_executable_detected": [29],
    "sysmon_error": [255],
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
        if fname == "domain":
            # DNS domain of the host FQDN and of any user principal (user@domain). Lets a sequence link an
            # on-prem federation server (ADFS01.corp.com) to cloud activity by a forged corp.com identity -
            # the case where no account, IP or host is shared (Golden SAML).
            out = set()
            h = self.host or ""
            if h.count(".") >= 2 and not h.replace(".", "").isdigit():
                out.add(h.split(".", 1)[1].lower())
            for v in [self.actor] + [e.get(f) for e in self.events for f in ("User", "AccountUpn", "UserPrincipalName",
                                                                                "InitiatingProcessAccountUpn", "UserId")]:
                if v and "@" in str(v):
                    out.add(str(v).rsplit("@", 1)[1].lower())
            return out
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
        category = (doc.get("logsource") or {}).get("category")
        if category and category not in LOGSOURCE_EVENTS:
            # an unmapped category would run against *every* event (e.g. a file rule matching network events)
            raise ValueError(f"unsupported logsource category '{category}' (needs ETW/other telemetry)")
    meta = dict(doc.get("chainhunter", {}))
    if "kill_chain" not in meta:  # SigmaHQ rules: derive the phase from their ATT&CK tactic tag
        for t in doc.get("tags", []) or []:
            tactic = TACTICS.get(str(t).lower().removeprefix("attack.").replace("-", "_"))
            if tactic:
                meta["kill_chain"] = tactic
                break
    if kind == "sequence":
        meta = {**meta, "sequence": doc["sequence"]}
    return Rule(
        id=str(doc.get("id", f.stem)), title=doc["title"], level=doc.get("level", "medium"),
        description=str(doc.get("description", "")).strip(), tags=doc.get("tags", []),
        detection=detection, meta=meta, path=f, logsource=doc.get("logsource", {}) or {},
        tests=doc.get("tests", {}) or {}, kind=kind,
    )


def load_rules(*dirs: Path, quiet: bool = False, verbose: bool = False) -> list[Rule]:
    rules, seen, skipped = [], set(), []
    for d in dirs:
        for f in sorted(d.rglob("*.yml")) + sorted(d.rglob("*.yaml")):
            try:
                r = load_rule_file(f)
            except Exception as e:  # skip rules using unsupported Sigma features, keep going
                skipped.append(f"{f.name}: {e}")
                continue
            if r and r.id not in seen:
                seen.add(r.id)
                rules.append(r)
    if skipped and not quiet:
        if verbose:
            for s in skipped:
                print(f"[!] skipped {s}", file=sys.stderr)
        else:
            print(f"[i] loaded {len(rules)} rules; skipped {len(skipped)} that need unsupported Sigma "
                  f"features or telemetry (--list-skipped to see them)", file=sys.stderr)
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


def _channel_ok(rule: Rule, event: dict) -> bool:
    """Enforce Sigma `logsource.service` against the event's channel. Without this, a rule written for the
    Application log (e.g. AV keyword matches) fires on any Sysmon/Security event containing the keyword."""
    service = str(rule.logsource.get("service", "")).lower()
    channel = str(event.get("Channel", ""))
    eid = event.get("EventID")
    # platform: cloud rules only see cloud events, Windows rules never see them (a Windows keyword rule
    # would otherwise fire on an Entra ID record that happens to contain the word)
    product = str(rule.logsource.get("product", "")).lower()
    plat = event.get("_platform")
    if product in CLOUD_PRODUCTS:
        if plat not in (product, "m365d" if product == "m365" else None):
            return False
    elif plat and product not in ("", plat):
        return False
    if (rule.logsource.get("category") and channel and isinstance(eid, int) and (eid <= 29 or eid == 255)
            and "sysmon" not in channel.lower()):
        # category rules mean Sysmon for these IDs; found on real APT29 data: a Sysmon WMI rule (EID 20/21)
        # fired on Kernel-Boot and TerminalServices events that reuse the same numbers
        return False
    if not service or not channel:
        return True  # nothing to enforce (e.g. synthetic/test events without a channel)
    known = SERVICE_CHANNELS.get(service)
    if known:
        return channel.lower() in known
    squash = lambda s: s.lower().replace("-", "").replace(" ", "").replace("/", "")
    return squash(service) in squash(channel)


def rule_matches(rule: Rule, event: dict) -> bool:
    if not _channel_ok(rule, event):
        return False
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
            # `distinct: Field` counts unique values (e.g. spray = many *different* accounts), not raw events
            size = len({str(e.get(thr["distinct"], "")).lower() for e in burst}) if thr.get("distinct") else len(burst)
            if size >= thr["count"]:
                out.append(build_detection(rule, burst, meta))
                i += len(burst)
            else:
                i += 1
    return out


def _sel_eids(sel) -> set[int] | None:
    """EventIDs a selection can match, or None if it doesn't pin EventID (matches any)."""
    maps = sel if isinstance(sel, list) else [sel]
    if not maps or not all(isinstance(m, dict) for m in maps):
        return None
    out: set[int] = set()
    for m in maps:
        vals = [v for k, v in m.items() if k.split("|")[0] == "EventID" and len(k.split("|")) == 1]
        if not vals:
            return None
        for v in vals[0] if isinstance(vals[0], list) else [vals[0]]:
            try:
                out.add(int(v))
            except (TypeError, ValueError):
                return None
    return out


def _ast_eids(node, sels: dict[str, set[int] | None]) -> set[int] | None:
    """Over-approximate the EventIDs a condition can match; None = unconstrained. Never under-approximates,
    so indexing can only skip events the rule could not have matched."""
    op = node[0]
    if op == "ref":
        return sels.get(node[1])
    if op == "not":
        return None
    if op in ("and", "or"):
        a, b = _ast_eids(node[1], sels), _ast_eids(node[2], sels)
        if op == "and":
            return b if a is None else a if b is None else a & b
        return None if a is None or b is None else a | b
    parts = [v for k, v in sels.items() if fnmatch.fnmatchcase(k, node[1])]
    if op == "any":
        return None if not parts or any(p is None for p in parts) else set().union(*parts)
    known = [p for p in parts if p is not None]
    return set.intersection(*known) if known else None


def candidate_eids(rule: Rule) -> set[int] | None:
    det = rule.detection
    has_eid = any(k.split("|")[0] == "EventID" for s in det.values() if isinstance(s, dict) for k in s)
    if rule.event_ids and not has_eid:
        return set(rule.event_ids)
    sels = {k: _sel_eids(v) for k, v in det.items() if k != "condition"}
    try:
        return _ast_eids(parse_condition(det["condition"]), sels)
    except Exception:
        return None


def run(rules: list[Rule], events: list[dict]) -> list[Detection]:
    """Match rules against events via an EventID index, the way a SIEM uses indexed fields: a process-creation
    rule only ever scans process-creation events. On 196k real APT29 events x 2,400 rules this is the difference
    between hours and minutes."""
    by_eid: dict[int, list[dict]] = {}
    for e in events:
        by_eid.setdefault(e.get("EventID"), []).append(e)
    detections: list[Detection] = []
    for rule in rules:
        if rule.kind != "signature":
            continue
        eids = candidate_eids(rule)
        pool = events if eids is None else [e for eid in eids for e in by_eid.get(eid, ())]
        hits = [e for e in pool if rule_matches(rule, e)]
        if eids is not None and len(eids) > 1:
            hits.sort(key=lambda e: e["TimeCreated"])
        if not hits:
            continue
        thr = rule.meta.get("threshold")
        detections.extend(apply_threshold(rule, hits, thr) if thr else (build_detection(rule, [h]) for h in hits))
    detections.sort(key=lambda d: d.time)
    return detections
