"""Blindspot: measure what you can *actually* detect with the telemetry you *actually* collect.

ATT&CK coverage dashboards count rule tags, i.e. what a SOC *thinks* it detects. Blindspot reads the real
logs and asks, for every rule, whether it can ever fire here:

  * DEAD - no events   : the rule needs event IDs / a log channel that this environment never produced
  * DEAD - no fields   : the events exist, but a field the rule requires is never populated
                         (classic: 4688 without "Include command line in process creation events")
  * LIVE               : the rule can fire

It then rolls that up into true ATT&CK coverage (techniques with live rules vs. techniques you only have
rules for), ranks the telemetry changes that would revive the most detections, and checks log health:
hosts missing a source their peers have, and sources that go silent mid-window. Silent failure is the
failure mode that bit this project six times; Blindspot is the tool that would have caught it.
"""
from __future__ import annotations

import fnmatch
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .detect import SERVICE_CHANNELS, Rule, candidate_eids, parse_condition

# What to tell an engineer to turn on, per event ID (Sysmon IDs refer to the Sysmon/Operational channel)
SOURCE_NAMES = {
    1: "Sysmon 1 - process creation", 2: "Sysmon 2 - file creation time changed", 3: "Sysmon 3 - network connection",
    5: "Sysmon 5 - process terminated", 6: "Sysmon 6 - driver loaded", 7: "Sysmon 7 - image (DLL) loaded",
    8: "Sysmon 8 - CreateRemoteThread", 9: "Sysmon 9 - raw disk access", 10: "Sysmon 10 - process access (LSASS dumping)",
    11: "Sysmon 11 - file create", 16: "Sysmon 16 - Sysmon config change", 4: "Sysmon 4 - Sysmon service state", 12: "Sysmon 12 - registry key create/delete", 13: "Sysmon 13 - registry value set",
    14: "Sysmon 14 - registry rename", 15: "Sysmon 15 - alternate data stream", 17: "Sysmon 17 - named pipe created",
    18: "Sysmon 18 - named pipe connected", 19: "Sysmon 19 - WMI filter", 20: "Sysmon 20 - WMI consumer",
    21: "Sysmon 21 - WMI binding", 22: "Sysmon 22 - DNS query", 23: "Sysmon 23 - file delete (archived)",
    25: "Sysmon 25 - process tampering", 26: "Sysmon 26 - file delete", 29: "Sysmon 29 - executable file detected",
    104: "System 104 - event log cleared", 400: "Windows PowerShell 400 - engine start",
    600: "Windows PowerShell 600 - provider start", 1102: "Security 1102 - audit log cleared",
    4103: "PowerShell 4103 - module logging", 4104: "PowerShell 4104 - script block logging",
    4624: "Security 4624 - logon (Audit Logon)", 4625: "Security 4625 - failed logon (Audit Logon)",
    4648: "Security 4648 - explicit credentials", 4656: "Security 4656 - handle requested (Kernel Object / File System auditing)",
    4657: "Security 4657 - registry value modified (Registry auditing + SACL)",
    4662: "Security 4662 - AD object access (Audit Directory Service Access + SACL)",
    4663: "Security 4663 - object access (Kernel Object / File System auditing)",
    4672: "Security 4672 - special privileges assigned", 4688: "Security 4688 - process creation (Audit Process Creation)",
    4697: "Security 4697 - service installed (Audit Security System Extension)",
    4698: "Security 4698 - scheduled task created (Audit Other Object Access)", 4699: "Security 4699 - scheduled task deleted",
    4720: "Security 4720 - user created", 4728: "Security 4728 - member added to global group",
    4732: "Security 4732 - member added to local group", 4738: "Security 4738 - user changed",
    4742: "Security 4742 - computer account changed", 4741: "Security 4741 - computer account created",
    4743: "Security 4743 - computer account deleted", 4765: "Security 4765 - SID history added",
    4766: "Security 4766 - SID history add failed", 5038: "Security 5038 - code integrity: invalid image hash",
    6281: "Security 6281 - code integrity: invalid page hash", 6004: "System 6004 - driver entered failed state", 4768: "Security 4768 - Kerberos TGT (Audit Kerberos Authentication)",
    4769: "Security 4769 - Kerberos service ticket (Audit Kerberos Service Ticket Operations)",
    4771: "Security 4771 - Kerberos pre-auth failed", 4776: "Security 4776 - NTLM credential validation",
    5136: "Security 5136 - directory object modified (Audit Directory Service Changes)",
    5140: "Security 5140 - network share accessed (Audit File Share)",
    5145: "Security 5145 - share object checked (Audit Detailed File Share)",
    5156: "Security 5156 - WFP connection allowed (Audit Filtering Platform Connection)",
    7036: "System 7036 - service state change", 7045: "System 7045 - service installed",
}

# Missing-field fixes that are a single, well-known configuration change
FIELD_FIXES = {
    (4688, "CommandLine"): "GPO: Administrative Templates > System > Audit Process Creation > "
                           "'Include command line in process creation events'",
    (4688, "ParentProcessName"): "Windows 10/Server 2016+ populates 4688 ParentProcessName; upgrade older hosts or use Sysmon 1",
    (1, "Hashes"): "Sysmon config: set <HashAlgorithms> (e.g. SHA256,IMPHASH)",
    (1, "OriginalFileName"): "Sysmon v10+ records OriginalFileName; upgrade Sysmon",
    (10, "CallTrace"): "Sysmon ProcessAccess events include CallTrace by default; check the config does not strip it",
}


def source_name(eid: int) -> str:
    return SOURCE_NAMES.get(eid, f"EventID {eid}")


def expected_channel(eid: int) -> str | None:
    """The log channel an event ID is written to, so 'channel collected, event absent' can be told apart
    from 'channel not collected at all'."""
    if eid <= 29 or eid == 255:
        return "microsoft-windows-sysmon/operational"
    if eid in (4103, 4104):
        return "microsoft-windows-powershell/operational"
    if eid in (400, 403, 600, 800):
        return "windows powershell"
    if eid in (104, 6004, 6005, 6006, 7034, 7036, 7040, 7045):
        return "system"
    if eid in (325, 326, 327):
        return "application"
    if 1100 <= eid <= 1108 or 4600 <= eid <= 6999:
        return "security"
    return None


# ---------- telemetry profile ----------

@dataclass
class Profile:
    events: int = 0
    by_eid: Counter = field(default_factory=Counter)
    channels: Counter = field(default_factory=Counter)
    fields_by_eid: dict[int, set[str]] = field(default_factory=lambda: defaultdict(set))
    all_fields: set[str] = field(default_factory=set)
    host_channels: dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    start: object = None
    end: object = None


def profile(events: list[dict]) -> Profile:
    p = Profile(events=len(events))
    for e in events:
        eid = e.get("EventID")
        ch = str(e.get("Channel", "")).lower()
        p.channels[ch] += 1
        p.host_channels[str(e.get("Computer", "")).split(".")[0].upper()][ch] += 1
        if isinstance(eid, int) and (eid <= 29 or eid == 255) and ch and "sysmon" not in ch:
            continue  # e.g. System-log event 1 is not Sysmon process creation; don't count it as coverage
        p.by_eid[eid] += 1
        present = {k for k, v in e.items() if v not in (None, "", "-")}
        p.fields_by_eid[eid] |= present
        p.all_fields |= present
    if events:
        p.start, p.end = events[0]["TimeCreated"], events[-1]["TimeCreated"]
    return p


# ---------- rule viability ----------

def _sel_fields(sel) -> set[str]:
    """Fields a selection needs populated to match (null-valued fields mean 'absent', so they don't count)."""
    if isinstance(sel, dict):
        return {k.split("|")[0] for k, v in sel.items() if v is not None and k.split("|")[0] != "EventID"}
    maps = [s for s in sel if isinstance(s, dict)] if isinstance(sel, list) else []
    if not maps or len(maps) != len(sel):
        return set()  # keyword search: no specific field
    return set.intersection(*(_sel_fields(m) for m in maps))


def _required(node, sels: dict[str, set[str]]) -> set[str]:
    """Fields every matching path through the condition needs (under-approximation: never claims too much)."""
    op = node[0]
    if op == "ref":
        return sels.get(node[1], set())
    if op == "not":
        return set()
    if op == "and":
        return _required(node[1], sels) | _required(node[2], sels)
    if op == "or":
        return _required(node[1], sels) & _required(node[2], sels)
    parts = [v for k, v in sels.items() if fnmatch.fnmatchcase(k, node[1])]
    if not parts:
        return set()
    return set.intersection(*parts) if op == "any" else set().union(*parts)


def required_fields(rule: Rule) -> set[str]:
    det = rule.detection
    try:
        return _required(parse_condition(det["condition"]),
                         {k: _sel_fields(v) for k, v in det.items() if k != "condition"})
    except Exception:
        return set()


@dataclass
class Viability:
    rule: Rule
    status: str               # LIVE | DEAD_EVENTS | DEAD_FIELDS | UNOBSERVED
    reason: str = ""
    missing_eids: set[int] = field(default_factory=set)
    missing_fields: dict[int, set[str]] = field(default_factory=dict)
    missing_service: str = ""


def _channel_seen(rule: Rule, p: Profile) -> bool:
    service = str(rule.logsource.get("service", "")).lower()
    if not service or not p.channels:
        return True
    known = SERVICE_CHANNELS.get(service)
    if known:
        return any(c in known for c in p.channels)
    squash = lambda s: s.lower().replace("-", "").replace(" ", "").replace("/", "")
    return any(squash(service) in squash(c) for c in p.channels)


def assess(rule: Rule, p: Profile) -> Viability:
    if rule.kind != "signature":
        return Viability(rule, "LIVE", "composite rule (depends on its component rules)")
    eids = candidate_eids(rule)
    if not _channel_seen(rule, p):
        svc = str(rule.logsource.get("service"))
        return Viability(rule, "DEAD_EVENTS", f"log channel for service '{svc}' never seen", missing_service=svc)
    if eids is not None:
        seen = {e for e in eids if p.by_eid.get(e)}
        if not seen:
            collected = sorted({ch for e in eids if (ch := expected_channel(e)) and p.channels.get(ch)})
            if collected:
                # the channel is there; the event may just be rare (a log clear, a new service) or its audit
                # subcategory / Sysmon config may be off. Absence in one window is not proof of a blind spot.
                return Viability(rule, "UNOBSERVED",
                                 f"'{', '.join(collected)}' is collected but {', '.join(source_name(e) for e in sorted(eids))} "
                                 f"never appeared: verify audit policy / Sysmon config (may just be rare)",
                                 missing_eids=set(eids))
            return Viability(rule, "DEAD_EVENTS", "needs " + ", ".join(source_name(e) for e in sorted(eids)),
                             missing_eids=set(eids))
    else:
        seen = None
    need = required_fields(rule)
    if need:
        pools = {e: p.fields_by_eid.get(e, set()) for e in seen} if seen is not None else {None: p.all_fields}
        # the rule can fire if at least one candidate event type carries every required field
        if not any(need <= flds for flds in pools.values()):
            missing = {e: need - flds for e, flds in pools.items()}
            desc = "; ".join(f"{source_name(e) if e is not None else 'events'} lack {', '.join(sorted(m))}"
                             for e, m in missing.items())
            return Viability(rule, "DEAD_FIELDS", desc, missing_fields={e: m for e, m in missing.items() if e is not None})
    return Viability(rule, "LIVE")


# ---------- coverage + recommendations ----------

@dataclass
class Recommendation:
    action: str
    revives: list[Rule]

    @property
    def techniques(self) -> set[str]:
        return {t for r in self.revives for t in r.attack_ids}


def recommendations(vs: list[Viability], live_techs: set[str], status: str = "DEAD") -> list[Recommendation]:
    """status='DEAD' -> concrete telemetry fixes; status='UNOBSERVED' -> things to verify (channel is collected,
    the event just never appeared - maybe rare, maybe its audit subcategory is off)."""
    buckets: dict[str, list[Rule]] = defaultdict(list)
    for v in vs:
        if status == "UNOBSERVED":
            if v.status == "UNOBSERVED":
                for eid in v.missing_eids:
                    buckets[f"Verify {source_name(eid)} is enabled"].append(v.rule)
            continue
        if v.status == "DEAD_EVENTS" and v.missing_service:
            buckets[f"Collect the '{v.missing_service}' log channel"].append(v.rule)
        elif v.status == "DEAD_EVENTS" and v.missing_eids:
            for eid in v.missing_eids:  # enabling any one candidate source revives the rule
                buckets[f"Collect {source_name(eid)}"].append(v.rule)
        elif v.status == "DEAD_FIELDS":
            for eid, flds in v.missing_fields.items():
                for f in flds:
                    fix = FIELD_FIXES.get((eid, f))
                    buckets[fix or f"Populate field '{f}' on {source_name(eid)}"].append(v.rule)
    recs = [Recommendation(a, rs) for a, rs in buckets.items()]
    # rank by *new* techniques gained first, then by rules revived
    recs.sort(key=lambda r: (len(r.techniques - live_techs), len(r.revives)), reverse=True)
    return recs


def coverage(vs: list[Viability]) -> dict[str, dict[str, set[str]]]:
    """tactic -> {'live': ..., 'unverified': only UNOBSERVED rules, 'blind': only dead rules}"""
    live_t, unv_t, all_t = defaultdict(set), defaultdict(set), defaultdict(set)
    for v in vs:
        tactic = v.rule.meta.get("kill_chain", "Unmapped")
        for t in v.rule.attack_ids:
            all_t[tactic].add(t)
            if v.status == "LIVE":
                live_t[tactic].add(t)
            elif v.status == "UNOBSERVED":
                unv_t[tactic].add(t)
    return {tac: {"live": live_t[tac], "unverified": unv_t[tac] - live_t[tac],
                  "blind": all_t[tac] - live_t[tac] - unv_t[tac]} for tac in all_t}


# ---------- log health ----------

@dataclass
class HealthIssue:
    kind: str       # MISSING_SOURCE | WENT_SILENT
    host: str
    channel: str
    detail: str


def health(events: list[dict], p: Profile, buckets: int = 24, min_events: int = 20,
           min_silence_hours: float = 6) -> list[HealthIssue]:
    issues: list[HealthIssue] = []
    hosts = [h for h in p.host_channels if h]
    # 1) a channel most hosts send, missing from some host
    if len(hosts) >= 3:
        for ch, total in p.channels.items():
            have = [h for h in hosts if p.host_channels[h].get(ch)]
            if total >= min_events and len(have) >= max(2, len(hosts) * 0.5):
                for h in hosts:
                    if h not in have:
                        issues.append(HealthIssue("MISSING_SOURCE", h, ch,
                                                  f"{len(have)}/{len(hosts)} hosts send '{ch}', {h} sends none"))
    # 2) a source that was active, then stopped while the rest of the data kept flowing. Needs a long window:
    #    in a 30-minute capture "PowerShell stopped" is the attacker finishing, not logging breaking.
    if p.start and p.end and (p.end - p.start).total_seconds() >= min_silence_hours * 3600:
        span = (p.end - p.start).total_seconds()
        bucket = lambda t: min(int((t - p.start).total_seconds() / span * buckets), buckets - 1)
        activity: dict[tuple, Counter] = defaultdict(Counter)
        overall = Counter()
        for e in events:
            b = bucket(e["TimeCreated"])
            overall[b] += 1
            activity[(str(e.get("Computer", "")).split(".")[0].upper(), str(e.get("Channel", "")).lower())][b] += 1
        tail = max(2, buckets // 6)
        tail_live = sum(overall[b] for b in range(buckets - tail, buckets)) > 0
        for (h, ch), c in activity.items():
            if sum(c.values()) < min_events or len(c) < 3 or not tail_live:
                continue
            last = max(c)
            if last < buckets - tail:
                t = p.start + (p.end - p.start) * ((last + 1) / buckets)
                issues.append(HealthIssue("WENT_SILENT", h, ch,
                                          f"{sum(c.values())} events, then nothing after ~{t.strftime('%Y-%m-%d %H:%M')} "
                                          f"while other sources kept logging"))
    return issues


# ---------- report ----------

TACTIC_COLUMNS = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
                  "Privilege Escalation", "Defense Evasion", "Stealth", "Defense Impairment", "Credential Access",
                  "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"]


@dataclass
class BlindspotResult:
    profile: Profile
    viability: list[Viability]
    recs: list[Recommendation]
    verify: list[Recommendation]
    cov: dict
    issues: list[HealthIssue]

    def _by(self, status):
        return [v for v in self.viability if v.status == status]

    @property
    def live(self):
        return self._by("LIVE")

    @property
    def unobserved(self):
        return self._by("UNOBSERVED")

    @property
    def dead_events(self):
        return self._by("DEAD_EVENTS")

    @property
    def dead_fields(self):
        return self._by("DEAD_FIELDS")

    @property
    def techniques(self) -> tuple[set[str], set[str], set[str]]:
        """(detectable, unverified, blind) - each technique counted once, at its best status."""
        pick = lambda k: set().union(*(c[k] for c in self.cov.values())) if self.cov else set()
        live = pick("live")
        unv = pick("unverified") - live
        return live, unv, pick("blind") - live - unv

    def technique_status(self) -> dict[str, tuple[str, dict[str, str]]]:
        """technique -> (best status, {rule title: status}) for the ATT&CK matrix."""
        rank = {"LIVE": 3, "UNOBSERVED": 2, "DEAD_FIELDS": 1, "DEAD_EVENTS": 1}
        out: dict[str, tuple[str, dict[str, str]]] = {}
        for v in self.viability:
            for t in v.rule.attack_ids:
                best, rules = out.get(t, ("DEAD_EVENTS", {}))
                rules[v.rule.title] = v.status
                out[t] = (max(best, v.status, key=lambda s: rank[s]), rules)
        return out


def analyse(rules: list[Rule], events: list[dict], p: Profile | None = None) -> BlindspotResult:
    """`p` lets the lake supply a profile computed in DuckDB; `events` is then only used for silence checks."""
    p = p or profile(events)
    vs = [assess(r, p) for r in rules]
    live_t = {t for v in vs if v.status == "LIVE" for t in v.rule.attack_ids}
    return BlindspotResult(p, vs, recommendations(vs, live_t), recommendations(vs, live_t, "UNOBSERVED"),
                           coverage(vs), health(events, p))


def markdown(res: BlindspotResult, top: int = 15) -> str:
    live_t, unv_t, blind_t = res.techniques
    n = max(len(res.viability), 1)
    lines = [
        "# ChainHunter Blindspot — what can you actually detect?", "",
        f"Telemetry: **{res.profile.events:,} events**, {len(res.profile.by_eid)} event IDs, "
        f"{len([c for c in res.profile.channels if c])} channels, {len([h for h in res.profile.host_channels if h])} hosts.", "",
        "| | Rules | Share |", "|---|---|---|",
        f"| Can fire here (live) | {len(res.live):,} | {len(res.live) / n:.0%} |",
        f"| Unverified: channel collected, event never seen (rare, or audit policy off) | {len(res.unobserved):,} | {len(res.unobserved) / n:.0%} |",
        f"| Dead: required log source not collected | {len(res.dead_events):,} | {len(res.dead_events) / n:.0%} |",
        f"| Dead: events present, required field always empty | {len(res.dead_fields):,} | {len(res.dead_fields) / n:.0%} |",
        "",
        f"**ATT&CK techniques:** {len(live_t)} detectable · {len(unv_t)} unverified · {len(blind_t)} blind",
        "", "## Telemetry fixes (proven gaps)", "",
        "| # | Change | Rules revived | New techniques |", "|---|---|---|---|",
    ]
    for i, r in enumerate(res.recs[:top], 1):
        new = sorted(r.techniques - live_t)
        lines.append(f"| {i} | {r.action} | {len(r.revives)} | {len(new)}: {', '.join(new[:6])}{' …' if len(new) > 6 else ''} |")
    lines += ["", "## Verify (channel collected, event not seen in this window)", "",
              "| # | Check | Rules affected | Techniques |", "|---|---|---|---|"]
    for i, r in enumerate(res.verify[:top], 1):
        lines.append(f"| {i} | {r.action} | {len(r.revives)} | {len(r.techniques - live_t)} |")
    lines += ["", "## Coverage by tactic", "", "| Tactic | Detectable | Unverified | Blind |", "|---|---|---|---|"]
    for tac, c in sorted(res.cov.items(), key=lambda kv: -len(kv[1]["blind"])):
        lines.append(f"| {tac} | {len(c['live'])} | {len(c['unverified'])} | {len(c['blind'])} |")
    lines += ["", "## Log health", ""]
    if res.issues:
        lines += ["| Issue | Host | Channel | Detail |", "|---|---|---|---|"]
        lines += [f"| {i.kind} | {i.host} | {i.channel} | {i.detail} |" for i in res.issues]
    else:
        lines.append("No missing sources or silent sources detected.")
    return "\n".join(lines) + "\n"


def _matrix(res: BlindspotResult) -> str:
    """ATT&CK-style matrix: one column per tactic, one cell per technique, coloured by detectability."""
    import html as _h
    e = _h.escape
    status = res.technique_status()
    cols: dict[str, set[str]] = defaultdict(set)
    for v in res.viability:
        tac = v.rule.meta.get("kill_chain")
        for t in v.rule.attack_ids:
            cols[tac if tac in TACTIC_COLUMNS else "Other"].add(t)
    cls = {"LIVE": "m-live", "UNOBSERVED": "m-unv", "DEAD_FIELDS": "m-blind", "DEAD_EVENTS": "m-blind"}
    label = {"LIVE": "can fire", "UNOBSERVED": "unverified", "DEAD_FIELDS": "dead (empty field)", "DEAD_EVENTS": "dead (no source)"}
    p = ["<div class='matrix'>"]
    for tac in [t for t in TACTIC_COLUMNS + ["Other"] if cols.get(t)]:
        techs = sorted(cols[tac], key=lambda t: ({"LIVE": 0, "UNOBSERVED": 1}.get(status[t][0], 2), t))
        p.append(f"<div class='mcol'><div class='mhead'>{e(tac)}<span>{len(techs)}</span></div>")
        for t in techs:
            best, rules = status[t]
            tip = "\n".join(f"{label[s]}: {title}" for title, s in sorted(rules.items(), key=lambda kv: kv[1])[:12])
            more = f"\n… {len(rules) - 12} more rules" if len(rules) > 12 else ""
            p.append(f"<a class='mcell {cls[best]}' href='https://attack.mitre.org/techniques/{e(t.replace('.', '/'))}/' "
                     f"target='_blank' rel='noopener' title='{e(t)} — {e(label[best])}\n{e(tip + more)}'>{e(t)}</a>")
        p.append("</div>")
    p.append("</div>")
    return "".join(p)


def html_page(res: BlindspotResult, top: int = 20) -> str:
    import html as _h
    from .report import _CSS
    e = _h.escape
    live_t, unv_t, blind_t = res.techniques
    n = max(len(res.viability), 1)
    css = (".bar{display:flex;height:22px;border-radius:6px;overflow:hidden;background:var(--chip)}"
           ".bar span{display:block;height:100%}.b-live,.m-live{background:var(--host)}.b-unv,.m-unv{background:var(--med)}"
           ".b-blind,.m-blind{background:var(--crit)}"
           ".matrix{display:flex;gap:6px;overflow-x:auto;padding-bottom:8px}.mcol{min-width:92px;flex:1}"
           ".mhead{font-size:11px;font-weight:700;min-height:44px;padding:4px;border-bottom:2px solid var(--line);margin-bottom:4px}"
           ".mhead span{display:block;color:var(--muted);font-weight:400}"
           ".mcell{display:block;font:11px ui-monospace,Consolas,monospace;color:#fff;text-decoration:none;padding:3px 5px;"
           "margin:2px 0;border-radius:4px}.mcell:hover{outline:2px solid var(--fg)}"
           ".legend{display:flex;gap:16px;font-size:13px;margin:6px 0 12px}.legend i{display:inline-block;width:12px;"
           "height:12px;border-radius:3px;margin-right:6px;vertical-align:-1px}")
    p = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,"
         f"initial-scale=1'><title>ChainHunter Blindspot</title><style>{_CSS}{css}</style></head><body><main>"
         f"<h1>Blindspot</h1><p class='muted'>What your rules can actually detect with the telemetry you actually collect "
         f"— {res.profile.events:,} events, {len([h for h in res.profile.host_channels if h])} hosts, "
         f"{len([c for c in res.profile.channels if c])} channels.</p><div class='stats'>"]
    for label, val in (("Rules that can fire", f"{len(res.live):,} ({len(res.live) / n:.0%})"),
                       ("Unverified (event not seen)", f"{len(res.unobserved):,}"),
                       ("Dead: source not collected", f"{len(res.dead_events):,}"),
                       ("Dead: field always empty", f"{len(res.dead_fields):,}"),
                       ("Techniques detectable", len(live_t)), ("Techniques blind", len(blind_t))):
        p.append(f"<div class='stat'><b>{e(str(val))}</b><span class='muted'>{label}</span></div>")
    p.append("</div><section class='chain'><h2>ATT&amp;CK coverage matrix</h2><p class='muted'>Every technique your rules "
             "cover, coloured by whether it can actually be detected on this telemetry. Hover for the rules, click to open "
             "the technique on attack.mitre.org.</p><div class='legend'><span><i class='m-live'></i>can fire</span>"
             "<span><i class='m-unv'></i>unverified: channel collected, event never seen</span>"
             "<span><i class='m-blind'></i>blind: source or field missing</span></div>")
    p.append(_matrix(res))
    p.append("</section><section class='chain'><h2>Telemetry fixes — proven gaps</h2><p class='muted'>The log source or "
             "field is definitely missing. Ranked by ATT&amp;CK techniques gained, then rules revived.</p><div class='tbl'>"
             "<table><tr><th>#</th><th>Change</th><th>Rules revived</th><th>New techniques</th></tr>")
    for i, r in enumerate(res.recs[:top], 1):
        new = sorted(r.techniques - live_t)
        p.append(f"<tr><td>{i}</td><td><b>{e(r.action)}</b></td><td>{len(r.revives)}</td>"
                 f"<td title='{e(', '.join(new))}'>{len(new)}</td></tr>")
    p.append("</table></div></section><section class='chain'><h2>Verify — channel collected, event never seen</h2>"
             "<p class='muted'>Not proof of a gap: the event may simply be rare (a log clear, a new service) in this window, "
             "or its audit subcategory / Sysmon rule may be off. Worth a 5-minute policy check.</p><div class='tbl'><table>"
             "<tr><th>#</th><th>Check</th><th>Rules affected</th><th>Techniques</th></tr>")
    for i, r in enumerate(res.verify[:top], 1):
        p.append(f"<tr><td>{i}</td><td>{e(r.action)}</td><td>{len(r.revives)}</td><td>{len(r.techniques - live_t)}</td></tr>")
    p.append("</table></div></section><section class='chain'><h2>Coverage by tactic</h2><div class='tbl'><table>"
             "<tr><th>Tactic</th><th style='width:45%'>Detectable / unverified / blind</th><th>Detectable</th>"
             "<th>Unverified</th><th>Blind</th></tr>")
    for tac, c in sorted(res.cov.items(), key=lambda kv: -sum(len(x) for x in kv[1].values())):
        tot = max(sum(len(x) for x in c.values()), 1)
        p.append(f"<tr><td>{e(tac)}</td><td><div class='bar'>"
                 + "".join(f"<span class='b-{k}' style='width:{len(c[key]) / tot:.1%}'></span>"
                           for k, key in (("live", "live"), ("unv", "unverified"), ("blind", "blind")))
                 + f"</div></td><td>{len(c['live'])}</td><td>{len(c['unverified'])}</td>"
                 f"<td title='{e(', '.join(sorted(c['blind'])))}'>{len(c['blind'])}</td></tr>")
    p.append("</table></div></section><section class='chain'><h2>Log health</h2>")
    if res.issues:
        p.append("<div class='tbl'><table><tr><th>Issue</th><th>Host</th><th>Channel</th><th>Detail</th></tr>")
        p += [f"<tr><td class='lvl high'>{e(i.kind)}</td><td>{e(i.host)}</td><td><code>{e(i.channel)}</code></td>"
              f"<td>{e(i.detail)}</td></tr>" for i in res.issues]
        p.append("</table></div>")
    else:
        p.append("<p>No missing sources or silent sources detected.</p>")
    p.append("</section><section class='chain'><h2>Rules that can't fire (or can't be confirmed)</h2><div class='filters'>"
             "<input type='search' class='f-dead' placeholder='Filter…'></div><div class='tbl'><table><tr><th>Rule</th>"
             "<th>Level</th><th>Status</th><th>Why</th></tr>")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    for v in sorted(res.dead_events + res.dead_fields + res.unobserved,
                    key=lambda v: (v.status == "UNOBSERVED", order.get(v.rule.level, 5), v.rule.title)):
        st = "unverified" if v.status == "UNOBSERVED" else "dead"
        p.append(f"<tr class='dead' data-text='{e((v.rule.title + ' ' + v.reason).lower())}'><td>{e(v.rule.title)}</td>"
                 f"<td class='lvl {e(v.rule.level)}'>{e(v.rule.level)}</td><td>{st}</td><td class='muted'>{e(v.reason)}</td></tr>")
    p.append("</table></div></section></main><script>const f=document.querySelector('.f-dead');f&&f.addEventListener('input',()=>"
             "{const t=f.value.toLowerCase();document.querySelectorAll('tr.dead').forEach(r=>r.style.display="
             "r.dataset.text.includes(t)?'':'none')})</script></body></html>")
    return "".join(p)

