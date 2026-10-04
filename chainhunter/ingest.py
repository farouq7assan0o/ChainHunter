"""Load events from EVTX, JSONL/NDJSON (flat, Elastic/Winlogbeat, or OTRF/Mordor style) into one flat schema.

Normalized event = dict with at least:
    EventID (int), Channel, Provider, Computer, TimeCreated (datetime, UTC), plus EventData/UserData
    fields flattened (TargetUserName, IpAddress, TicketEncryptionType, SourceImage, TargetImage, ...).

Real-world normalisation (each of these broke detections on real telemetry before it was added):
  * hex fields are canonicalised: GrantedAccess 0x00001010 -> 0x1010, Status 0x00000006 -> 0x6
  * IPv4-mapped IPv6 (::ffff:172.16.66.1) is reduced to IPv4, so one attacker is one source
  * string values are stripped (LogonProcessName is logged as "NtLmSsp " with a trailing space)
  * <UserData> is read, so 1102 "log cleared" keeps the SubjectUserName that did it
  * unnamed <Data> elements (Application/ESENT logs) land in Data1..DataN plus a joined `Data`
  * Security 4688 fields are aliased to Sysmon names so one process_creation rule covers both
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

# Elastic/Winlogbeat/OTRF field -> normalized field
ECS_MAP = {
    "event.code": "EventID",
    "winlog.event_id": "EventID",
    "winlog.channel": "Channel",
    "winlog.provider_name": "Provider",
    "winlog.computer_name": "Computer",
    "host.name": "Computer",
    "Hostname": "Computer",
    "SourceName": "Provider",
    "@timestamp": "TimeCreated",
    "TimeGenerated": "TimeCreated",  # Sentinel SecurityEvent (Windows events forwarded to Log Analytics)
}

# Native Security-log names -> Sysmon names, so one Sigma rule covers both sources
ALIASES = {
    4688: {"NewProcessName": "Image", "ParentProcessName": "ParentImage", "SubjectUserName": "User"},
}

IP_FIELDS = {"IpAddress", "SourceIp", "DestinationIp", "SourceAddress", "DestAddress", "ClientAddress"}
HEX_FIELDS = {"GrantedAccess", "AccessMask", "Status", "SubStatus", "FailureCode", "TicketEncryptionType",
              "TicketOptions", "UserAccountControl"}


def _canon_hex(v):
    s = str(v).strip()
    if s.lower().startswith("0x"):
        try:
            return hex(int(s, 16))
        except ValueError:
            return s
    return s


MOJIBAKE_MARKERS = ("â€", "Ã", "Â")


def fix_mojibake(s: str) -> str:
    """Undo UTF-8 text that was mis-decoded as Windows-1252 and re-saved. Real case: OTRF's APT29 export
    stores the U+202E right-to-left override in 'cod.3aka3.scr' as 'â€®', hiding the masquerade trick."""
    if not any(m in s for m in MOJIBAKE_MARKERS):
        return s
    try:
        return s.encode("cp1252").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return s


def apply_aliases(ev: dict) -> dict:
    for k, v in list(ev.items()):
        if isinstance(v, str):
            v = fix_mojibake(v.strip())
            ev[k] = _canon_hex(v) if k in HEX_FIELDS else v
    for k in IP_FIELDS & ev.keys():
        if isinstance(ev[k], str) and ev[k].lower().startswith("::ffff:"):
            ev[k] = ev[k][7:]
    for src, dst in ALIASES.get(ev.get("EventID"), {}).items():
        if src in ev and dst not in ev:
            ev[dst] = ev[src]
    # SigmaHQ calls the event provider `Provider_Name`; 86 of its Windows rules silently never fired without this
    if ev.get("Provider") and "Provider_Name" not in ev:
        ev["Provider_Name"] = ev["Provider"]
    elif ev.get("Provider_Name") and "Provider" not in ev:
        ev["Provider"] = ev["Provider_Name"]
    return ev


def _flatten(obj: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in obj.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.update(_flatten(v, key))
        else:
            out[key] = v
    return out


def parse_time(value) -> datetime:
    if isinstance(value, datetime):
        dt = value
    else:
        s = str(value).strip().replace("Z", "+00:00")
        # trim >6 fractional digits (Windows emits 7)
        if "." in s:
            head, tail = s.split(".", 1)
            frac = "".join(c for c in tail if c.isdigit())
            rest = tail[len(frac):]
            s = f"{head}.{frac[:6]}{rest}"
        dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def normalize(raw: dict) -> dict:
    from .cloud import normalize_cloud
    cloud = normalize_cloud(raw)  # Sentinel tables / Defender XDR rows
    if cloud is not None:
        return apply_aliases(cloud)
    flat = _flatten(raw)
    ev: dict = {}
    for k, v in flat.items():
        if k in ECS_MAP:
            ev.setdefault(ECS_MAP[k], v)
        elif k.startswith("winlog.event_data."):
            ev[k.split(".", 2)[2]] = v
        else:
            ev.setdefault(k.split(".")[-1] if k.startswith("EventData.") else k, v)
    if "EventID" in ev:
        ev["EventID"] = int(ev["EventID"])
    if "TimeCreated" in ev:
        ev["TimeCreated"] = parse_time(ev["TimeCreated"])
    return apply_aliases(ev)


def load_json(path: Path) -> Iterator[dict]:
    text = path.read_text(encoding="utf-8-sig")
    if text.lstrip().startswith("["):
        for raw in json.loads(text):
            yield normalize(raw)
        return
    for line in text.splitlines():
        if line.strip():
            yield normalize(json.loads(line))


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def event_from_xml(root) -> dict:
    """One Windows <Event> element (from an EVTX file or live `wevtutil qe /f:xml`) -> ChainHunter event."""
    sysnode = root.find("e:System", NS)
    provider = sysnode.find("e:Provider", NS)
    ev = {
        "EventID": int(sysnode.find("e:EventID", NS).text),
        "Channel": sysnode.findtext("e:Channel", default="", namespaces=NS),
        "Provider": provider.get("Name", "") if provider is not None else "",
        "Computer": sysnode.findtext("e:Computer", default="", namespaces=NS),
        "TimeCreated": parse_time(sysnode.find("e:TimeCreated", NS).get("SystemTime")),
    }
    rid = sysnode.findtext("e:EventRecordID", default="", namespaces=NS)
    if rid:
        ev["EventRecordID"] = int(rid)
    unnamed = []
    for data in root.iterfind("e:EventData/e:Data", NS):
        if data.get("Name"):
            ev[data.get("Name")] = data.text or ""
        elif data.text:
            unnamed.append(data.text)
    for i, text in enumerate(unnamed, 1):
        ev[f"Data{i}"] = text
    if unnamed:
        ev["Data"] = " | ".join(unnamed)
    userdata = root.find("e:UserData", NS)
    if userdata is not None:
        for wrapper in userdata:
            for child in wrapper:
                if child.text and child.text.strip():
                    ev.setdefault(_local(child.tag), child.text)
    return apply_aliases(ev)


def load_evtx(path: Path) -> Iterator[dict]:
    try:
        import Evtx.Evtx as evtx  # python-evtx
        import xml.etree.ElementTree as ET
    except ImportError as e:
        raise SystemExit("EVTX support needs python-evtx: pip install python-evtx") from e
    with evtx.Evtx(str(path)) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
            except Exception as ex:  # corrupt/partial records exist in real logs; skip, don't die
                print(f"[!] {path.name}: skipped unparsable record ({ex.__class__.__name__})", file=sys.stderr)
                continue
            yield event_from_xml(root)


SUPPORTED = {".evtx", ".json", ".jsonl", ".ndjson"}


class NoEventsError(SystemExit):
    """Raised instead of silently analysing nothing: an empty input once produced a report claiming every
    rule was dead, which looks exactly like a real (and alarming) result."""


def load(paths: list[Path]) -> list[dict]:
    events: list[dict] = []
    for p in paths:
        if not p.exists():
            raise NoEventsError(f"[x] input not found: {p}\n    Point ChainHunter at a real .evtx/.json/.jsonl file or a folder "
                                f"containing them (e.g. datasets\\cache\\otrf\\...json).")
        files = [f for f in (sorted(p.rglob("*")) if p.is_dir() else [p]) if f.suffix.lower() in SUPPORTED]
        if not files:
            raise NoEventsError(f"[x] no supported log files in: {p}\n    Supported: {', '.join(sorted(SUPPORTED))}")
        for f in files:
            events.extend(load_evtx(f) if f.suffix.lower() == ".evtx" else load_json(f))
    events = [e for e in events if "TimeCreated" in e]
    if not events:
        raise NoEventsError(f"[x] 0 events loaded from {', '.join(map(str, paths))}: the files contain no parsable "
                            f"Windows events. Nothing to analyse.")
    events.sort(key=lambda e: e["TimeCreated"])
    return events
