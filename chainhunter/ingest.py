"""Load events from EVTX, JSONL/NDJSON (flat or Elastic/Winlogbeat style) into one flat schema.

Normalized event = dict with at least:
    EventID (int), Channel, Computer, TimeCreated (datetime, UTC), plus EventData fields flattened
    (TargetUserName, IpAddress, TicketEncryptionType, SourceImage, TargetImage, ...).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

# Elastic/Winlogbeat field -> normalized field
ECS_MAP = {
    "event.code": "EventID",
    "winlog.event_id": "EventID",
    "winlog.channel": "Channel",
    "winlog.computer_name": "Computer",
    "host.name": "Computer",
    "@timestamp": "TimeCreated",
}


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
    return ev


def load_json(path: Path) -> Iterator[dict]:
    text = path.read_text(encoding="utf-8-sig")
    if text.lstrip().startswith("["):
        for raw in json.loads(text):
            yield normalize(raw)
        return
    for line in text.splitlines():
        if line.strip():
            yield normalize(json.loads(line))


def load_evtx(path: Path) -> Iterator[dict]:
    try:
        import Evtx.Evtx as evtx  # python-evtx
        import xml.etree.ElementTree as ET
    except ImportError as e:
        raise SystemExit("EVTX support needs python-evtx: pip install python-evtx") from e

    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    with evtx.Evtx(str(path)) as log:
        for record in log.records():
            root = ET.fromstring(record.xml())
            sysnode = root.find("e:System", ns)
            ev = {
                "EventID": int(sysnode.find("e:EventID", ns).text),
                "Channel": sysnode.findtext("e:Channel", default="", namespaces=ns),
                "Computer": sysnode.findtext("e:Computer", default="", namespaces=ns),
                "TimeCreated": parse_time(sysnode.find("e:TimeCreated", ns).get("SystemTime")),
            }
            for data in root.iterfind("e:EventData/e:Data", ns):
                if data.get("Name"):
                    ev[data.get("Name")] = data.text or ""
            yield ev


def load(paths: list[Path]) -> list[dict]:
    events: list[dict] = []
    for p in paths:
        files = sorted(p.rglob("*")) if p.is_dir() else [p]
        for f in files:
            suffix = f.suffix.lower()
            if suffix == ".evtx":
                events.extend(load_evtx(f))
            elif suffix in {".json", ".jsonl", ".ndjson"}:
                events.extend(load_json(f))
    events = [e for e in events if "TimeCreated" in e]
    events.sort(key=lambda e: e["TimeCreated"])
    return events
