"""Live mode: detect and correlate as events arrive.

    chainhunter watch -r rules                                  # this machine's Windows logs (run as admin)
    chainhunter watch -r rules --channel Security --channel Microsoft-Windows-Sysmon/Operational --interval 5
    chainhunter watch -r rules --replay datasets/cache/otrf/apt29_...json --speed 120   # stream a recording

Sources
  * live: polls `wevtutil qe <channel> /q:*[System[EventRecordID>N]]` per channel (built into Windows), tracking
    the last record id so nothing is read twice. Security and Sysmon need an elevated terminal; channels that
    can't be read are reported once, not silently skipped.
  * replay: streams a recorded dataset in timestamp order at N x speed through the same engine, so live mode
    can be demonstrated and tested without admin rights or a live attack.

Engine: a sliding window (default 6h) of recent events and detections. Each tick runs signature rules on the
new events, re-evaluates sequences over the window, correlates, and announces new alerts, new incidents and
severity escalations. Alerts are also appended to a JSONL file for a SIEM/SOAR to pick up.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .correlate import ALERT_LEVELS, correlate
from .detect import Detection, Rule, run
from .ingest import event_from_xml, load
from .sequence import run_sequences

DEFAULT_CHANNELS = ["Security", "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-PowerShell/Operational",
                    "System"]
SEVERITY_RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


# ---------- sources ----------

class WindowsSource:
    def __init__(self, channels: list[str], backfill_minutes: int = 0):
        self.channels = list(channels)
        self.last: dict[str, int] = {}
        self.problems: dict[str, str] = {}
        for ch in self.channels:  # start at "now" (or N minutes back) so the first tick isn't the whole log
            self.last[ch] = self._latest_id(ch, backfill_minutes)

    def _run(self, args: list[str]) -> tuple[int, str]:
        try:
            p = subprocess.run(["wevtutil", *args], capture_output=True, text=True, encoding="utf-8", errors="replace",
                               timeout=60)
            return p.returncode, p.stdout if p.returncode == 0 else (p.stderr or p.stdout)
        except FileNotFoundError:
            return 1, "wevtutil not found (live mode needs Windows; use --replay elsewhere)"
        except subprocess.TimeoutExpired:
            return 1, "wevtutil timed out"

    def _latest_id(self, ch: str, backfill_minutes: int) -> int:
        code, out = self._run(["qe", ch, "/c:1", "/rd:true", "/f:xml"])
        if code != 0:
            self.problems[ch] = out.strip().splitlines()[0] if out.strip() else "cannot read channel"
            return 0
        events = self._parse(out)
        if not events:
            return 0
        latest = events[0].get("EventRecordID", 0)
        if backfill_minutes:  # step back: find the first record inside the window
            ms = backfill_minutes * 60_000
            code, out = self._run(["qe", ch, f"/q:*[System[TimeCreated[timediff(@SystemTime) <= {ms}]]]",
                                   "/c:1", "/f:xml"])
            first = self._parse(out) if code == 0 else []
            return (first[0].get("EventRecordID", latest) - 1) if first else latest
        return latest

    @staticmethod
    def _parse(xml_text: str) -> list[dict]:
        out = []
        body = xml_text.strip()
        if not body:
            return out
        try:
            root = ET.fromstring(f"<Events>{body}</Events>" if not body.startswith("<Events") else body)
        except ET.ParseError:
            return out
        for node in root:
            try:
                out.append(event_from_xml(node))
            except Exception:  # a malformed record must not kill the watcher
                continue
        return out

    def poll(self) -> list[dict]:
        batch = []
        for ch in self.channels:
            if ch in self.problems:
                continue
            code, out = self._run(["qe", ch, f"/q:*[System[EventRecordID>{self.last[ch]}]]", "/f:xml"])
            if code != 0:
                self.problems[ch] = out.strip().splitlines()[0] if out.strip() else "read failed"
                continue
            events = self._parse(out)
            if events:
                self.last[ch] = max(e.get("EventRecordID", 0) for e in events)
                batch.extend(events)
        batch.sort(key=lambda e: e["TimeCreated"])
        return batch


class ReplaySource:
    """Streams a recording in timestamp order: each poll advances a simulated clock by interval x speed."""

    def __init__(self, paths: list[Path], interval: float, speed: float):
        self.events = load(paths)
        self.step = timedelta(seconds=interval * speed)
        self.clock = self.events[0]["TimeCreated"] if self.events else None
        self.pos = 0
        self.problems: dict[str, str] = {}

    @property
    def done(self) -> bool:
        return self.pos >= len(self.events)

    def poll(self) -> list[dict]:
        if self.done:
            return []
        self.clock += self.step
        start = self.pos
        while self.pos < len(self.events) and self.events[self.pos]["TimeCreated"] <= self.clock:
            self.pos += 1
        return self.events[start:self.pos]


# ---------- engine ----------

def _dkey(d: Detection) -> tuple:
    # no event count: a threshold burst that grows across polls is still the same alert
    return (d.rule.id, d.time.isoformat(), d.host, d.actor)


@dataclass
class Engine:
    rules: list[Rule]
    window: timedelta = timedelta(hours=6)
    min_level: str = "medium"
    events: list[dict] = field(default_factory=list)
    signatures: list[Detection] = field(default_factory=list)
    seen: set = field(default_factory=set)
    incidents: dict = field(default_factory=dict)   # first-detection key -> severity
    counters: dict = field(default_factory=lambda: {"events": 0, "alerts": 0, "incidents": 0})

    def _levels(self) -> set[str]:
        order = ["informational", "low", "medium", "high", "critical"]
        return set(order[order.index(self.min_level):])

    def ingest(self, batch: list[dict]) -> list[str]:
        """Process one batch; return human-readable announcements (also the unit under test)."""
        out: list[str] = []
        if not batch:
            return out
        self.counters["events"] += len(batch)
        self.events.extend(batch)
        now = max(e["TimeCreated"] for e in batch)
        horizon = now - self.window
        self.events = [e for e in self.events if e["TimeCreated"] >= horizon]
        self.signatures = [d for d in self.signatures if d.end >= horizon]
        # per-event rules only need the new batch; threshold (burst) rules are re-evaluated over the whole window,
        # otherwise one burst split across two polls becomes two alerts (seen with DCSync in replay)
        self.signatures += run([r for r in self.rules if not r.meta.get("threshold")], batch)
        bursts = run([r for r in self.rules if r.meta.get("threshold")], self.events)
        current = self.signatures + bursts
        seqs = run_sequences(self.rules, current, self.events)
        levels = self._levels()
        for d in sorted(current + seqs, key=lambda d: d.time):
            k = _dkey(d)
            if k in self.seen:
                continue
            self.seen.add(k)
            if d.rule.level in levels:
                self.counters["alerts"] += 1
                tag = " [SEQUENCE]" if d.rule.kind == "sequence" else ""
                out.append(f"ALERT    {d.time:%Y-%m-%d %H:%M:%S}  {d.rule.level:<8} {d.rule.title}{tag}  "
                           f"host={d.host or '-'} actor={d.actor or '-'}")
        for c in correlate(current + seqs, self.window):
            if not any(d.rule.level in ALERT_LEVELS for d in c.detections):
                continue
            key = _dkey(c.detections[0])
            prev = self.incidents.get(key)
            if prev is None:
                self.incidents[key] = c.severity
                self.counters["incidents"] += 1
                out.append(f"INCIDENT {c.severity:<8} opened: {len(c.detections)} detections, "
                           f"{len(c.entities['hosts'])} host(s), {' -> '.join(c.phases)}")
            elif SEVERITY_RANK.get(c.severity, 0) > SEVERITY_RANK.get(prev, 0):
                self.incidents[key] = c.severity
                out.append(f"INCIDENT {c.severity:<8} escalated from {prev}: {len(c.detections)} detections, "
                           f"{' -> '.join(c.phases)}")
        return out


def watch(source, engine: Engine, interval: float, alerts_file: Path | None = None, max_ticks: int | None = None,
          sleep=time.sleep, echo=print) -> dict:
    reported: set[str] = set()
    ticks = 0
    fh = alerts_file.open("a", encoding="utf-8") if alerts_file else None
    try:
        while max_ticks is None or ticks < max_ticks:
            ticks += 1
            batch = source.poll()
            for ch, why in source.problems.items():
                if ch not in reported:
                    reported.add(ch)
                    echo(f"[!] cannot read channel {ch}: {why}  (run the terminal as administrator?)")
            for line in engine.ingest(batch):
                echo(line)
                if fh:
                    fh.write(json.dumps({"time": datetime.now(timezone.utc).isoformat(), "message": line}) + "\n")
                    fh.flush()
            if isinstance(source, ReplaySource) and source.done:
                break
            sleep(interval)
    except KeyboardInterrupt:
        echo("[i] stopped")
    finally:
        if fh:
            fh.close()
    return engine.counters
