"""Attack-story views for large incidents, modelled on how XDR consoles present an incident:

  * alert groups   - the same rule on the same host collapses into one row (count, first/last seen)
  * host swimlane  - alerts over time, one lane per host, so lateral movement is visible at a glance
  * process tree   - parent/child lineage of every alerting process, rebuilt from Sysmon ProcessGuids

On real APT29 telemetry this turns 1,910 raw alerts into ~100 groups, three host lanes and a process tree
that starts at the RLO-masqueraded payload launched from explorer.exe.
"""
from __future__ import annotations

import html
from dataclasses import dataclass, field

from .correlate import ALERT_LEVELS, Chain, risk_of
from .detect import Detection

LEVEL_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
RLO = "‮"  # right-to-left override: makes 'cod.3aka3.scr' render as 'rcs.3aka3.doc'
GUID_FIELDS = ("ProcessGuid", "SourceProcessGuid", "SourceProcessGUID")


def short_host(h: str) -> str:
    return h.split(".")[0] if h and not h.replace(".", "").isdigit() else h


def show(s: str) -> str:
    """Make hidden characters visible instead of letting them reorder the text on screen."""
    return str(s).replace(RLO, "[U+202E]")


@dataclass
class AlertGroup:
    detections: list[Detection] = field(default_factory=list)

    @property
    def rule(self):
        return self.detections[0].rule

    @property
    def host(self) -> str:
        return self.detections[0].host

    @property
    def first(self):
        return self.detections[0].time

    @property
    def last(self):
        return max(d.end for d in self.detections)

    @property
    def level(self) -> str:
        return self.rule.level

    @property
    def count(self) -> int:
        return len(self.detections)

    @property
    def events(self) -> list[dict]:
        return [e for d in self.detections for e in d.events]

    @property
    def actors(self) -> list[str]:
        return sorted({d.actor for d in self.detections if d.actor})

    @property
    def risk(self) -> int:
        return sum(risk_of(d) for d in self.detections)


def group_alerts(c: Chain) -> list[AlertGroup]:
    groups: dict[tuple, AlertGroup] = {}
    for d in c.detections:
        groups.setdefault((d.rule.id, short_host(d.host).lower()), AlertGroup()).detections.append(d)
    for g in groups.values():
        g.detections.sort(key=lambda d: d.time)
    return sorted(groups.values(), key=lambda g: g.first)


# ---------- host swimlane ----------

SEV_COLOR = {"critical": "var(--crit)", "high": "var(--high)", "medium": "var(--med)",
             "low": "var(--low)", "informational": "var(--low)"}


def swimlane(c: Chain) -> str:
    e = html.escape
    dets = [d for d in c.detections if d.rule.level in ALERT_LEVELS and d.rule.kind != "sequence"] or c.detections
    lanes: list[str] = []
    for d in sorted(dets, key=lambda d: d.time):
        h = short_host(d.host) or "unknown"
        if h not in lanes:
            lanes.append(h)
    t0, t1 = min(d.time for d in dets), max(d.time for d in dets)
    span = max((t1 - t0).total_seconds(), 1)
    W, LEFT, RIGHT, LANE, TOP = 1320, 130, 20, 54, 30
    H = TOP + LANE * len(lanes) + 34
    x = lambda t: LEFT + (t - t0).total_seconds() / span * (W - LEFT - RIGHT)
    p = [f"<svg class='lane' viewBox='0 0 {W} {H}' role='img' aria-label='Alerts over time by host'>"]
    for i, h in enumerate(lanes):
        y = TOP + i * LANE
        p.append(f"<rect class='lanebg' x='{LEFT}' y='{y + 6}' width='{W - LEFT - RIGHT}' height='{LANE - 12}' rx='6'/>"
                 f"<text class='lanelbl' x='{LEFT - 12}' y='{y + LANE / 2 + 4}' text-anchor='end'>{e(h)}</text>")
    for k in range(6):  # time axis
        t = t0 + (t1 - t0) * (k / 5)
        xx = x(t)
        p.append(f"<line class='tick' x1='{xx}' x2='{xx}' y1='{TOP}' y2='{H - 30}'/>"
                 f"<text class='ticklbl' x='{xx}' y='{H - 12}' text-anchor='middle'>{t.strftime('%H:%M:%S')}</text>")
    first_on_lane: dict[str, float] = {}
    for d in sorted(dets, key=lambda d: (LEVEL_ORDER.get(d.rule.level, 0), d.time)):
        h = short_host(d.host) or "unknown"
        cy = TOP + lanes.index(h) * LANE + LANE / 2
        r = {"critical": 6.5, "high": 5.5}.get(d.rule.level, 4)
        p.append(f"<circle cx='{x(d.time):.1f}' cy='{cy}' r='{r}' fill='{SEV_COLOR.get(d.rule.level)}' "
                 f"data-host='{e(h)}'><title>{e(d.time.strftime('%H:%M:%S'))} · {e(h)} · {e(d.rule.level)}\n"
                 f"{e(d.rule.title)}</title></circle>")
        first_on_lane[h] = min(first_on_lane.get(h, 1e12), x(d.time))
    for i, h in enumerate(lanes[1:], 1):  # mark where the intrusion reaches each new host
        xx = first_on_lane[h]
        y = TOP + i * LANE
        near_edge = xx > W - 180  # keep the label inside the chart
        p.append(f"<path class='hop' d='M{xx},{y - LANE / 2 + 6} L{xx},{y + 8}'/>"
                 f"<text class='hoplbl' x='{xx - 6 if near_edge else xx + 6}' y='{y + 2}' "
                 f"text-anchor='{'end' if near_edge else 'start'}'>first alert on {e(h)}</text>")
    p.append("</svg>")
    return "".join(p)


# ---------- process tree ----------

def process_index(events: list[dict]) -> dict[str, dict]:
    idx: dict[str, dict] = {}
    for ev in events:
        if ev.get("EventID") != 1 or not ev.get("ProcessGuid"):
            continue
        g = str(ev["ProcessGuid"]).lower()
        idx[g] = {"image": ev.get("Image", ""), "cmd": ev.get("CommandLine", ""), "user": ev.get("User", ""),
                  "host": ev.get("Computer", ""), "time": ev.get("TimeCreated"),
                  "parent": str(ev.get("ParentProcessGuid", "")).lower(), "parent_image": ev.get("ParentImage", "")}
    return idx


def process_tree(c: Chain, idx: dict[str, dict], max_nodes: int = 260) -> str:
    """Render the lineage of every process that raised a medium+ alert (plus its ancestors)."""
    if not idx:
        return ""
    e = html.escape
    flagged: dict[str, dict[str, str]] = {}
    for d in c.detections:
        if d.rule.level not in ALERT_LEVELS:
            continue
        for ev in d.events:
            for f in GUID_FIELDS:
                g = str(ev.get(f, "")).lower()
                if g in idx:
                    cur = flagged.setdefault(g, {})
                    cur[d.rule.title] = max(cur.get(d.rule.title, d.rule.level), d.rule.level, key=lambda l: LEVEL_ORDER.get(l, 0))
                    break
    if not flagged:
        return ""
    ranked = sorted(flagged, key=lambda g: (-max(LEVEL_ORDER.get(l, 0) for l in flagged[g].values()), idx[g]["time"]))
    nodes: set[str] = set()
    for g in ranked:
        chain, cur, depth = [], g, 0
        while cur in idx and cur not in nodes and depth < 15:
            chain.append(cur)
            cur, depth = idx[cur]["parent"], depth + 1
        if len(nodes) + len(chain) > max_nodes:
            break
        nodes.update(chain)
    children: dict[str, list[str]] = {}
    roots = []
    for g in nodes:
        par = idx[g]["parent"]
        (children.setdefault(par, []) if par in nodes else roots).append(g)
    for lst in list(children.values()) + [roots]:
        lst.sort(key=lambda g: idx[g]["time"])

    def node(g: str) -> str:
        p = idx[g]
        img = show(p["image"])
        name = img.rsplit("\\", 1)[-1] or img
        badges = "".join(f"<span class='badge {lvl}' title='{e(t)}'>{e(t)}</span>"
                         for t, lvl in sorted(flagged.get(g, {}).items(), key=lambda kv: -LEVEL_ORDER.get(kv[1], 0)))
        rlo = "<span class='badge critical'>hidden RLO character in filename</span>" if RLO in str(p["image"]) else ""
        kids = children.get(g, [])
        inner = "".join(node(k) for k in kids)
        cls = "proc hit" if g in flagged else "proc"
        return (f"<li><div class='{cls}'><b>{e(name)}</b> <span class='muted'>{e(show(p['user']))} · "
                f"{e(p['time'].strftime('%H:%M:%S')) if p['time'] else ''}</span>{rlo}{badges}"
                f"<div class='cmd'>{e(show(p['cmd']))[:400]}</div></div>"
                + (f"<ul>{inner}</ul>" if inner else "") + "</li>")

    by_host: dict[str, list[str]] = {}
    for r in roots:
        by_host.setdefault(short_host(idx[r]["host"]), []).append(r)
    out = [f"<p class='muted'>{len(flagged)} alerting processes and their ancestry "
           f"({len(nodes)} nodes). Highlighted rows raised alerts.</p>"]
    for h, rs in sorted(by_host.items(), key=lambda kv: min(idx[r]["time"] for r in kv[1])):
        out.append(f"<div class='ptree-host'><h4>{e(h)}</h4><ul class='ptree'>{''.join(node(r) for r in rs)}</ul></div>")
    return "".join(out)
