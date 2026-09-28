"""Group detections into incidents (attack chains) by shared entities within a time window.

Two detections join the same chain if they share an actor account, a source (IP/workstation),
or a target host, and fall within `window` of each other. Union-find keeps it transitive, so
account -> host -> reused account links stitch a multi-stage intrusion into one story.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from .detect import Detection

LEVEL_SCORE = {"informational": 1, "low": 2, "medium": 4, "high": 7, "critical": 10}


@dataclass
class Chain:
    detections: list[Detection]
    entities: dict[str, set[str]] = field(default_factory=dict)

    @property
    def start(self):
        return self.detections[0].time

    @property
    def end(self):
        return self.detections[-1].end

    @property
    def phases(self) -> list[str]:
        """Phases in order of first occurrence, so the chain reads as the attack unfolded."""
        return list(dict.fromkeys(d.rule.meta.get("kill_chain", "Unknown") for d in self.detections))

    @property
    def score(self) -> int:
        """Severity sum plus a bonus per distinct kill-chain phase (breadth = real intrusion)."""
        base = sum(LEVEL_SCORE.get(d.rule.level, 3) for d in self.detections)
        return base + 5 * len(self.phases)

    @property
    def severity(self) -> str:
        s = self.score
        return "Critical" if s >= 40 else "High" if s >= 20 else "Medium" if s >= 10 else "Low"


def _keys(d: Detection) -> set[str]:
    keys = set()
    if d.actor:
        keys.add("acct:" + d.actor.lower().split("\\")[-1].split("@")[0])
    if d.source:
        keys.add("src:" + d.source.lower())
    if d.host:
        keys.add("host:" + d.host.lower().split(".")[0])
    return keys


def correlate(detections: list[Detection], window: timedelta = timedelta(hours=6)) -> list[Chain]:
    n = len(detections)
    parent = list(range(n))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    keys = [_keys(d) for d in detections]
    for i in range(n):
        for j in range(i + 1, n):
            if detections[j].time - detections[i].end > window:
                break
            if keys[i] & keys[j]:
                parent[find(i)] = find(j)

    groups: dict[int, list[Detection]] = {}
    for i, d in enumerate(detections):
        groups.setdefault(find(i), []).append(d)

    chains = []
    for dets in groups.values():
        dets.sort(key=lambda d: d.time)
        ents = {"accounts": set(), "sources": set(), "hosts": set()}
        for d in dets:
            if d.actor:
                ents["accounts"].add(d.actor)
            if d.source:
                ents["sources"].add(d.source)
            if d.host:
                ents["hosts"].add(d.host)
            target_field = d.rule.meta.get("collect_targets")
            for e in d.events:
                if target_field and e.get(target_field):
                    ents.setdefault("targeted", set()).add(e[target_field])
        chains.append(Chain(dets, ents))
    chains.sort(key=lambda c: c.score, reverse=True)
    return chains
