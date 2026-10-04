"""Group detections into incidents (attack chains) and score entities with risk-based alerting.

Two detections join the same chain if they share an actor account, a source (IP/workstation),
or a target host, and fall within `window` of each other. Union-find keeps it transitive, so
account -> host -> reused account links stitch a multi-stage intrusion into one story.

Risk-based alerting (RBA): every detection adds risk to each entity it touches. An entity whose
risk crosses RISK_THRESHOLD, or that shows 4+ techniques across 3+ phases, is flagged — the same
model Splunk ES RBA uses to turn many low-fidelity signals into one high-fidelity alert.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from .detect import Detection
from .sequence import norm_entity

TACTIC_ORDER = ["Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
                "Privilege Escalation", "Defense Evasion", "Stealth", "Defense Impairment", "Credential Access",
                "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"]
ALERT_LEVELS = {"medium", "high", "critical"}
LEVEL_SCORE = {"informational": 1, "low": 2, "medium": 4, "high": 7, "critical": 10}
KIND_WEIGHT = {"signature": 1.0, "sequence": 1.5, "anomaly": 0.5}
RISK_THRESHOLD = 300


def risk_of(d: Detection) -> int:
    base = d.rule.meta.get("risk", LEVEL_SCORE.get(d.rule.level, 3) * 10)
    return int(base * KIND_WEIGHT.get(d.rule.kind, 1.0))


@dataclass
class EntityRisk:
    kind: str
    value: str
    score: int = 0
    techniques: set[str] = field(default_factory=set)
    phases: set[str] = field(default_factory=set)
    detections: int = 0

    @property
    def flagged(self) -> bool:
        return self.score >= RISK_THRESHOLD or (len(self.techniques) >= 4 and len(self.phases) >= 3)


@dataclass
class Chain:
    detections: list[Detection]
    entities: dict[str, set[str]] = field(default_factory=dict)
    risk: list[EntityRisk] = field(default_factory=list)

    @property
    def start(self):
        return self.detections[0].time

    @property
    def end(self):
        return max(d.end for d in self.detections)

    @property
    def phases(self) -> list[str]:
        """Phases in order of first occurrence, so the chain reads as the attack unfolded.

        Sequence detections confirm phases but don't set the order (they're stamped at their first stage);
        simultaneous detections tie-break on ATT&CK tactic order. Informational/low alerts are context, not
        story: on real APT29 data an informational "User Logoff" rule tagged Impact otherwise led the chain.
        """
        def rank(d):
            ph = d.rule.meta.get("kill_chain", "Unknown")
            return d.time, TACTIC_ORDER.index(ph) if ph in TACTIC_ORDER else 99
        story = [d for d in self.detections if d.rule.kind != "sequence" and d.rule.level in ALERT_LEVELS]
        base = sorted(story or [d for d in self.detections if d.rule.kind != "sequence"], key=rank)
        seq = [d for d in self.detections if d.rule.kind == "sequence"]
        return list(dict.fromkeys(d.rule.meta.get("kill_chain", "Unknown") for d in base + seq))

    @property
    def techniques(self) -> list[str]:
        return sorted({t for d in self.detections for t in d.rule.attack_ids})

    @property
    def score(self) -> int:
        """Severity sum (sequences weigh more, anomalies less) plus a bonus per distinct kill-chain phase."""
        base = sum(LEVEL_SCORE.get(d.rule.level, 3) * KIND_WEIGHT.get(d.rule.kind, 1) for d in self.detections)
        return int(base + 5 * len(self.phases))

    @property
    def severity(self) -> str:
        s = self.score
        return "Critical" if s >= 40 else "High" if s >= 20 else "Medium" if s >= 10 else "Low"

    @property
    def confidence(self) -> str:
        kinds = {d.rule.kind for d in self.detections}
        if "sequence" in kinds:
            return "High (confirmed multi-stage sequence)"
        if len(self.phases) >= 3:
            return "Medium (multiple correlated phases)"
        return "Low (single-stage signal)"


def _entities(d: Detection) -> list[tuple[str, str]]:
    ents = [(k, getattr(d, k)) for k in ("actor", "source", "host") if getattr(d, k)]
    ents += d.extra.get("entities", [])
    return list(dict.fromkeys(ents))


def _keys(d: Detection) -> set[str]:
    return {f"{k}:{norm_entity(v, k)}" for k, v in _entities(d)}


def entity_risk(detections: list[Detection]) -> list[EntityRisk]:
    table: dict[tuple[str, str], EntityRisk] = {}
    label = {"actor": "Account", "source": "Source", "host": "Host"}
    for d in detections:
        for k, v in _entities(d):
            key = (k, norm_entity(v, k))
            er = table.setdefault(key, EntityRisk(label[k], v))
            er.score += risk_of(d)
            er.techniques.update(d.rule.attack_ids)
            er.phases.add(d.rule.meta.get("kill_chain", "Unknown"))
            er.detections += 1
    return sorted(table.values(), key=lambda e: e.score, reverse=True)


def correlate(detections: list[Detection], window: timedelta = timedelta(hours=6)) -> list[Chain]:
    detections = sorted(detections, key=lambda d: d.time)
    n = len(detections)
    parent = list(range(n))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    # Linear-time linking. Link rule: j joins an earlier i that shares an entity key when
    # j.time - i.end <= window. For each key keep the earlier detection with the latest end: if *any* earlier
    # i qualifies, that one does, and every qualifying i is already connected to it - so the components are
    # identical to the all-pairs version (verified against it in tests). 95,700 detections: 61s -> <1s.
    best: dict[str, int] = {}
    for j, d in enumerate(detections):
        for k in _keys(d):
            i = best.get(k)
            if i is not None and d.time - detections[i].end <= window:
                parent[find(i)] = find(j)
            if i is None or d.end > detections[i].end:
                best[k] = j

    groups: dict[int, list[Detection]] = {}
    for i, d in enumerate(detections):
        groups.setdefault(find(i), []).append(d)

    chains = []
    for dets in groups.values():
        ents: dict[str, set[str]] = {"accounts": set(), "sources": set(), "hosts": set()}
        bucket = {"actor": "accounts", "source": "sources", "host": "hosts"}
        for d in dets:
            for k, v in _entities(d):
                ents[bucket[k]].add(v)
            target_field = d.rule.meta.get("collect_targets")
            for e in d.events:
                if target_field and e.get(target_field):
                    ents.setdefault("targeted", set()).add(e[target_field])
        chains.append(Chain(dets, ents, entity_risk(dets)))
    chains.sort(key=lambda c: c.score, reverse=True)
    return chains
