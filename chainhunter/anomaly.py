"""UEBA-lite: behavioural detections learned from a baseline period, no signatures required.

The first `baseline` fraction of the dataset's time span is treated as normal. After it:
  * first-seen authentication source — an IP never seen authenticating during the baseline
  * host fan-out — an account reaching more distinct hosts within an hour than anyone did in the baseline
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from .detect import Detection, Rule

AUTH_EVENTS = {4624, 4625, 4648, 4768, 4769, 4771, 4776}
IGNORED_SOURCES = {"", "-", "::1", "127.0.0.1", "0.0.0.0"}


def _rule(rid, title, desc, tags, kill_chain, level, kql, spl) -> Rule:
    return Rule(id=rid, title=title, level=level, description=desc, tags=tags, detection={},
                meta={"kill_chain": kill_chain, "queries": {"kql": kql, "spl": spl}},
                path=Path("<anomaly>"), kind="anomaly")


FIRST_SEEN = _rule(
    "ch-a001", "First-Seen Authentication Source",
    "Identify authentication from a source address never observed during the baseline period — "
    "new infrastructure presenting valid credentials.",
    ["attack.initial_access", "attack.t1078"], "Initial Access", "medium",
    "event.code:(4624 or 4768 or 4769 or 4776) and source.ip:{src}",
    "index=wineventlog EventCode IN (4624,4768,4769,4776) src_ip={src} | stats min(_time) as first_seen count by src_ip, user, host",
)
FAN_OUT = _rule(
    "ch-a002", "Anomalous Host Fan-Out",
    "Identify an account authenticating to more distinct hosts within one hour than any account did "
    "during the baseline — typical of lateral movement or remote discovery.",
    ["attack.lateral_movement", "attack.t1021"], "Lateral Movement", "medium",
    "event.code:4624 and winlog.event_data.LogonType:3 and winlog.event_data.TargetUserName:{actor}",
    "index=wineventlog EventCode=4624 Logon_Type=3 user={actor} | bin _time span=1h | stats dc(host) as hosts by _time, user",
)


def detect_anomalies(events: list[dict], baseline: float = 0.25) -> list[Detection]:
    auth = [e for e in events if e.get("EventID") in AUTH_EVENTS]
    if len(auth) < 20:
        return []
    t0, t1 = events[0]["TimeCreated"], events[-1]["TimeCreated"]
    cutoff = t0 + (t1 - t0) * baseline
    base = [e for e in auth if e["TimeCreated"] <= cutoff]
    live = [e for e in auth if e["TimeCreated"] > cutoff]
    out: list[Detection] = []

    known = {str(e.get("IpAddress", "")) for e in base}
    new_src: dict[str, list[dict]] = {}
    for e in live:
        src = str(e.get("IpAddress", "")).removeprefix("::ffff:")
        if src not in IGNORED_SOURCES and src not in known:
            new_src.setdefault(src, []).append(e)
    for src, evs in new_src.items():
        d = Detection(rule=FIRST_SEEN, events=evs, actor=str(evs[0].get("TargetUserName", "")),
                      host=str(evs[0].get("Computer", "")), source=src,
                      extra={"accounts": sorted({str(e.get("TargetUserName")) for e in evs if e.get("TargetUserName")})})
        d.extra["queries"] = {k: v.format(src=src) for k, v in FIRST_SEEN.meta["queries"].items()}
        out.append(d)

    def max_fan_out(evs):
        per_acct: dict[str, list[dict]] = {}
        for e in evs:
            if e.get("EventID") == 4624 and str(e.get("LogonType")) in ("3", "10") and e.get("TargetUserName"):
                per_acct.setdefault(str(e["TargetUserName"]).lower(), []).append(e)
        best = {}
        for acct, xs in per_acct.items():
            for i, e in enumerate(xs):
                window = [x for x in xs[i:] if x["TimeCreated"] - e["TimeCreated"] <= timedelta(hours=1)]
                hosts = {x.get("Computer") for x in window}
                if len(hosts) > best.get(acct, (0,))[0]:
                    best[acct] = (len(hosts), window)
        return best

    base_max = max((v[0] for v in max_fan_out(base).values()), default=0)
    threshold = max(4, base_max + 2)
    for acct, (n, window) in max_fan_out(live).items():
        if n >= threshold:
            d = Detection(rule=FAN_OUT, events=window, actor=acct, host=str(window[0].get("Computer", "")),
                          source=str(window[0].get("IpAddress", "")), extra={"distinct_hosts": n, "baseline_max": base_max})
            d.extra["queries"] = {k: v.format(actor=acct) for k, v in FAN_OUT.meta["queries"].items()}
            out.append(d)
    out.sort(key=lambda d: d.time)
    return out
