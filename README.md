# ChainHunter

**Alerts aren't incidents.** ChainHunter ingests Windows logs, runs Sigma-style detections, links the hits into one attack chain (shared accounts, source hosts and target systems within a time window), and writes the incident report for you.

```
[+] 836 events | 6 rules | 7 detections | 1 chain(s)
    Incident 1: Critical score=75  Lateral Movement -> Credential Access -> Privilege Escalation -> Impact
[+] Wrote out\report.md, timeline.html, attack_layer.json
```

<!-- TODO: add demo GIF / timeline screenshot here -->

## What it produces
| Output | What it is |
|---|---|
| `report.md` | Incident report in the CDSA commercial format: Executive Summary → Technical Analysis (numbered steps with Objective / Query / Figure / Finding / Kill Chain + ATT&CK) → IOC table → Timeline |
| `timeline.html` | Self-contained interactive timeline per correlated incident (light/dark, mobile-friendly) |
| `attack_layer.json` | MITRE ATT&CK Navigator layer, so you can see detection coverage as a heatmap |

Every detection also ships with equivalent **KQL (Elastic)** and **SPL (Splunk)** hunting queries, so findings can be reproduced in either SIEM.

## Quick start
```bash
pip install -e ".[evtx,dev]"
python samples/make_demo.py            # synthetic GOAD-style dataset
chainhunter samples/goad_demo.jsonl -o out
pytest -q
```

Inputs: `.evtx`, or `.json/.jsonl/.ndjson` exports (flat, or Elastic/Winlogbeat `winlog.event_data.*` documents). Directories are scanned recursively.

## How it works
```
ingest  ──►  detect  ──►  correlate  ──►  report
EVTX/JSON    Sigma-subset   union-find on     Markdown (CDSA) / HTML / ATT&CK layer
normalize    + burst        account ∪ source
             thresholds     ∪ host, in window
```
* **Detection engine:** a dependency-light Sigma subset (selections, `contains/startswith/endswith/re/all` modifiers, `and/or/not`, `1 of`/`all of`). ChainHunter-specific metadata lives under a `chainhunter:` key: kill-chain phase, entity fields, burst `threshold`, and SIEM queries.
* **Correlation:** two detections join the same chain if they share an entity and fall inside the window. Because the grouping is transitive, *account → host → reused account* hops stitch a multi-stage intrusion together.
* **Scoring:** severity sum plus a bonus for each distinct kill-chain phase. Breadth across phases is what separates a real intrusion from noise.

## Detection pack (v1)
| ID | Detection | ATT&CK |
|---|---|---|
| ch-0001 | Kerberoasting: RC4 service-ticket burst vs AES baseline | T1558.003 |
| ch-0002 | LSASS access via comsvcs.dll MiniDump | T1003.001 |
| ch-0003 | NTLM network logon from unmanaged workstation name | T1550.002, T1078 |
| ch-0004 | Directory replication by non-machine account (DCSync) | T1003.006 |
| ch-0005 | Member added to privileged group | T1098 |
| ch-0006 | Security/System event log cleared | T1070.001 |

Every rule is unit-tested with positive **and** negative cases (see `tests/`), and CI runs the full pipeline on each push.

## Roadmap
- **v2:** entity graph view (networkx + interactive graph), chain-scoring tuning, Navigator export per incident
- **v3:** detection-as-code: test every rule against public attack datasets (EVTX-ATTACK-SAMPLES, OTRF Security-Datasets) in CI, plus pySigma conversion to KQL/SPL/EQL
- **v4:** live Elastic/Splunk connectors, LLM-drafted executive summary

## Background
Built from a real threat hunt I ran in an Elastic lab: a GOAD Active Directory forest compromised through stolen credentials, credential dumping and replication abuse. I reconstructed that chain by hand; ChainHunter automates the reconstruction. The bundled dataset is **synthetic and fictional**.

## License
MIT
