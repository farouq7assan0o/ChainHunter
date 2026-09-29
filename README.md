# ChainHunter

**Alerts aren't incidents.** ChainHunter ingests Windows logs and runs four detection layers: Sigma signatures, ordered multi-stage sequences, UEBA-style anomalies and risk-based alerting. It links the results into one attack chain and writes the incident report.

```
[+] 836 events | 9 rules | 7 signature hits | 3 sequences | 1 anomalies | 1 incident(s)
    Incident 1: Critical score=127  Initial Access -> Lateral Movement -> Credential Access -> Privilege Escalation -> Impact
      ! Source  192.168.101.51                           risk=750  T1003.001, T1003.006, T1078, T1078.002, T1550.002, T1558.003
      ! Host    castelblack.north.sevenkingdoms.local    risk=540  T1003.001, T1078, T1078.002, T1550.002, T1558.003
      ! Account rickon.stark                             risk=440  T1003.001, T1078, T1078.002, T1550.002, T1558.003
```

<!-- TODO: add screenshot of report.html attack graph (focus mode on an account) -->

## Why it's different
| Layer | What it catches | Why it matters |
|---|---|---|
| **Signatures** | Sigma rules; SigmaHQ-compatible via logsource → EventID mapping | Known technique patterns |
| **Sequences** | Ordered steps joined on entities, e.g. *account Kerberoasted → same account logs on* | Proves the attack *progressed* (the crack worked), not just that it was attempted |
| **Anomalies (UEBA-lite)** | First-seen auth sources and host fan-out, learned from a baseline window | Catches the attacker with **zero signatures**; in the demo it independently flags the attacker IP |
| **Risk-based alerting** | Risk scored per entity across all layers, flagged when it crosses a threshold or spans many techniques and phases | Turns many weak signals into one high-fidelity alert, the Splunk ES RBA model |
| **Correlation** | Union-find over shared accounts, sources and hosts within a time window | One incident with ordered kill-chain phases instead of 11 separate alerts |

## Outputs
| File | Contents |
|---|---|
| `report.md` | CDSA-format incident report: Executive Summary (with auto-drafted containment actions for flagged entities) → RBA table → numbered technical steps (Objective / KQL-SPL-EQL / Figure / Finding / Kill Chain + ATT&CK) → IOCs → Timeline |
| `report.html` | Interactive report: **attack graph** (sources → accounts → hosts, click a node to focus its path and timeline), RBA table, timeline with hunting queries and raw evidence drawers. Light and dark themes. |
| `attack_layer.json` | ATT&CK Navigator heatmap of detected techniques |
| `incidents.json` | Machine-readable incidents for SOAR or ticketing hand-off |

## Quick start
```bash
pip install -e ".[evtx,dev]"
python samples/make_demo.py                 # synthetic GOAD-style dataset
chainhunter hunt samples/goad_demo.jsonl -o out
chainhunter validate -v                     # lint + embedded tests + ATT&CK coverage
chainhunter convert --to eql                # compile rules to KQL / SPL / EQL
pytest -q
```
Inputs: `.evtx`, or `.json/.jsonl/.ndjson` (flat, or Elastic/Winlogbeat `winlog.event_data.*`). Security 4688 fields are aliased to Sysmon names, so one `process_creation` rule covers both.

Bring your own Sigma: `chainhunter hunt logs/ -r rules -r path/to/sigma/rules/windows`. Rules that use unsupported modifiers are skipped with a warning; they don't crash the run.

## Detection-as-code
Every rule carries its own positive and negative test cases:
```yaml
tests:
  match:   [ {EventID: 4662, SubjectUserName: bob,    Properties: "{1131f6aa-...}"} ]
  nomatch: [ {EventID: 4662, SubjectUserName: "DC01$", Properties: "{1131f6aa-...}"} ]
```
`chainhunter validate` lints each rule (condition references, ATT&CK tags, level, sequence step and join integrity, translatability), runs its tests and prints ATT&CK coverage. It exits non-zero on failure, so CI blocks broken detections from merging.

## The Sigma compiler
Rules compile from their detection logic, so queries never drift from what the engine runs:
```
sequence with maxspan=14400s
  [any where ((event.code == "4769" and winlog.event_data.TicketEncryptionType : "0x17") and not ...)] by winlog.event_data.ServiceName
  [any where (event.code == "4624" and (winlog.event_data.LogonType : "3" or ...))] by winlog.event_data.TargetUserName
```
Sequence rules compile to native **EQL `sequence ... by`**, so the same cracked-credential-reuse logic can be deployed as a live Elastic detection rule. Signature rules also compile to KQL and to SPL (with `bin | stats | where` for thresholds).

## Rule pack
| ID | Type | Detection | ATT&CK |
|---|---|---|---|
| ch-0001 | signature | Kerberoasting: RC4 service-ticket burst vs AES baseline | T1558.003 |
| ch-0002 | signature | LSASS access via comsvcs.dll MiniDump | T1003.001 |
| ch-0003 | signature | NTLM network logon from unmanaged workstation name | T1550.002, T1078 |
| ch-0004 | signature | Directory replication by non-machine account (DCSync) | T1003.006 |
| ch-0005 | signature | Member added to privileged group | T1098 |
| ch-0006 | signature | Security/System event log cleared | T1070.001 |
| ch-s001 | sequence | Kerberoasted account later authenticates (cracked credential reuse) | T1558.003 → T1078.002 |
| ch-s002 | sequence | Unmanaged-host logon → LSASS access on the same host | T1550.002 → T1003.001 |
| ch-s003 | sequence | Account from unmanaged host → directory replication | T1078 → T1003.006 |
| ch-a001 | anomaly | First-seen authentication source | T1078 |
| ch-a002 | anomaly | Anomalous host fan-out | T1021 |

## Architecture
```
ingest ─► signatures ─► sequences ─► anomalies ─► correlate + RBA ─► report
EVTX/ECS   Sigma engine   ordered,      baseline-     union-find on       MD (CDSA) / HTML graph /
normalize  + thresholds   entity-joined  learned       entities, entity    Navigator / JSON
+ aliases                 steps                        risk scoring
```

## Roadmap
- Test rules in CI against public attack datasets (EVTX-ATTACK-SAMPLES, OTRF Security-Datasets)
- Live Elastic/Splunk connectors, and pushing compiled EQL sequences as Elastic detection rules
- LLM-drafted executive summary grounded in `incidents.json`

## Background
Built from a real threat hunt I ran in an Elastic lab: a GOAD Active Directory forest compromised through stolen credentials, credential dumping and replication abuse. I reconstructed that chain by hand over hours; ChainHunter reconstructs it in under a second. The bundled dataset is **synthetic and fictional**.

## License
MIT
