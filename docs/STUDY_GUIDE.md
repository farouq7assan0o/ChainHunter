# ChainHunter Study Guide

Everything this project taught: how the pieces work, every bug that real data exposed, the performance lessons, and the limits. Each lesson is written so you can explain it in an interview.

**How to read it.** Part A gives the concepts. Part B is the most valuable: real problems, each written as **Symptom → How it was found → Fix → Concept → Interview question**. Part C covers performance, Part D the honest limits, and Part E maps the project to SOC interview questions.

---

## Part A: How ChainHunter works

### A1. The pipeline
```
logs ──► ingest/normalise ──► signatures ──► sequences ──► anomalies ──► correlate + risk ──► reports
(EVTX, JSON,  (one flat schema)   (Sigma)      (ordered,     (baseline)   (incidents,          (MD, HTML,
 Sentinel)                                     joined)                     entity risk)         JSON, Navigator)
```
- **Normalise first.** Every source (EVTX, Winlogbeat/Elastic JSON, OTRF JSON, Sentinel tables, Defender XDR) becomes one flat event with `EventID`, `Channel`, `Computer`, `TimeCreated` and its fields. Rules are only as good as this step: most bugs in Part B are normalisation bugs.
- **Detection is layered.** Each layer catches what the others miss: signatures find known patterns, sequences prove progression, anomalies need no signature at all, and risk scoring turns many weak signals into one strong one.

### A2. Sigma rules (signature layer)
- **`logsource`** says *where* a rule applies: `product` (windows / azure / m365), `category` (e.g. `process_creation` = Sysmon 1 or Security 4688) or `service` (e.g. `security` = the Security channel).
- **`detection`** holds named **selections** (field: value maps) and a **condition** (`selection and not filter`, `1 of sel_*`).
  - Within a map, fields are ANDed and a list of values is ORed.
- **Modifiers** change how a value matches: `contains`, `startswith`, `endswith`, `re` (regex), `cidr`, `all` (every value must match), `windash` (`-` or `/`).
- `Field: null` means "the field is absent or empty".
- **Keyword selections** (a bare list of strings) search every value in the event.
- ChainHunter parses the condition into a small syntax tree (AST) and evaluates it per event. The SQL compiler and Blindspot reuse the same tree.

### A3. Sequences (multi-stage rules)
- A sequence is **ordered steps within a time window**, joined on entities. Example: `roast.ServiceName = use.actor` means the account whose ticket was roasted later logs on, i.e. the offline crack *worked*.
- A step either references another rule or matches raw events inline.
- **Join operands** are `step.field`: `actor`, `host`, `source`, any raw field, or `domain`, which is derived from host FQDNs and `user@domain` names. The `domain` join is what links Golden SAML stages that share nothing else (see B19).
- **Why it matters:** "Kerberoasting attempted" is medium severity. "A roasted account then logged in" is a confirmed compromise.

### A4. Correlation (incidents)
- Two detections belong to the same incident if they **share an entity key** (account, source or host, normalised) and are **within the time window**.
- **Union-find** makes it transitive: account → host → another account chains a whole intrusion together.
- **Normalisation of entities:** `DOMAIN\user` and `user@domain` both become `user`. Only *hosts* drop their DNS suffix (`castelblack.north.local` = `CASTELBLACK`); account names keep their dots, so `jon.snow` ≠ `jon.arryn` (a bug once merged them, see B21).
- **Linear-time linking (C9):** for each key, remember the earlier detection with the latest end time. A new detection joins it if it's within the window. This gives exactly the same incidents as comparing every pair.

### A5. Risk-based alerting (RBA)
- Every detection adds risk to every entity it touches: level × weight, where sequences weigh 1.5× and anomalies 0.5×.
- An entity is flagged when its risk crosses a threshold **or** it shows 4+ techniques across 3+ phases.
- This is the Splunk ES RBA idea: many low-fidelity signals on one entity become one high-fidelity alert.

### A6. Anomalies (UEBA-lite)
- The first 25% of the time span is the **baseline**.
- **First-seen source:** an IP authenticating that never appeared in the baseline.
- **Host fan-out:** an account reaching more distinct hosts within an hour than anyone did in the baseline.
- No signature is needed: in the demo it independently flags the attacker's IP.

### A7. Blindspot (true coverage)
For each rule, Blindspot asks whether it can ever fire on *these* logs:
- **DEAD, no source:** the required event IDs or log channel were never collected.
- **DEAD, empty field:** the events exist, but a field the rule needs is always empty. The classic case is 4688 without the "Include command line" GPO.
- **UNVERIFIED:** the channel is collected, but the event ID never appeared. It may just be rare (see B15).
- **LIVE:** the rule can fire.

Two rules keep it honest:
- Required event IDs are **over-approximated**, so a rule is never wrongly called dead.
- Required fields are **under-approximated**, so a rule never claims to need more than it does.

### A8. The lake (scale layer)
- **Parquet** is columnar and compressed: 368 MB of JSON became 5.2 MB. A query reads only the columns it needs.
- **DuckDB** is an embedded, vectorised, multi-threaded SQL engine, with no server.
- **Superset pre-filter + exact re-check.** Each rule compiles to SQL that may match *more* rows than the rule, never fewer. Python then re-checks each returned row with the real matcher, so results are **identical by construction**. Parity was proven: 189 = 189 detections on 30 recordings, also tested with 2 workers.
- **Polarity-aware widening.** A Sigma feature SQL can't express becomes TRUE in a positive position and FALSE under NOT. Either way the SQL can only admit more rows.
- **Fan-out (`--workers`).** Files are split across processes. Hits are merged **before** thresholds, so a burst split across files still counts.

### A9. Live mode
- Polls `wevtutil` per channel and tracks `EventRecordID`, so nothing is read twice.
- A sliding window holds recent events and detections. Each poll: run rules on the new events, re-run burst rules over the window (B18), re-run sequences, correlate, announce new alerts, incidents and escalations.

### A10. Suppression guardrails
- **Scoped:** a rule plus conditions, never a global mute.
- **Attributed and expiring.** Critical rules need `allow_critical`.
- **Sequences run on unsuppressed hits,** so muting a noisy step can't hide the chain it belongs to.
- **Impact check:** the pipeline is replayed with and without the suppression. It's **RISKY** if it hides an incident's earliest alert, a host's first sign of compromise, or a whole phase.

### A11. Grounded AI analyst
- The model only sees an **evidence pack** (`E1…En`) and must cite IDs for every sentence.
- **The verifier, not the model, decides what's supported.** A sentence fails if it cites nothing, cites a fake ID, or mentions a host, account, IP or ATT&CK ID that isn't in the evidence it cites.
- *Status:* tested with a fake model. Not yet run against a real local model (see Part D).

---

## Part B: What real data taught

### B1. Zero-padded hex values
- **Symptom:** an LSASS access rule matching `GrantedAccess: 0x1010` never fired on real Mimikatz data.
- **How found:** I printed real field values from the EVTX-ATTACK-SAMPLES recordings.
- **Fix:** canonicalise hex fields at ingest (`0x00001010` → `0x1010`; also `Status`, `AccessMask`, `TicketEncryptionType`).
- **Concept:** equality on unnormalised data fails *silently*. No error, just no detection.
- **Interview Q:** "Your rule looks right but never fires. How do you debug it?" → Check the raw field values in real logs. Format differences (padding, case, spaces, encoding) are the usual cause.

### B2. IPv4-mapped IPv6
- **Symptom:** one attacker appeared as two sources, `172.16.66.1` and `::ffff:172.16.66.1`.
- **Fix:** reduce `::ffff:` addresses to IPv4.
- **Concept:** entity normalisation decides whether correlation sees one attacker or two.

### B3. Event 1102 keeps its data in `<UserData>`
- **Symptom:** "Security log cleared" alerts had no account.
- **Fix:** read `<UserData>` as well as `<EventData>`.
- **Concept:** not every Windows event stores its fields in the same XML structure.

### B4. Unnamed `<Data>` fields (ESENT / Application log)
- **Symptom:** ntdsutil events (325/326/327) had no searchable fields.
- **Fix:** store them as `Data1..N` plus a joined `Data` field.

### B5. Trailing spaces
- **Symptom:** `LogonProcessName` is logged as `"NtLmSsp "`.
- **Fix:** strip string values at ingest.

### B6. Double-encoded text hid the attacker's trick
- **Symptom:** the APT29 payload showed as `â€®cod.3aka3.scr`, and SigmaHQ's right-to-left-override rule didn't fire.
- **How found:** I looked at the raw bytes: `E2 80 AE` (U+202E in UTF-8) had been mis-read as Windows-1252 and saved again.
- **Fix:** repair that kind of mojibake at ingest (encode as cp1252, decode as UTF-8, only when the telltale markers are present). Genuine accented names are left alone.
- **Concept:** a data-pipeline encoding bug can disable a detection completely. After the fix, the RLO rule fired on the real initial-access payload.
- **Interview Q:** "What's an RLO filename?" → U+202E reverses how the text after it is displayed, so `cod.3aka3.scr` shows as `rcs.3aka3.doc`: a screensaver executable disguised as a document.

### B7. `logsource.service` wasn't enforced
- **Symptom:** an *Application-log* antivirus keyword rule fired on a *Sysmon* event whose path contained "mimikatz".
- **How found:** I read the titles of SigmaHQ hits on real data, not just their count.
- **Fix:** restrict each rule to its service's channel.
- **Concept:** where a rule applies matters as much as what it matches.

### B8. Unmapped categories matched everything
- **Symptom:** a `file_change` rule fired on `dns.exe` *network* connections.
- **Fix:** map every category to its Sysmon event IDs. Categories needing telemetry ChainHunter doesn't ingest (ETW `file_access`) are skipped, not guessed.

### B9. `Provider_Name`: 86 rules silently dead
- **Symptom:** Blindspot said "Moriya Rootkit: System 7045 lacks `Provider_Name`".
- **Fix:** populate both `Provider` and `Provider_Name`.
- **Result:** 44 rules came to life, and the ntdsutil attack was newly detected (benchmark 24/30 → 25/30).
- **Concept:** one field-name mismatch can disable dozens of rules with no error at all.

### B10. Event-ID collisions between providers
- **Symptom:** SigmaHQ's "WMI Event Subscription" (Sysmon 19/20/21) fired on APT29.
- **How found:** Blindspot said Sysmon WMI events were never collected, which contradicted the hit. Blindspot was right.
- **Root cause:** Kernel-Boot writes event 20 and TerminalServices writes event 21. Event IDs are only unique **per provider**.
- **Fix:** Sysmon-range IDs (1–29) only count when they come from the Sysmon channel.
- **Concept:** an event ID without its provider/channel is ambiguous. Two independent analyses disagreeing is a great bug detector.

### B11. Field names differing only by case
- **Symptom:** building the lake failed with a "duplicate column" error.
- **Root cause:** real APT29 data has both `IpAddress` and `Ipaddress`, and DuckDB column names are case-insensitive.
- **Fix:** merge case-variants into one column and keep every original spelling queryable.

### B12. ATT&CK renamed a tactic
- **Symptom:** SigmaHQ rules showed phase "Unknown".
- **Root cause:** ATT&CK v18 split Defense Evasion into **Stealth** and **Defense Impairment**, and SigmaHQ uses the new names (with hyphens: `attack.defense-impairment`).
- **Fix:** support old and new names, and both hyphen and underscore.

### B13. Informational alerts distorted the story
- **Symptom:** the APT29 kill chain started with "Impact", from an informational "User Logoff Event" rule.
- **Fix:** build the attack story from medium+ alerts and keep informational/low as context.
- **Concept:** a kill chain should show the attack's progression, not every log line.

### B14. Empty input produced a confident report
- **Symptom:** a placeholder path (`path\to\logs`) produced a Blindspot page claiming 2,385 dead rules.
- **Fix:** a missing path, a folder without log files, or zero events now stop with a clear error.
- **Concept:** a tool that measures blind spots must never be silently blind itself.

### B15. Rare event ≠ blind spot
- **Symptom:** Blindspot advised "collect Security 1102 (audit log cleared)".
- **Why that was wrong:** 1102 only exists when someone clears a log. Its absence from a 33-minute recording proves nothing.
- **Fix:** if the channel is collected but the event never appeared, mark it **UNVERIFIED** ("verify the audit policy"), not DEAD.
- **Concept:** absence of evidence vs evidence of absence.

### B16. Same data, two pipelines, two field names (cloud)
- **Symptom:** SigmaHQ's Azure rules use `properties.message` and `userAgent` (the diagnostic-export shape); Sentinel exports the same data as `ActivityDisplayName` and `UserAgent`.
- **Fix:** populate both names at ingest.
- **And a dash:** real Entra ID writes `Update application – Certificates and secrets management ` (en-dash plus a trailing space), while SigmaHQ's rule uses a hyphen. The rule never fired until operation names were normalised.
- **Interview Q:** "How do SIEM connectors affect detection?" → The same event arrives with different field names and formats depending on the connector, so rules must target the normalised schema, and you test them on data from *your* connector.

### B17. Platform isolation
- **Risk:** a Windows keyword rule could fire on an Entra ID record that happens to contain the word.
- **Fix:** tag every event with its platform (`azure`, `m365`, `m365d` or Windows) and enforce the rule's `product`.

### B18. A burst split across two polls (live mode)
- **Symptom:** DCSync alerted twice in replay.
- **Root cause:** threshold rules were evaluated per batch.
- **Fix:** re-evaluate burst rules over the whole sliding window, and keep an alert's identity stable as its burst grows.
- **Concept:** streaming detection needs state. The same idea applies to multi-process fan-out, where hits are merged before thresholds.

### B19. Golden SAML: no shared entity
- **Situation:** the on-prem stage (an uncommon process reading the ADFS database on `ADFS01`) and the cloud stage (app credentials added for `pgustavo@…`) share no account, IP or host. With Golden SAML the cloud identity can be forged.
- **Fix:** a `domain` join. `ADFS01.simulandlabs.com` serves `simulandlabs.com`, the same domain as the cloud identity. Rule `ch-s004` turns the two stages into one Critical incident.
- **Interview Q:** "Why is Golden SAML hard to detect?" → Forged tokens look like valid sign-ins, and the on-prem key theft and the cloud activity share no identity. You correlate the federation server with its federated domain, and you monitor access to the ADFS signing material.

### B20. Loud ≠ false positive
- **Situation:** rule health marked two rules as TUNE (very loud) on APT29.
- **Why they were loud:** APT29's Python implant was triggering them.
- **Lesson:** on attack data, "loud" can be the attack. The advice is "scope it or add a reviewed suppression", never "delete it", and the impact check exists for exactly this.

### B21. Over-eager normalisation merged two accounts
- **Symptom:** clicking `jon.snow` in the graph highlighted the wrong items.
- **Root cause:** the normaliser cut everything after the first dot, so `jon.snow` became `jon`, and `jon.arryn` would merge with it.
- **Fix:** only hosts drop their DNS suffix.

---

## Part C: Performance (and measuring honestly)

| Problem (measured) | Fix | Result |
|---|---|---|
| ~2,400 rules × 196k events in pure Python | EventID index: each rule only scans the event types it can match | hours → ~7 min |
| Lake v1: `SELECT *` per rule, 136 ms each even with 0 matches (389 columns) | batched scans return only row ids; matched rows fetched once | 322 s → 69 s |
| "Vulnerable Driver Load" spent **10.7 s planning** on a lake with no driver events | long value lists → one regex; rules whose event types are absent are never run | 69 s → 32 s |
| One RE2-invalid regex (`⠀`) failed a whole batch of 100 rules | validate patterns at compile time, widen invalid ones | no rescans |
| A ~100-keyword rule rescanned an all-columns string 100 times | one regex pass; prune rules whose channel is absent | 100 s → ~0 |
| 22 rules fell back to fetching whole event types | polarity-aware widening | 0 fallbacks, 0 skipped |
| Matched rows came back with all 389 columns | projection to the ~61 columns rules use | memory fix |
| Correlation compared every pair (~92M comparisons) | linear-time algorithm, checked against the old one on randomised trials | 61 s → 2 s |
| One process on 4 cores | `--workers 4` | 600–670 s → 394 s |

Measurement lessons:
- **Profile before optimising.** Almost every fix above came from timing phases first. Grouping rules by event type, for example, did *nothing* on APT29: it only had 4 row groups to skip. Even a reasonable idea is a guess until it's measured.
- **The measuring tool can change the result.** One run took 802 s because `tracemalloc` (memory tracing) slows Python down. Clean runs were 596 s and 666 s.
- **Report noise as a range.** On a laptop you're also using, ±10% is normal, so it's "600–670 s", not one number.
- **Don't claim a failed measurement.** The Windows memory counter returned 0 because of a mistake in my code, so no peak-memory figure is claimed.

---

## Part D: Honest limits (what NOT to claim)

- **The 10M-event test is APT29 replayed 50 times** with shifted days and hosts. It's a scale test, not 10 million unique events.
- **25/30** is with SigmaHQ's rules. ChainHunter's own pack alone gets 16/30, and 6 of those 16 hits are log-clearing alerts on samples where the researchers cleared the logs before recording.
- **The AI analyst** is verified with a fake model in tests. It hasn't been run against a real local model yet, so don't report a grounding score until it has.
- **Throughput:** ~25k events/s on a 4-core laptop means a billion events takes about 11 hours on one machine.
- **Cloud data:** the real cloud dataset is tiny (one Golden SAML recording, 52 events). Cloud coverage is proven to work, not proven broad.
- **Not a Defender/Sentinel replacement:** it's the same concepts (correlation, attack story, coverage), built open and explainable, for learning and portfolio use.

---

## Part E: Mapping to SOC interview questions

| Question you were asked | What ChainHunter gives you to say |
|---|---|
| Brute force vs password spray vs Kerbrute? | Real data in the benchmark: **4768 status 0x6** for many *different* users from one IP = username enumeration (Kerbrute-style, no lockouts, no 4625s). **4771 0x18** = Kerberos pre-auth failure (wrong password). Spray = few passwords across many accounts; brute force = many passwords on one account. ChainHunter counts *distinct* accounts per source for this reason. |
| Which services / which part of Kerberos is involved? | The KDC on the domain controller: the TGT request (AS-REQ) logs 4768/4771, and service tickets (TGS) log 4769. Kerberoasting shows up as an RC4 (0x17) burst of 4769s. |
| How do SIEM connectors work and detect? | Connectors decide field names and formats (B16): the same Entra ID event arrives as `ActivityDisplayName` through Sentinel and `properties.message` through diagnostic export. Detections must target a normalised schema and be tested on *your* connector's data. Blindspot then measures which rules can actually fire. |
| Splunk vs Elastic? How many query languages does Elastic have? | ChainHunter compiles the same rule to **SPL** (Splunk), **KQL** and **EQL** (Elastic). Elastic also has Lucene query syntax, ES\|QL and Elasticsearch SQL. EQL's `sequence … by` expresses multi-stage, joined logic natively, which ChainHunter uses for its sequence rules. |
| "There's a live RDP session you can't find in the logs (logon type 10). How do you think?" | Use Blindspot thinking: first check whether the evidence *can* exist. Is the Security channel collected from that host, with the logon audit policy on? Next, the session may show up elsewhere: TerminalServices LocalSessionManager (21/22/25) and RemoteConnectionManager (1149), a reconnect (logon type 7), Network Level Authentication (the target first logs a network logon, type 3), or a different authentication path. Then check time zones and log retention. |
| How do you reduce alert fatigue without going blind? | Scoped, expiring, audited suppressions. Run an impact check before approving one (RISKY if it hides an incident's first sign). Sequences still see suppressed hits. Rule-health verdicts tell you what to tune vs trust. |

---

## Quick reference

```bash
python -m chainhunter hunt <logs> -r rules -r <sigma>/rules/windows -o out/x        # analyse + report
python -m chainhunter blindspot <logs> -r rules -r <sigma>/rules/windows             # what can fire here
python -m chainhunter bench -r rules -r <sigma>/rules/windows                        # real attack recordings
python -m chainhunter lake <logs> -o lake/x ; python -m chainhunter hunt --lake lake/x -r rules --workers 4
python -m chainhunter suppress impact <logs> -r rules --rule "<title>" --where host=X # before approving
python -m chainhunter rulehealth --lake lake/x -r rules --bench                      # trust / tune / dead
python -m chainhunter watch -r rules [--replay <file> --speed 600]                   # live mode
python -m chainhunter validate ; python -m pytest -q                                 # rules + code tests
```
