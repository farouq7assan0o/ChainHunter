# 5-minute ChainHunter demo

What to show, in what order, and what to say. Rehearse it out loud. Each step names the **one idea** the interviewer should remember, so you can skip steps if you're short on time.

**Before the call:** open these in browser tabs, and have a terminal in `D:\Security\Tools\ChainHunter`:
- `out\apt29_day1\report.html`
- `out\blindspot\blindspot.html`
- `out\goldensaml\report.html`

Run the replay once beforehand so it starts instantly.

---

### 0:00 – 0:30 · The problem (no screen yet)
> "SOC analysts drown in alerts that are really pieces of one attack. And most teams don't know which of their detections can actually fire on the logs they collect. I built ChainHunter to solve both: it turns raw Windows and cloud logs into correlated attack stories, and it measures real detection coverage. I tested it on public recordings of real attacks."

**Idea to land:** alerts aren't incidents, and coverage is measured, not assumed.

### 0:30 – 1:45 · APT29 (tab: `apt29_day1/report.html`)
> "This is MITRE's APT29 emulation: 196,000 real events from 4 machines. ChainHunter ran 2,400 Sigma rules and produced about 1,900 detections, then grouped them into **one** incident."

- Point at the **swimlane**: "You can watch it spread: SCRANTON, then NASHUA, then the domain controller."
- Scroll to the **process tree**: "It starts at the real payload. This filename has a hidden right-to-left-override character, so `cod.3aka3.scr` displays as a `.doc`. Then cmd, PowerShell, a UAC bypass, and LSASS access."
- **Story:** "The original data stored that character double-encoded, so no rule could see it. I found it in the raw bytes and repaired it at ingest, and then SigmaHQ's own rule fired on the real payload."

**Idea to land:** correlation into one story, plus a bug only real data could reveal.

### 1:45 – 2:45 · Blindspot (tab: `blindspot/blindspot.html`)
> "Coverage dashboards count rule tags, which is what you *think* you detect. Blindspot checks every rule against the logs you actually have."

- Point at the boxes: "90% of the rules can fire here, 171 can't, and it says exactly why."
- Point at the **fix list**: "For example, collecting the Application log would revive 23 rules."
- **Story:** "Blindspot caught a false positive in my own engine. A Sysmon WMI rule had fired, but Blindspot said Sysmon WMI events were never collected. Blindspot was right: a boot event used the same event number. Event IDs are only unique per provider."

**Idea to land:** measured coverage, and two independent analyses cross-checking each other.

### 2:45 – 3:30 · Endpoint + cloud (tab: `goldensaml/report.html`)
> "This is a real Golden SAML attack. The attacker steals the ADFS signing key on-prem, then acts in the cloud as a forged user. The two halves share no account, IP or host, so normal correlation can't link them. ChainHunter links them through the federated domain: one Critical incident across ADFS and Entra ID."
- **Story:** "SigmaHQ's rule for this never fired on real Entra ID data, because Microsoft writes an en-dash where the rule has a hyphen."

**Idea to land:** cross-domain thinking, and normalisation is where detection breaks.

### 3:30 – 4:15 · Live mode (terminal)
```bash
python -m chainhunter watch -r rules --replay samples\goad_demo.jsonl --speed 600 --interval 1
```
> "The same engine, streaming. Watch the incident open at Medium on a logon from a Kali box, then escalate to Critical when the LSASS dump lands."

**Idea to land:** it isn't just a batch report tool.

### 4:15 – 5:00 · Scale and honesty (no screen, or the README table)
> "For scale, logs go into a Parquet lake and rules compile to SQL in DuckDB. I proved the results identical to the in-memory engine, and on a 10-million-event test (APT29 replayed 50 times) it runs in under 7 minutes on my laptop. What it is *not*: a Defender replacement. It's the same concepts, built open and explainable."

**Idea to land:** engineering judgement and honesty about limits.

---

## If you only get 2 minutes
APT29 process tree (the RLO story) → Blindspot (the event-ID collision story) → "tested on 30 real attack recordings, 25 detected."

## Questions to expect after the demo
See `STUDY_GUIDE.md` Part E, and practise these:
1. Why union-find for correlation? What breaks if the window is too big?
2. How do you know Blindspot isn't wrong itself?
3. How would this handle a billion events a day?
4. What's the false-positive rate? (Honest answer: it's measured as volume per million events; true FP rate needs labelled normal-activity data, which public datasets lack.)
5. Why is the AI summary trustworthy? (The verifier checks every sentence against cited evidence. Say the real-model score only once you've measured it.)
6. What would you build next, and why?
