# Talk submission (BSides / community conference CFP)

**Title:** Silent Failures: What Real Attack Logs Taught Me About Detection Rules

**Format:** 25–30 minute talk (a 15-minute version works too)

**Level:** Beginner–intermediate (SOC analysts, detection engineers)

## Abstract (≈150 words)
Detection rules usually fail silently: no error, no alert, just a quiet network that isn't really quiet. I replayed 2,400 SigmaHQ rules against public recordings of real attacks, including MITRE's APT29 emulation and a Golden SAML intrusion spanning on-prem ADFS and Entra ID, and catalogued what broke. Zero-padded hex values, IPv4-mapped IPv6, a double-encoded right-to-left-override character that hid APT29's disguised payload, one field-name mismatch that disabled 86 rules, an en-dash that defeated an exact match, and event IDs shared between providers that produced false positives. This talk walks through each failure, how it was found, and how to catch it in your own environment. It shows how to measure which of your rules can actually fire on the telemetry you collect, and how to track rule regressions against real attack data every week, using open-source tooling and public datasets anyone can reproduce.

## Takeaways
1. A checklist of normalisation failures to test for in any SIEM pipeline.
2. How to measure *real* detection coverage against your telemetry, not rule tags.
3. A free, reproducible way to benchmark rules against real attack recordings.

## Outline
1. **Why silent failures matter** (3 min): a broken rule looks like a quiet network.
2. **The setup** (3 min): public attack recordings, 2,400 Sigma rules, an open-source engine.
3. **Ten failures** (14 min): hex padding, IPv6, mojibake hiding RLO, `Provider_Name`, the en-dash, event-ID collisions, connector field names, "absent ≠ blind", streaming thresholds, "loud ≠ false positive".
4. **Measuring real coverage** (4 min): which rules can fire, and the fix that revives each dead one.
5. **Tracking regressions weekly** (3 min): the public benchmark.
6. **Takeaways and Q&A** (3 min).

## Speaker bio (edit to taste)
Farouq Hassan is a SOC analyst holding the HTB CDSA certification. He builds open-source detection tooling and focuses on threat hunting, detection engineering and Active Directory attack detection.
