# Real attack logs broke my detections in ways synthetic data never did

*How replaying 2,400 Sigma rules against public recordings of real attacks exposed silent failures that every unit test had missed.*

---

I built a detection engine, ChainHunter, and tested it the way most of us do: synthetic events, unit tests, everything green. Then I pointed it at **public recordings of real attacks** (EVTX-ATTACK-SAMPLES, OTRF Security-Datasets, MITRE's APT29 emulation) and loaded **2,400 SigmaHQ rules**.

Nothing crashed. Nothing errored. Things just didn't fire, or fired for the wrong reason. Every one of these failures was **silent**, which is the worst kind in detection engineering: a broken rule looks exactly like a quiet network.

Here are the ones worth knowing.

## 1. Zero-padded hex: the rule was right, the comparison wasn't
An LSASS-access rule matched `GrantedAccess: 0x1010`. Real Mimikatz data logs `0x00001010`. A string comparison says those are different, so the rule never fires. The same happens with `Status: 0x00000006` vs `0x6`.

**Fix:** canonicalise hex fields at ingest. **Lesson:** when a correct-looking rule never fires, look at the raw field values first.

## 2. One attacker, two IP addresses
The same host appeared as `172.16.66.1` and `::ffff:172.16.66.1` (IPv4-mapped IPv6). Correlation saw two attackers. One normalisation line turned them back into one.

## 3. The attacker's disguise was hidden by an encoding bug
APT29's initial payload is named with a right-to-left-override character (U+202E), so `cod.3aka3.scr` displays as `rcs.3aka3.doc`. SigmaHQ has a rule for exactly that trick, and it didn't fire. In the published dataset, the character's UTF-8 bytes had been read as Windows-1252 and saved again (`E2 80 AE` became `C3 A2 E2 82 AC C2 AE`): **280 times, with zero correct copies**.

After repairing the encoding at ingest, the rule fired on the real payload. A data-pipeline bug had switched off a detection for the single most important event in the dataset.

## 4. 86 rules dead because of one field name
SigmaHQ calls the event provider `Provider_Name`; my engine stored it as `Provider`. **86 rules could never match**, with no error. Populating both names revived 44 of them and caught one more real attack (ntdsutil copying the domain's password database).

## 5. An en-dash defeated an exact match
Entra ID logs `Update application – Certificates and secrets management ` with an **en-dash and a trailing space**. A SigmaHQ rule uses a hyphen. The rule has been flipped between the two characters twice upstream, because each contributor was right about the export pipeline they looked at. A public 2021 dataset confirms the en-dash form. Matching on *fragments* rather than exact strings ends the argument.

## 6. Event IDs are not unique
A Sysmon WMI-persistence rule (events 19/20/21) fired on APT29. But a separate analysis said Sysmon WMI events were never collected. The second analysis was right: **Kernel-Boot also writes event 20, and TerminalServices writes event 21**. An event ID is only meaningful together with its provider.

What made this findable was having **two independent analyses disagree**. That's worth building in on purpose.

## 7. Same event, two pipelines, two field names
SigmaHQ's Azure rules use the diagnostic-export shape (`properties.message`, `userAgent`). Microsoft Sentinel exports the same events as `ActivityDisplayName` and `UserAgent`. Your connector decides which one you get, so rules must target a normalised schema and be tested on *your* connector's data.

## 8. "Absent" is not "blind"
My coverage tool first told me to "collect Security event 1102". But 1102 only exists when someone clears a log. Its absence from a 33-minute recording proves nothing. The fix was a separate verdict: **channel collected, event never seen → verify the audit policy**, not "you're blind".

## 9. A burst split across two polls became two alerts
In streaming mode, a DCSync burst rule alerted twice, because each poll evaluated thresholds on its own batch. Burst rules need state across the window: the same lesson as merging results from parallel workers *before* applying thresholds.

## 10. Loud is not the same as false positive
On APT29, two rules were by far the loudest. They were loud because **APT29's own Python implant was triggering them**. "This rule is noisy, delete it" would have deleted the detection that was working. Tune the scope, and check what a suppression would hide before you approve it.

---

## What I'd tell another detection engineer
1. **Test on real recordings, not just synthetic events.** Public datasets exist: EVTX-ATTACK-SAMPLES, OTRF Security-Datasets, MITRE's APT29 evaluation data.
2. **Measure which rules *can* fire on your telemetry** before trusting a coverage dashboard. I found about 10% of 2,400 rules dead on a rich dataset, each for a nameable reason.
3. **Normalisation is where detection breaks.** Hex, IPv6, encodings, field names, dashes, whitespace, event-ID collisions: none of these show up in rule unit tests.
4. **Build two independent views and look for disagreements.** That's how the event-ID collision surfaced.
5. **Watch for silent regressions.** I now replay the latest SigmaHQ release against real attack data every week and publish which rules stopped firing.

*ChainHunter is open source (MIT): github.com/farouq7assan0o/ChainHunter. Every lesson above is written up in detail in `docs/STUDY_GUIDE.md`.*
