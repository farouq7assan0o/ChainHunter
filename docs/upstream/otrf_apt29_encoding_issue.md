# Issue for OTRF/Security-Datasets

**Where:** https://github.com/OTRF/Security-Datasets/issues/new. Checked first: no existing issue for "apt29 encoding", "unicode", "mojibake" or "cod.3aka3".

**Why it matters:** the APT29 day-1 initial-access payload uses a right-to-left-override (RLO) filename. In the published JSON that character is double-encoded, so detections built for it (e.g. SigmaHQ `ad691d92-15f2-4181-9aa4-723c74f9ddc3`) can't fire on the dataset.

---

**Title:** APT29 day-1 export: U+202E (RLO) is double-encoded, hides the masqueraded payload name

**Body:**

In `datasets/compound/apt29/day1/apt29_evals_day1_manual.zip` (`apt29_evals_day1_manual_2020-05-01225525.json`), the right-to-left override in the initial-access payload name is stored double-encoded (UTF-8 bytes read as Windows-1252, then re-encoded as UTF-8):

```
expected (U+202E in UTF-8):  E2 80 AE
in the file:                 C3 A2 E2 82 AC C2 AE   ->  renders as "â€®cod.3aka3.scr"
```

Counts across the file: **280** double-encoded occurrences, **0** correctly encoded ones.

Impact: the masquerade (`cod.3aka3.scr` displaying as `rcs.3aka3.doc`) is the key initial-access detail of this emulation step, but detections looking for U+202E can't match it. For example, SigmaHQ "Potential Defense Evasion Via Right-to-Left Override" (`ad691d92-15f2-4181-9aa4-723c74f9ddc3`) doesn't fire on the raw data. It does fire once the text is repaired.

Repro:

```python
raw = open("apt29_evals_day1_manual_2020-05-01225525.json", "rb").read()
print(raw.count(b"\xc3\xa2\xe2\x82\xac\xc2\xae"), raw.count(b"\xe2\x80\xae"))   # 280 0
i = raw.find(b"cod.3aka3.scr"); print(raw[i-9:i])
```

Repair (lossless for this pattern): `s.encode("cp1252").decode("utf-8")` on affected strings restores U+202E.

Possible fixes: re-export the JSON with UTF-8 end-to-end, or add a note to the dataset's metadata so users know to repair it. Happy to help test a re-export. Day 2 and other datasets exported through the same pipeline may be worth checking for the same pattern.
