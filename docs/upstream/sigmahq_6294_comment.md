# Comment for SigmaHQ/sigma PR #6294

**Where:** https://github.com/SigmaHQ/sigma/pull/6294 (open). Post as a comment, not a new issue. #5530 and #6247 already cover the history, and #6294 is the fix in progress.

**Why it helps:** it's an independent confirmation from a public, reproducible dataset, from a different tenant, five years earlier, through the same `Microsoft.aadiam` pipeline. That supports the fragment approach over another dash flip.

---

Independent confirmation from a public dataset, in case it helps settle this one.

OTRF Security-Datasets has a 2021 Golden SAML recording with a Sentinel `AuditLogs` export of exactly this action:
https://github.com/OTRF/Security-Datasets/tree/master/datasets/compound/GoldenSAMLADFSMailAccess (`AADAuditEvents.Zip`)

Both `OperationName` and `ActivityDisplayName` for the credential change are:

```
'Update application – Certificates and secrets management '
 len 57, U+2013 EN DASH at position 19, trailing U+0020 at position 56
 Resource = Microsoft.aadiam, SourceSystem = Azure AD, TimeGenerated 2021-08-02
```

That's byte-for-byte what you measured on the live tenant in this PR, from a different tenant and five years earlier. So the en dash plus trailing space looks stable for this pipeline, not a recent change.

Repro:

```python
import json, unicodedata
for line in open("AADAuditEvents.json", encoding="utf-8-sig"):
    v = json.loads(line).get("ActivityDisplayName", "")
    if "Certificates" in v:
        print(repr(v), len(v), [(i, f"U+{ord(c):04X}") for i, c in enumerate(v) if ord(c) > 127])
```

Against that event, the current hyphen value doesn't match and the fragments in this PR do. I'd support merging the fragment form: it's robust to the dash variant, the trailing space, and whichever export path is in use.
