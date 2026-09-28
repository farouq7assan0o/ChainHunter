from datetime import datetime, timedelta, timezone
from pathlib import Path

from chainhunter.correlate import correlate
from chainhunter.detect import load_rules, run
from chainhunter.ingest import load, normalize

ROOT = Path(__file__).resolve().parent.parent
RULES = load_rules(ROOT / "rules")
T = datetime(2026, 1, 1, tzinfo=timezone.utc)


def fired(events):
    return {d.rule.id for d in run(RULES, events)}


def e(eid, s=0, **kw):
    return {"EventID": eid, "TimeCreated": T + timedelta(seconds=s), "Computer": "dc01", **kw}


def test_rules_load():
    assert len(RULES) >= 6
    assert all(r.attack_ids for r in RULES)


def test_kerberoast_burst_fires_and_single_does_not():
    burst = [e(4769, i, TicketEncryptionType="0x17", ServiceName=f"svc{i}", IpAddress="10.0.0.5") for i in range(3)]
    assert "ch-0001" in fired(burst)
    assert "ch-0001" not in fired(burst[:1])
    aes = [dict(x, TicketEncryptionType="0x12") for x in burst]
    assert "ch-0001" not in fired(aes)


def test_dcsync_filters_machine_accounts():
    props = "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"
    assert "ch-0004" in fired([e(4662, Properties=props, SubjectUserName="bob")])
    assert "ch-0004" not in fired([e(4662, Properties=props, SubjectUserName="DC01$")])


def test_lsass_comsvcs():
    hit = e(10, TargetImage=r"C:\Windows\System32\lsass.exe", CallTrace="x|C:\Windows\System32\comsvcs.dll+1")
    miss = e(10, TargetImage=r"C:\Windows\System32\lsass.exe", SourceImage=r"C:\Program Files\av.exe", CallTrace="ntdll.dll")
    assert "ch-0002" in fired([hit])
    assert "ch-0002" not in fired([miss])


def test_ecs_normalization():
    ev = normalize({"@timestamp": "2026-09-08T14:00:51.1234567Z", "event": {"code": "4769"},
                    "winlog": {"computer_name": "dc", "event_data": {"TicketEncryptionType": "0x17"}}})
    assert ev["EventID"] == 4769 and ev["TicketEncryptionType"] == "0x17" and ev["Computer"] == "dc"


def test_demo_correlates_into_one_chain():
    demo = ROOT / "samples" / "goad_demo.jsonl"
    if not demo.exists():
        import runpy
        runpy.run_path(str(ROOT / "samples" / "make_demo.py"))
    chains = correlate(run(RULES, load([demo])))
    assert len(chains) == 1
    assert chains[0].severity == "Critical"
    assert {"Credential Access", "Lateral Movement", "Impact"} <= set(chains[0].phases)
