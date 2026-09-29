from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from chainhunter.anomaly import detect_anomalies
from chainhunter.convert import compile_rule
from chainhunter.correlate import correlate
from chainhunter.detect import load_rule_file, load_rules, run
from chainhunter.ingest import load, normalize
from chainhunter.sequence import run_sequences
from chainhunter.validate import validate

ROOT = Path(__file__).resolve().parent.parent
RULES = load_rules(ROOT / "rules")
REGISTRY = {r.id: r for r in RULES}
T = datetime(2026, 1, 1, tzinfo=timezone.utc)


def e(eid, s=0, **kw):
    return {"EventID": eid, "TimeCreated": T + timedelta(seconds=s), "Computer": "dc01", **kw}


def fired(events, rules=RULES):
    return {d.rule.id for d in run(rules, events)}


# ---------- detection-as-code: every rule's embedded tests ----------

@pytest.mark.parametrize("result", validate(RULES), ids=lambda r: r.rule.id)
def test_embedded_rule_tests(result):
    assert not result.errors, result.errors
    assert result.passed >= 2, "each rule needs positive and negative cases"


# ---------- Sigma engine compatibility ----------

def _sigma(tmp_path, body: str):
    f = tmp_path / "r.yml"
    f.write_text(body, encoding="utf-8")
    return load_rule_file(f)


def test_sigmahq_style_logsource_category_and_4688_alias(tmp_path):
    rule = _sigma(tmp_path, r"""
title: Suspicious Encoded PowerShell
id: sigma-test
logsource: {category: process_creation, product: windows}
detection:
  selection_img:
    - Image|endswith: '\powershell.exe'
    - OriginalFileName: PowerShell.EXE
  selection_cli:
    CommandLine|contains|windash: ' -enc '
  condition: all of selection_*
tags: [attack.execution, attack.t1059.001]
level: high
""")
    sysmon = e(1, Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", CommandLine="powershell /enc AAA")
    native = normalize({"EventID": 4688, "TimeCreated": "2026-01-01T00:00:00Z",
                        "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                        "CommandLine": "powershell -enc AAA"})
    wrong_eid = e(4104, Image=r"C:\x\powershell.exe", CommandLine="powershell -enc AAA")
    assert fired([sysmon], [rule]) == {"sigma-test"}
    assert fired([native], [rule]) == {"sigma-test"}
    assert fired([wrong_eid], [rule]) == set()


def test_modifiers_cidr_null_and_them(tmp_path):
    rule = _sigma(tmp_path, """
title: t
id: mod-test
detection:
  sel_net: {IpAddress|cidr: 10.0.0.0/8}
  sel_null: {LogonProcessName: null}
  condition: 1 of them and not sel_null
tags: [attack.t1078]
""")
    assert fired([e(4624, IpAddress="10.2.3.4", LogonProcessName="NtLmSsp")], [rule]) == {"mod-test"}
    assert fired([e(4624, IpAddress="10.2.3.4")], [rule]) == set()
    assert fired([e(4624, IpAddress="192.168.1.1", LogonProcessName="x")], [rule]) == set()


def test_unsupported_modifier_is_skipped_not_fatal(tmp_path):
    (tmp_path / "bad.yml").write_text("title: b\nid: b\ndetection:\n  s: {CommandLine|base64offset|contains: x}\n"
                                      "  condition: s\ntags: [attack.t1027]\n", encoding="utf-8")
    assert load_rules(tmp_path, quiet=True) == []


def test_ecs_normalization():
    ev = normalize({"@timestamp": "2026-09-08T14:00:51.1234567Z", "event": {"code": "4769"},
                    "winlog": {"computer_name": "dc", "event_data": {"TicketEncryptionType": "0x17"}}})
    assert ev["EventID"] == 4769 and ev["TicketEncryptionType"] == "0x17" and ev["Computer"] == "dc"


# ---------- compiler ----------

def test_compiler_outputs():
    lsass = REGISTRY["ch-0002"]
    assert r"winlog.event_data.TargetImage:*\\lsass.exe" in compile_rule(lsass, "kql")
    assert compile_rule(lsass, "eql").startswith("any where")
    assert "| where count>=3" in compile_rule(REGISTRY["ch-0001"], "spl")
    seq = compile_rule(REGISTRY["ch-s001"], "eql", REGISTRY)
    assert seq.startswith("sequence with maxspan=14400s")
    assert "by winlog.event_data.ServiceName" in seq and "by winlog.event_data.TargetUserName" in seq


# ---------- end-to-end on the demo dataset ----------

@pytest.fixture(scope="module")
def demo():
    path = ROOT / "samples" / "goad_demo.jsonl"
    if not path.exists():
        import runpy
        runpy.run_path(str(ROOT / "samples" / "make_demo.py"))
    events = load([path])
    sigs = run(RULES, events)
    seqs = run_sequences(RULES, sigs, events)
    anoms = detect_anomalies(events)
    return events, sigs, seqs, anoms


def test_demo_sequences(demo):
    _, _, seqs, _ = demo
    assert {d.rule.id for d in seqs} == {"ch-s001", "ch-s002", "ch-s003"}
    reuse = next(d for d in seqs if d.rule.id == "ch-s001")
    assert reuse.extra["steps"][1][1].actor == "jon.snow"


def test_demo_anomaly_finds_attacker_ip_without_signatures(demo):
    _, _, _, anoms = demo
    assert [d.source for d in anoms if d.rule.id == "ch-a001"] == ["192.168.101.51"]


def test_demo_correlates_into_one_ordered_chain(demo):
    _, sigs, seqs, anoms = demo
    chains = correlate(sigs + seqs + anoms)
    assert len(chains) == 1
    c = chains[0]
    assert c.severity == "Critical" and c.confidence.startswith("High")
    assert c.phases[0] == "Initial Access" and c.phases[-1] == "Impact"
    flagged = {r.value for r in c.risk if r.flagged}
    assert "192.168.101.51" in flagged and "rickon.stark" in flagged


def test_entity_normalisation_keeps_account_dots():
    from chainhunter.sequence import norm_entity
    assert norm_entity("NORTH\jon.snow", "actor") == "jon.snow" != norm_entity("jon.arryn", "actor")
    assert norm_entity("jon.snow@north.local", "actor") == "jon.snow"
    assert norm_entity("CASTELBLACK.north.sevenkingdoms.local", "host") == "castelblack"
    assert norm_entity("192.168.1.5", "host") == "192.168.1.5"
