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


def test_logsource_service_restricts_channel(tmp_path):
    # found on real data: an Application-log keyword rule fired on a Sysmon event containing the keyword
    rule = _sigma(tmp_path, """
title: AV keyword
id: svc-test
logsource: {product: windows, service: application}
detection:
  keywords: [mimikatz]
  condition: keywords
tags: [attack.t1003]
""")
    sysmon = e(10, Channel="Microsoft-Windows-Sysmon/Operational", SourceImage=r"C:\x\mimikatz.exe")
    app = e(1116, Channel="Application", Data="HackTool:Win32/Mimikatz detected")
    assert fired([sysmon], [rule]) == set()
    assert fired([app], [rule]) == {"svc-test"}


def test_unmapped_logsource_category_is_skipped(tmp_path):
    # found on real data: a file_change rule with no EventID mapping matched dns.exe *network* events
    (tmp_path / "etw.yml").write_text("title: t\nid: etw\nlogsource: {category: file_access, product: windows}\n"
                                      "detection:\n  s: {Image|endswith: '\\\\dns.exe'}\n  condition: s\n"
                                      "tags: [attack.t1005]\n", encoding="utf-8")
    assert load_rules(tmp_path, quiet=True) == []


def test_sysmon_category_rule_ignores_other_providers_same_eid(tmp_path):
    # found on real APT29 data: Sysmon WMI rule (EID 20) fired on a Kernel-Boot System event 20
    rule = _sigma(tmp_path, """
title: WMI sub
id: wmi-test
logsource: {product: windows, category: wmi_event}
detection:
  selection: {EventID: [19, 20, 21]}
  condition: selection
tags: [attack.t1546.003]
""")
    assert fired([e(20, Channel="System")], [rule]) == set()
    assert fired([e(20, Channel="Microsoft-Windows-Sysmon/Operational")], [rule]) == {"wmi-test"}


def test_blindspot_classifies_rules_against_real_telemetry(tmp_path):
    from chainhunter.blindspot import analyse
    rules = [_sigma(tmp_path, body) for body in ("""
title: needs sysmon 10
id: dead-events
logsource: {product: windows, category: process_access}
detection: {s: {TargetImage|endswith: lsass.exe}, condition: s}
tags: [attack.credential_access, attack.t1003.001]
""",)]
    (tmp_path / "r2.yml").write_text("title: needs cmdline\nid: dead-field\nlogsource: {product: windows, category: process_creation}\n"
                                     "detection: {s: {CommandLine|contains: whoami}, condition: s}\n"
                                     "tags: [attack.discovery, attack.t1033]\n", encoding="utf-8")
    (tmp_path / "r3.yml").write_text("title: logon\nid: live\nlogsource: {product: windows, service: security}\n"
                                     "detection: {s: {EventID: 4624, LogonType: 3}, condition: s}\n"
                                     "tags: [attack.lateral_movement, attack.t1021]\n", encoding="utf-8")
    rules = load_rules(tmp_path, quiet=True)
    # 4688 WITHOUT CommandLine (the classic missing GPO), 4624 present, no Sysmon at all
    events = [e(4688, i, Channel="Security", NewProcessName=r"C:\x.exe", Computer=f"h{i % 3}") for i in range(30)]
    events += [e(4624, i, Channel="Security", LogonType="3", Computer=f"h{i % 3}") for i in range(30)]
    res = analyse(rules, sorted(events, key=lambda x: x["TimeCreated"]))
    status = {v.rule.id: v.status for v in res.viability}
    assert status == {"dead-events": "DEAD_EVENTS", "dead-field": "DEAD_FIELDS", "live": "LIVE"}
    actions = [r.action for r in res.recs]
    assert any("Include command line" in a for a in actions)
    assert any("Sysmon 10" in a for a in actions)
    live, unverified, blind = res.techniques
    assert live == {"T1021"} and blind == {"T1003.001", "T1033"} and not unverified


def test_blindspot_rare_event_on_collected_channel_is_unverified_not_dead(tmp_path):
    # 1102 only appears when someone clears the log: absence on a collected Security channel isn't a blind spot
    from chainhunter.blindspot import analyse
    (tmp_path / "r.yml").write_text("title: log cleared\nid: clr\nlogsource: {product: windows, service: security}\n"
                                    "detection: {s: {EventID: 1102}, condition: s}\ntags: [attack.defense_evasion, attack.t1070.001]\n",
                                    encoding="utf-8")
    (tmp_path / "p.yml").write_text("title: prov\nid: prov\nlogsource: {product: windows, service: system}\n"
                                    "detection: {s: {EventID: 7045, Provider_Name: Service Control Manager}, condition: s}\n"
                                    "tags: [attack.persistence, attack.t1543.003]\n", encoding="utf-8")
    events = [e(4624, i, Channel="Security") for i in range(5)]
    events += [normalize({"EventID": 7045, "TimeCreated": "2026-01-01T00:00:09Z", "Channel": "System",
                          "Provider": "Service Control Manager", "ServiceName": "x"})]
    res = analyse(load_rules(tmp_path, quiet=True), events)
    assert {v.rule.id: v.status for v in res.viability} == {"clr": "UNOBSERVED", "prov": "LIVE"}
    assert any("Verify Security 1102" in r.action for r in res.verify) and not res.recs
    # and the Provider_Name alias lets the SigmaHQ-style rule actually fire
    assert fired(events, load_rules(tmp_path, quiet=True)) == {"prov"}


def test_blindspot_health_flags_host_missing_a_source():
    from chainhunter.blindspot import analyse
    events = [e(4624, i, Channel="Security", Computer=h) for i in range(40) for h in ("a", "b", "c")]
    events += [e(1, i, Channel="Microsoft-Windows-Sysmon/Operational", Computer=h) for i in range(40) for h in ("a", "b")]
    res = analyse([], sorted(events, key=lambda x: x["TimeCreated"]))
    assert [(i.kind, i.host) for i in res.issues] == [("MISSING_SOURCE", "C")]


def test_bad_input_fails_loudly_instead_of_empty_report(tmp_path):
    # real user report: a placeholder path produced a Blindspot page saying 2,385 rules were dead
    from chainhunter.ingest import NoEventsError
    for bad in (tmp_path / "path" / "to" / "logs", tmp_path):  # missing path, folder with no log files
        with pytest.raises(NoEventsError):
            load([bad])


def test_lake_detections_identical_to_in_memory(tmp_path):
    """The DuckDB lake is a pure speed-up: SQL pre-filters, Python re-checks, results must not change."""
    pytest.importorskip("duckdb")
    from chainhunter.lake import Lake, build_lake, compile_where, run_lake
    demo = ROOT / "samples" / "goad_demo.jsonl"
    if not demo.exists():
        import runpy
        runpy.run_path(str(ROOT / "samples" / "make_demo.py"))
    # case-variant field names (real APT29 has IpAddress and Ipaddress) must survive the lake too
    extra = tmp_path / "variants.jsonl"
    extra.write_text('{"EventID": 4624, "TimeCreated": "2026-09-08T13:40:00Z", "Computer": "x", "LogonType": "3", '
                     '"AuthenticationPackageName": "NTLM", "WorkstationName": "KALI", "TargetUserName": "arya", '
                     '"Ipaddress": "192.168.101.51"}\n', encoding="utf-8")
    events = load([demo, extra])
    build_lake([demo, extra], tmp_path / "lake", chunk=300)  # several chunks
    key = lambda d: (d.rule.id, d.time.isoformat(), d.host, d.actor, len(d.events))
    mem = sorted(map(key, run(RULES, events)))
    lake, stats = run_lake(RULES, Lake(tmp_path / "lake"))
    assert sorted(map(key, lake)) == mem and mem
    # absent columns are NULL-safe, including under NOT (engine: missing field never matches)
    assert compile_where(REGISTRY["ch-0004"], {"Properties"}).count("FALSE") >= 1
    # multi-process fan-out: files split across workers, hits merged before thresholds -> same detections
    from chainhunter.lake import run_lake_parallel
    par, _ = run_lake_parallel(RULES, tmp_path / "lake", workers=2)
    assert sorted(map(key, par)) == mem


def test_linear_correlation_matches_all_pairs_reference():
    import random
    from chainhunter.correlate import _keys
    from chainhunter.detect import Detection
    rule = RULES[0]
    rng = random.Random(7)
    for trial in range(40):
        dets = []
        for _ in range(rng.randint(5, 60)):
            start = T + timedelta(minutes=rng.randint(0, 2000))
            evs = [{"TimeCreated": start}, {"TimeCreated": start + timedelta(minutes=rng.choice([0, 5, 400]))}]
            dets.append(Detection(rule, evs, actor=rng.choice(["a", "b", "c", "", "d"]),
                                  host=rng.choice(["h1", "h2", "h3", "h4"]), source=rng.choice(["", "s1", "s2"])))
        dets.sort(key=lambda d: d.time)
        window = timedelta(minutes=rng.choice([30, 120, 360]))
        # reference: the original all-pairs implementation
        parent = list(range(len(dets)))
        def find(i):
            while parent[i] != i:
                i = parent[i]
            return i
        ks = [_keys(d) for d in dets]
        for i in range(len(dets)):
            for j in range(i + 1, len(dets)):
                if dets[j].time - dets[i].end > window:
                    break
                if ks[i] & ks[j]:
                    parent[find(i)] = find(j)
        ref = sorted(sorted(id(dets[i]) for i in range(len(dets)) if find(i) == r) for r in {find(i) for i in range(len(dets))})
        got = sorted(sorted(id(d) for d in c.detections) for c in correlate(dets, window))
        assert got == ref, f"trial {trial}"


@pytest.fixture(scope="module")
def demo_chain(demo):
    _, sigs, seqs, anoms = demo
    return correlate(sigs + seqs + anoms)[0]


def test_ai_verifier_flags_invented_facts(demo_chain):
    """The grounding verifier, not the model, decides what counts as supported."""
    from chainhunter.ai import evidence_pack, score, verify
    pack = evidence_pack(demo_chain)
    roast = next(e.id for e in pack if "Kerberoast" in e.alert)
    raw = {"executive_summary": [
               {"text": "rickon.stark requested RC4 service tickets (T1558.003).", "evidence": [roast]},      # grounded
               {"text": "The attacker then pivoted to host WEB-07.", "evidence": [roast]},                  # invented host
               {"text": "Credentials were dumped via T1003.001.", "evidence": [roast]},                     # wrong citation
               {"text": "Traffic came from 10.9.9.9.", "evidence": [roast]},                                # invented IP
               {"text": "Something happened.", "evidence": []},                                            # no citation
               {"text": "It spread widely.", "evidence": ["E999"]}],                                        # fake ID
           "attack_narrative": [], "containment": [], "gaps": ""}
    v = verify(raw, demo_chain, pack)["executive_summary"]
    assert [c.grounded for c in v] == [True, False, False, False, False, False]
    assert "WEB-07" in v[1].problems[0] and "T1003.001" in v[2].problems[0] and "10.9.9.9" in v[3].problems[0]
    assert score({"s": v}) == (1, 6)


def test_ai_pipeline_with_fake_backend(demo_chain, monkeypatch):
    from chainhunter import ai
    class Fake:
        def complete(self, system, user, schema):
            assert "E1 |" in user and "evidence" in system.lower()
            return {"executive_summary": [{"text": "Kerberoasting was detected.", "evidence": ["E1"]}],
                    "attack_narrative": [], "containment": [], "gaps": "Initial access not observed."}
    monkeypatch.setattr(ai, "backend", lambda spec: Fake())
    out = ai.analyse([demo_chain], "fake")
    assert not out[0].error and ai.score(out[0].verified)[1] == 1
    assert "grounding" in ai.markdown(out) and "grounding" in ai.html_section(out[0])


def test_suppression_guardrails_and_chain_protection(tmp_path, demo):
    from chainhunter import suppress
    events, sigs, _, _ = demo
    f = tmp_path / "s.yml"
    f.write_text("""suppressions:
- {id: s-001, rule: "NTLM Network Logon from Unmanaged Workstation Name", where: {actor: "jon.snow"}, reason: "test", expires: 2099-01-01}
- {id: s-002, rule: "*", reason: "too broad"}
- {id: s-003, rule: "ch-0004", reason: "dcsync is critical", expires: 2099-01-01}
- {id: s-004, rule: "ch-0005", reason: "old", expires: 2000-01-01}
""", encoding="utf-8")
    sups = suppress.load(f)
    kept, hidden = suppress.apply(sigs, sups)
    by = {s.id: s for s in sups}
    assert [d.actor for d in hidden] == ["jon.snow"] and by["s-001"].hits == 1      # scoped: only jon.snow's logon
    assert not by["s-002"].active                                                   # '*' refused without allow_broad
    assert by["s-003"].hits == 0 and any(d.rule.id == "ch-0004" for d in kept)      # critical needs allow_critical
    assert by["s-004"].expired and any(d.rule.id == "ch-0005" for d in kept)        # expired no longer applies
    # sequences run on the unsuppressed hits, so the chain that used the muted logon still fires
    seqs = run_sequences(RULES, sigs, events)
    assert {"ch-s001", "ch-s003"} <= {d.rule.id for d in seqs}


def test_suppression_impact_flags_risky_vs_safe(demo):
    from chainhunter import suppress
    from chainhunter.impact import simulate
    events, sigs, _, _ = demo
    cand = lambda where: [suppress.Suppression("c", "ch-0003", where, "t", "", "", None)]
    broad = simulate(RULES, events, cand({}), signatures=list(sigs))
    assert broad.verdict == "RISKY"
    losses = " ".join(l for i in broad.incidents for l in i.losses)
    assert "earliest alert" in losses and "first sign of compromise" in losses and "Lateral Movement" in losses
    narrow = simulate(RULES, events, cand({"actor": "jon.snow"}), signatures=list(sigs))
    assert narrow.verdict == "SAFE" and narrow.hidden_total == 1
    assert simulate(RULES, events, cand({"actor": "nobody"}), signatures=list(sigs)).verdict == "NO EFFECT"


def test_rule_health_verdicts(demo):
    from chainhunter.impact import rule_health
    events, sigs, _, _ = demo
    rows = {h.rule.id: h for h in rule_health(RULES, events, loud_per_million=1000, signatures=list(sigs))}
    assert rows["ch-0003"].alerts == 3 and rows["ch-0003"].verdict == "TUNE"       # 3 / 836 events ≈ 3,600 per 1M
    assert rows["ch-0006"].verdict == "UNPROVEN" and rows["ch-0006"].tested          # quiet, tested, no attack evidence given


def test_cloud_sentinel_records_normalise_for_sigma(tmp_path):
    rule = _sigma(tmp_path, """
title: app cred
id: cloud-test
logsource: {product: azure, service: auditlogs}
detection:
  selection: {properties.message: 'Update application - Certificates and secrets management'}
  condition: selection
tags: [attack.persistence, attack.t1098.001]
""")
    # real Entra ID export: en dash + trailing space, JSON-in-a-string InitiatedBy (Sentinel AuditLogs shape)
    raw = {"Type": "AuditLogs", "TimeGenerated": "2021-08-02T13:29:25.983Z",
           "ActivityDisplayName": "Update application – Certificates and secrets management ",
           "InitiatedBy": '{"user":{"userPrincipalName":"pgustavo@simulandlabs.com","ipAddress":"1.2.3.4"}}',
           "TargetResources": '[{"type":"Application","displayName":"SimuLandApp"}]', "UserAgent": "PowerShell"}
    ev = normalize(raw)
    assert ev["_platform"] == "azure" and ev["Computer"] == "Entra ID" and ev["User"] == "pgustavo@simulandlabs.com"
    assert ev["IpAddress"] == "1.2.3.4" and ev["targetResources.type"] == "Application" and ev["userAgent"] == "PowerShell"
    assert fired([ev], [rule]) == {"cloud-test"}                       # fires only thanks to dash/space normalisation
    # platform isolation: a Windows keyword rule never fires on the cloud record, the cloud rule never on Windows
    win = _sigma(tmp_path, "title: kw\nid: win-kw\nlogsource: {product: windows}\ndetection:\n  k: [secrets]\n  condition: k\ntags: [attack.t1005]\n")
    assert fired([ev], [win]) == set()
    assert fired([e(4624, Channel="Security", **{"properties.message": raw["ActivityDisplayName"]})], [rule]) == set()


def test_domain_join_links_federation_server_to_cloud_identity():
    from chainhunter.detect import Detection
    d1 = Detection(RULES[0], [{"TimeCreated": T}], host="ADFS01.corp.example")
    d2 = Detection(RULES[0], [{"TimeCreated": T, "User": "alice@corp.example"}], actor="alice@corp.example", host="Entra ID")
    assert d1.values("domain") == {"corp.example"} == d2.values("domain")


def test_watch_replay_streams_incident_incrementally():
    from chainhunter.watch import Engine, ReplaySource, watch
    demo = ROOT / "samples" / "goad_demo.jsonl"
    src = ReplaySource([demo], interval=1, speed=600)
    lines: list[str] = []
    counters = watch(src, Engine(RULES), 0, echo=lines.append, sleep=lambda s: None)
    alerts = [l for l in lines if l.startswith("ALERT")]
    assert counters["incidents"] == 1 and any("escalated from Medium" in l for l in lines)   # opens small, escalates
    assert sum("(DCSync)" in l for l in alerts) == 1                                          # burst split across polls = one alert
    assert any("[SEQUENCE]" in l for l in alerts) and counters["events"] == 836


def test_watch_parses_live_wevtutil_xml():
    from chainhunter.watch import WindowsSource
    xml = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/>"
           "<EventID>4624</EventID><TimeCreated SystemTime='2026-09-30T10:00:00.000Z'/><EventRecordID>42</EventRecordID>"
           "<Channel>Security</Channel><Computer>WS01</Computer></System><EventData><Data Name='LogonType'>3</Data>"
           "<Data Name='IpAddress'>::ffff:10.0.0.5</Data></EventData></Event>")
    evs = WindowsSource._parse(xml + xml.replace("<EventRecordID>42", "<EventRecordID>43"))
    assert [e["EventRecordID"] for e in evs] == [42, 43] and evs[0]["IpAddress"] == "10.0.0.5" and evs[0]["EventID"] == 4624


def test_mojibake_repair_restores_rlo():
    # real OTRF APT29 data: U+202E stored double-encoded, hiding the RLO masquerade
    ev = normalize({"EventID": 1, "TimeCreated": "2020-05-02T02:55:56Z",
                    "Image": "C:\\ProgramData\\victim\\\u00e2\u20ac\u00aecod.3aka3.scr"})
    assert ev["Image"].endswith("\u202ecod.3aka3.scr")
    assert normalize({"EventID": 1, "TimeCreated": "2020-05-02T02:55:56Z", "User": "Ãlvaro"})["User"] == "Ãlvaro"


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
    assert norm_entity(r"NORTH\jon.snow", "actor") == "jon.snow" != norm_entity("jon.arryn", "actor")
    assert norm_entity("jon.snow@north.local", "actor") == "jon.snow"
    assert norm_entity("CASTELBLACK.north.sevenkingdoms.local", "host") == "castelblack"
    assert norm_entity("192.168.1.5", "host") == "192.168.1.5"
