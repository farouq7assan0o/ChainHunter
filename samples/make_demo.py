"""Generate a synthetic, fictional GOAD-style dataset (benign baseline + one multi-stage intrusion).

Run: python samples/make_demo.py  -> samples/goad_demo.jsonl
"""
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(7)
T0 = datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc)
DC_N, DC_ROOT, SRV = "winterfell.north.sevenkingdoms.local", "kingslanding.sevenkingdoms.local", "castelblack.north.sevenkingdoms.local"
ATK_IP = "192.168.101.51"
events = []


def ev(t, eid, computer, channel="Security", **data):
    events.append({"TimeCreated": t.isoformat(), "EventID": eid, "Computer": computer, "Channel": channel, **data})


# ---- benign baseline noise ----
users = ["arya.stark", "samwell.tarly", "hodor", "jeor.mormont", "robb.stark"]
for i in range(400):
    t = T0 + timedelta(seconds=random.randint(0, 4 * 3600))
    u = random.choice(users)
    ev(t, 4769, DC_N, TargetUserName=u, ServiceName=random.choice(["CASTELBLACK$", "WINTERFELL$", "http_svc"]),
       TicketEncryptionType="0x12", IpAddress=f"192.168.101.{random.randint(60, 90)}")
    ev(t, 4624, SRV, TargetUserName=u, LogonType=3, AuthenticationPackageName="Kerberos",
       WorkstationName=f"WS-{random.randint(1, 20):02}", IpAddress=f"192.168.101.{random.randint(60, 90)}")
for i in range(20):
    ev(T0 + timedelta(minutes=i * 12), 4662, DC_N, SubjectUserName="WINTERFELL$",
       Properties="%%7688 {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}")

# ---- intrusion (fictional) ----
at = lambda h, m, s=0, ms=0: T0.replace(hour=h, minute=m, second=s, microsecond=ms * 1000)
ev(at(13, 13, 9), 4624, DC_ROOT, TargetUserName="cersei.lannister", LogonType=3,
   AuthenticationPackageName="NTLM", WorkstationName="KALI", IpAddress=ATK_IP)
ev(at(13, 33, 2), 4624, SRV, TargetUserName="rickon.stark", LogonType=3,
   AuthenticationPackageName="NTLM", WorkstationName="KALI", IpAddress=ATK_IP)
for i, spn in enumerate(["sansa.stark", "jon.snow", "sql_svc"]):
    ev(at(14, 0, 51, i * 4), 4769, DC_N, TargetUserName="rickon.stark", ServiceName=spn,
       TicketEncryptionType="0x17", IpAddress=ATK_IP)
ev(at(14, 5, 42), 10, SRV, "Microsoft-Windows-Sysmon/Operational",
   SourceImage=r"C:\Windows\System32\rundll32.exe", TargetImage=r"C:\Windows\system32\lsass.exe",
   GrantedAccess="0x1fffff", SourceUser=r"CASTELBLACK\Administrator",
   CallTrace=r"C:\Windows\SYSTEM32\ntdll.dll+9d4c4|C:\Windows\System32\comsvcs.dll+2b9e")
ev(at(14, 16, 10), 4624, SRV, TargetUserName="jon.snow", LogonType=3,
   AuthenticationPackageName="NTLM", WorkstationName="KALI", IpAddress=ATK_IP)
ev(at(15, 14, 30), 4728, DC_N, SubjectUserName="jon.snow", TargetUserName="Domain Admins",
   MemberName="CN=rickon.stark,CN=Users,DC=north,DC=sevenkingdoms,DC=local")
for i in range(8):
    ev(at(15, 24 + i * 2), 4662, DC_ROOT, SubjectUserName="cersei.lannister", SubjectDomainName="SEVENKINGDOMS",
       Properties="%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}")

events.sort(key=lambda e: e["TimeCreated"])
out = Path(__file__).with_name("goad_demo.jsonl")
out.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
print(f"wrote {len(events)} events -> {out}")
