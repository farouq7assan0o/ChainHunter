"""Cloud identity telemetry: Microsoft Sentinel / Log Analytics tables and Defender XDR advanced-hunting rows.

Supported record shapes (detected per record):
  * Sentinel tables, by `Type`: AuditLogs, SigninLogs, AADNonInteractiveUserSignInLogs, OfficeActivity,
    AzureActivity, AADUserRiskEvents, SecurityAlert
  * Defender XDR rows (Timestamp + ActionType): IdentityQueryEvents, IdentityLogonEvents, CloudAppEvents, ...

Each record is normalised so that:
  * SigmaHQ cloud rules match: they are written against the Azure *diagnostic export* shape
    (`properties.message`, `userAgent`, ...), while Sentinel exports the same data as `ActivityDisplayName`,
    `UserAgent`, ... - the same event, two pipelines, two field names. Both spellings are kept.
  * operation names are compared on normalised text. Real Entra ID data writes "Update application –
    Certificates and secrets management " (en dash + trailing space); SigmaHQ's rule says "... - ..." (hyphen).
    Without this the rule never fires on real data.
  * entities line up with on-prem ones: actor = user principal (DOMAIN\\user and user@domain both reduce to
    `user` in correlation), source = client IP, host = the cloud service or the device.
  * `_platform` (azure | m365 | m365d) is set, so Windows rules never fire on cloud events and vice versa.
"""
from __future__ import annotations

import json
import re

SENTINEL = {
    "auditlogs": ("azure", "Entra ID"),
    "signinlogs": ("azure", "Entra ID"),
    "aadnoninteractiveusersigninlogs": ("azure", "Entra ID"),
    "aaduserriskevents": ("azure", "Entra ID Protection"),
    "azureactivity": ("azure", "Azure Resource Manager"),
    "officeactivity": ("m365", None),  # host = OfficeWorkload (Exchange, SharePoint, ...)
    "securityalert": ("m365", "Security alerts"),
}
JSON_FIELDS = ("InitiatedBy", "TargetResources", "AdditionalDetails", "AdditionalFields_string", "Folders",
               "OperationProperties", "Parameters", "ModifiedProperties", "LocationDetails", "DeviceDetail",
               "Status", "Properties")
DASHES = re.compile(r"[‐-―−]")


def norm_text(s) -> str:
    """Operation names: unicode dashes -> '-', collapse whitespace, strip."""
    return re.sub(r"\s+", " ", DASHES.sub("-", str(s))).strip()


def _parse_json(v):
    if isinstance(v, str) and v[:1] in "[{":
        try:
            return json.loads(v)
        except json.JSONDecodeError:
            return v
    return v


def _flatten(prefix: str, v, out: dict, depth: int = 0):
    if depth > 4:
        return
    if isinstance(v, dict):
        for k, x in v.items():
            _flatten(f"{prefix}.{k}", x, out, depth + 1)
    elif isinstance(v, list):
        if v and all(isinstance(x, dict) and "key" in x and "value" in x for x in v):  # [{key, value}] pairs
            for x in v:
                out.setdefault(f"{prefix}.{x['key']}", x["value"])
        else:
            for i, x in enumerate(v[:5]):
                _flatten(f"{prefix}.{i}", x, out, depth + 1)
            if v and isinstance(v[0], dict):  # Sigma writes `targetResources.type`, meaning the first element
                for k, x in v[0].items():
                    if not isinstance(x, (dict, list)):
                        out.setdefault(f"{prefix}.{k}", x)
    elif v not in (None, ""):
        out.setdefault(prefix, v)


def kind(raw: dict) -> str | None:
    t = str(raw.get("Type", "")).lower()
    if t in SENTINEL:
        return t
    if "Timestamp" in raw and "ActionType" in raw and "EventID" not in raw:
        return "m365d"
    return None


def normalize_cloud(raw: dict) -> dict | None:
    """Return a ChainHunter event for a cloud record, or None if it isn't one (Windows etc.)."""
    k = kind(raw)
    if not k:
        return None
    from .ingest import parse_time  # late import: ingest imports this module
    ev: dict = {}
    for key, v in raw.items():
        if v in (None, "", [], {}):
            continue
        v = _parse_json(v) if key in JSON_FIELDS else v
        if isinstance(v, (dict, list)):
            _flatten(key, v, ev)
            ev[key] = json.dumps(v, ensure_ascii=False)[:4000]  # keep the original, searchable
        else:
            ev[key] = v
    # time, event id, channel, platform
    t = raw.get("TimeGenerated") or raw.get("Timestamp") or raw.get("ActivityDateTime") or raw.get("CreationTime")
    ev["TimeCreated"] = parse_time(t)
    ev["EventID"] = 0
    if k == "m365d":
        ev["_platform"], ev["Channel"] = "m365d", "m365d/" + str(raw.get("ActionType", "")).lower()
        ev["Computer"] = raw.get("DeviceName") or raw.get("DestinationDeviceName") or "Microsoft 365 Defender"
    else:
        ev["_platform"], host = SENTINEL[k]
        ev["Channel"] = k
        ev["Computer"] = host or f"{raw.get('OfficeWorkload', 'Microsoft 365')} Online"
    # entities: actor (user principal) and source (client IP), in the names correlation already reads
    upn = (raw.get("InitiatingUserOrApp") or raw.get("UserPrincipalName") or raw.get("UserId") or raw.get("AccountUpn")
           or raw.get("InitiatingProcessAccountUpn") or ev.get("InitiatedBy.user.userPrincipalName") or raw.get("Caller"))
    if upn:
        ev.setdefault("User", str(upn))
    ip = (raw.get("IPAddress") or raw.get("IpAddress") or raw.get("Client_IPAddress") or raw.get("ClientIP")
          or raw.get("CallerIpAddress") or ev.get("InitiatedBy.user.ipAddress"))
    if ip:
        ev["IpAddress"] = str(ip).split(":")[0] if str(ip).count(":") == 1 else str(ip)  # drop :port on IPv4
    # Sigma (diagnostic-export) aliases for Sentinel column names
    op = raw.get("ActivityDisplayName") or raw.get("OperationName") or raw.get("Operation")
    if op:
        ev["properties.message"] = norm_text(op)
        ev.setdefault("operationName", norm_text(raw.get("OperationName") or op))
    if raw.get("Result"):
        ev.setdefault("properties.result", raw["Result"])
    for key in list(ev):  # UserAgent -> userAgent, TargetResources.type -> targetResources.type, ...
        if key[:1].isupper() and not key.startswith("_"):
            ev.setdefault(key[0].lower() + key[1:], ev[key])
    for key in ("ActivityDisplayName", "OperationName", "Operation"):
        if key in ev and isinstance(ev[key], str):
            ev[key] = norm_text(ev[key])
    return ev
