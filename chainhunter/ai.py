"""Grounded AI analyst: an LLM drafts the incident write-up, ChainHunter verifies every sentence.

    chainhunter hunt logs/ --ai ollama:qwen2.5:3b     # local, offline (default model runs on a 4 GB GPU)
    chainhunter hunt logs/ --ai claude                # Claude API (claude-opus-5-5), when logs may leave the box

The model only ever sees an *evidence pack*: the incident's medium+ alert groups, each with an ID (E1, E2 ...),
time, host, rule, ATT&CK technique, actor and one key field. It must answer in a fixed JSON schema where every
sentence carries the evidence IDs it relies on.

Then the verifier checks each sentence - not the model:
  * it cites at least one evidence ID, and every cited ID exists
  * every host, account, IP address and ATT&CK technique ID it mentions appears in the evidence it cites
Sentences that fail are kept but marked UNSUPPORTED, and the report shows a grounding score. Small local
models do invent hosts and techniques; this is what makes their output usable in a SOC.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .correlate import ALERT_LEVELS, Chain
from .story import group_alerts, short_host, show

MAX_EVIDENCE = 40          # keeps the pack inside a small model's context window
DETAIL_FIELDS = ("CommandLine", "ScriptBlockText", "Image", "TargetImage", "ServiceName", "TaskName",
                 "TargetFilename", "ObjectName", "PipeName", "IpAddress", "TargetUserName", "Properties")

_CLAIM = {  # inlined (no $ref): works with both Ollama's grammar engine and Claude structured outputs
    "type": "object",
    "properties": {"text": {"type": "string"}, "evidence": {"type": "array", "items": {"type": "string"}}},
    "required": ["text", "evidence"],
    "additionalProperties": False,
}
SCHEMA = {
    "type": "object",
    "properties": {
        "executive_summary": {"type": "array", "items": _CLAIM},
        "attack_narrative": {"type": "array", "items": _CLAIM},
        "containment": {"type": "array", "items": _CLAIM},
        "gaps": {"type": "string"},
    },
    "required": ["executive_summary", "attack_narrative", "containment", "gaps"],
    "additionalProperties": False,
}

SYSTEM = """You are a senior SOC analyst writing an incident report from correlated detections.
Rules:
- Use ONLY the evidence items provided. Do not add hosts, accounts, IPs, tools or techniques that are not in them.
- Every sentence is one claim object; its "evidence" array lists the IDs (e.g. "E3") of the items that support it.
- Name hosts, accounts, IPs and ATT&CK IDs exactly as they appear in the evidence.
- executive_summary: 2-4 plain-language sentences for a manager (what happened, how bad, what is affected).
- attack_narrative: the attack in time order, one step per claim.
- containment: concrete, prioritised actions, each tied to the evidence that justifies it.
- gaps: one or two sentences on what the evidence does NOT show (e.g. initial access vector unknown).
Answer with JSON only, matching the schema."""


# ---------- evidence pack ----------

@dataclass
class Evidence:
    id: str
    time: str
    host: str
    severity: str
    alert: str
    phase: str
    attack: list[str]
    actors: list[str]
    count: int
    detail: str

    def text(self) -> str:
        return " ".join([self.host, self.alert, self.phase, *self.attack, *self.actors, self.detail]).lower()

    def line(self) -> str:
        return (f"{self.id} | {self.time} | host={self.host} | {self.severity} | {self.alert} | phase={self.phase} | "
                f"attack={','.join(self.attack) or '-'} | actor={','.join(self.actors) or '-'} | x{self.count}"
                + (f" | {self.detail}" if self.detail else ""))


def evidence_pack(chain: Chain, limit: int = MAX_EVIDENCE) -> list[Evidence]:
    groups = [g for g in group_alerts(chain) if g.level in ALERT_LEVELS] or group_alerts(chain)
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    if len(groups) > limit:  # keep the most severe, then restore time order
        groups = sorted(sorted(groups, key=lambda g: rank.get(g.level, 5))[:limit], key=lambda g: g.first)
    out = []
    for i, g in enumerate(groups, 1):
        ev = g.events[0] if g.events else {}
        detail = next((f"{f}={show(str(ev[f]))[:160]}" for f in DETAIL_FIELDS if ev.get(f)), "")
        out.append(Evidence(f"E{i}", g.first.strftime("%Y-%m-%d %H:%M:%S"), short_host(g.host) or "n/a", g.level,
                            g.rule.title, g.rule.meta.get("kill_chain", ""), g.rule.attack_ids[:3],
                            [show(a) for a in g.actors[:3]], g.count, detail))
    return out


def prompt(chain: Chain, pack: list[Evidence]) -> str:
    hosts = sorted({short_host(h) for h in chain.entities["hosts"]})
    return (f"Incident window: {chain.start:%Y-%m-%d %H:%M:%S} to {chain.end:%Y-%m-%d %H:%M:%S} UTC. "
            f"Severity {chain.severity}. Hosts: {', '.join(hosts)}.\n\nEvidence:\n" + "\n".join(e.line() for e in pack))


# ---------- verification ----------

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


@dataclass
class Claim:
    text: str
    evidence: list[str]
    problems: list[str] = field(default_factory=list)

    @property
    def grounded(self) -> bool:
        return not self.problems


def _entities(chain: Chain) -> dict[str, str]:
    """Known entity strings (lower-case -> kind) the verifier looks for in claims."""
    ents: dict[str, str] = {}
    for h in chain.entities["hosts"]:
        ents[short_host(h).lower()] = "host"
    for a in chain.entities["accounts"]:
        name = show(a).split("\\")[-1].lower()
        if len(name) > 3:
            ents[name] = "account"
    return ents


def verify(raw: dict, chain: Chain, pack: list[Evidence]) -> dict[str, list[Claim]]:
    by_id = {e.id: e for e in pack}
    known = _entities(chain)
    all_hosts = {short_host(h).lower() for h in chain.entities["hosts"]}
    out: dict[str, list[Claim]] = {}
    for section in ("executive_summary", "attack_narrative", "containment"):
        claims = []
        for item in raw.get(section, []) or []:
            c = Claim(str(item.get("text", "")).strip(), [str(x).strip() for x in item.get("evidence", []) or []])
            if not c.text:
                continue
            if not c.evidence:
                c.problems.append("cites no evidence")
            bad = [x for x in c.evidence if x not in by_id]
            if bad:
                c.problems.append(f"cites non-existent evidence {', '.join(bad)}")
            cited = " ".join(by_id[x].text() for x in c.evidence if x in by_id)
            low = c.text.lower()
            for ent, kind in known.items():
                if re.search(rf"(?<![\w.-]){re.escape(ent)}(?![\w-])", low) and ent not in cited:
                    c.problems.append(f"{kind} '{ent}' is not in the cited evidence")
            for ip in IP_RE.findall(c.text):
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if ip not in cited:
                    c.problems.append(f"IP {ip} is not in the cited evidence")
            for t in TECH_RE.findall(c.text):
                if t.lower() not in cited:
                    c.problems.append(f"technique {t} is not in the cited evidence")
            # a host-looking token that isn't any known host at all = invented
            for tok in re.findall(r"\b[A-Z][A-Z0-9-]{3,}\b", c.text):
                if tok.lower() not in all_hosts and tok.lower() not in known and tok.isupper() and "-" in tok:
                    c.problems.append(f"'{tok}' looks like a host that is not in this incident")
            claims.append(c)
        out[section] = claims
    return out


def score(verified: dict[str, list[Claim]]) -> tuple[int, int]:
    claims = [c for cs in verified.values() for c in cs]
    return sum(c.grounded for c in claims), len(claims)


# ---------- backends ----------

class BackendError(RuntimeError):
    pass


class Ollama:
    """Local model through Ollama's HTTP API (structured output via a JSON schema in `format`)."""

    def __init__(self, model: str, host: str | None = None, num_ctx: int = 8192):
        self.model = model
        self.host = (host or os.environ.get("OLLAMA_HOST") or "http://127.0.0.1:11434").rstrip("/")
        if not self.host.startswith("http"):
            self.host = "http://" + self.host
        self.num_ctx = num_ctx

    def complete(self, system: str, user: str, schema: dict) -> dict:
        body = {"model": self.model, "stream": False, "format": schema,
                "options": {"temperature": 0.1, "num_ctx": self.num_ctx},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        req = urllib.request.Request(f"{self.host}/api/chat", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=900) as r:
                data = json.loads(r.read())
        except urllib.error.URLError as e:
            raise BackendError(f"Ollama not reachable at {self.host} ({e.reason}). Is it installed and running? "
                               f"Try: ollama run {self.model} \"hi\"") from e
        if data.get("error"):
            raise BackendError(f"Ollama: {data['error']} (did you run: ollama pull {self.model}?)")
        try:
            return json.loads(data["message"]["content"])
        except (KeyError, json.JSONDecodeError) as e:
            raise BackendError(f"{self.model} did not return valid JSON") from e


class Claude:
    """Claude API backend (official SDK). Credentials resolve from ANTHROPIC_API_KEY or an `ant auth login` profile."""

    def __init__(self, model: str = "claude-opus-5-5"):
        try:
            import anthropic
        except ImportError as e:
            raise BackendError("The Claude backend needs the SDK: python -m pip install anthropic") from e
        self.anthropic = anthropic
        self.client = anthropic.Anthropic()
        self.model = model

    def complete(self, system: str, user: str, schema: dict) -> dict:
        a = self.anthropic
        try:
            resp = self.client.beta.messages.create(
                model=self.model,
                max_tokens=16000,
                system=system,
                messages=[{"role": "user", "content": user}],
                output_config={"effort": "medium", "format": {"type": "json_schema", "schema": schema}},
                # server-side refusal fallback: security content can trip safety classifiers
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
            )
        except a.AuthenticationError as e:
            raise BackendError("Claude API: no valid credentials (set ANTHROPIC_API_KEY or run `ant auth login`)") from e
        except a.RateLimitError as e:
            raise BackendError("Claude API: rate limited, try again shortly") from e
        except a.APIStatusError as e:
            raise BackendError(f"Claude API error {e.status_code}: {e.message}") from e
        except a.APIConnectionError as e:
            raise BackendError("Claude API: network error") from e
        if resp.stop_reason == "refusal":
            raise BackendError("Claude declined this request (refusal)")
        text = next((b.text for b in resp.content if b.type == "text"), "")
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise BackendError("Claude returned no JSON") from e


def backend(spec: str):
    """'ollama:MODEL' | 'claude' | 'claude:MODEL'"""
    kind, _, model = spec.partition(":")
    if kind == "ollama":
        return Ollama(model or "qwen2.5:3b")
    if kind == "claude":
        return Claude(model or "claude-opus-5-5")
    raise SystemExit(f"[x] unknown --ai backend '{spec}' (use ollama:MODEL or claude)")


# ---------- orchestration + rendering ----------

@dataclass
class Analysis:
    chain_index: int
    pack: list[Evidence]
    verified: dict[str, list[Claim]]
    gaps: str
    model: str
    error: str = ""


def analyse(chains: list[Chain], spec: str, top: int = 3) -> list[Analysis]:
    be = backend(spec)
    out = []
    for i, c in enumerate(chains[:top]):
        pack = evidence_pack(c)
        try:
            raw = be.complete(SYSTEM, prompt(c, pack), SCHEMA)
            out.append(Analysis(i, pack, verify(raw, c, pack), str(raw.get("gaps", "")), spec))
        except BackendError as e:
            out.append(Analysis(i, pack, {}, "", spec, error=str(e)))
    return out


def markdown(analyses: list[Analysis]) -> str:
    lines = ["# AI analyst draft (grounded)", ""]
    for a in analyses:
        lines.append(f"## Incident {a.chain_index + 1}")
        if a.error:
            lines += [f"_AI draft unavailable: {a.error}_", ""]
            continue
        ok, n = score(a.verified)
        lines += [f"_Model: `{a.model}` · grounding: **{ok}/{n}** claims verified against cited evidence_", ""]
        for section, title in (("executive_summary", "Executive summary"), ("attack_narrative", "Attack narrative"),
                               ("containment", "Containment")):
            lines.append(f"### {title}")
            for c in a.verified.get(section, []):
                cite = ", ".join(c.evidence) or "none"
                flag = "" if c.grounded else f" **⚠ UNSUPPORTED: {'; '.join(c.problems)}**"
                lines.append(f"- {c.text} [{cite}]{flag}")
            lines.append("")
        if a.gaps:
            lines += ["### Evidence gaps", a.gaps, ""]
        lines += ["### Evidence pack", "", "| ID | Time | Host | Severity | Alert | ATT&CK |", "|---|---|---|---|---|---|"]
        lines += [f"| {e.id} | {e.time} | {e.host} | {e.severity} | {e.alert} | {', '.join(e.attack)} |" for e in a.pack]
        lines.append("")
    return "\n".join(lines)


def html_section(a: Analysis) -> str:
    import html as _h
    e = _h.escape
    if a.error:
        return f"<h3>AI analyst draft</h3><p class='muted'>Unavailable: {e(a.error)}</p>"
    ok, n = score(a.verified)
    p = [f"<h3>AI analyst draft <span class='muted' style='text-transform:none;letter-spacing:0'>— {e(a.model)} · "
         f"grounding {ok}/{n} claims verified against cited evidence</span></h3><div class='ai'>"]
    for section, title in (("executive_summary", "Executive summary"), ("attack_narrative", "Attack narrative"),
                           ("containment", "Containment")):
        p.append(f"<h4>{title}</h4><ul>")
        for c in a.verified.get(section, []):
            tip = e(" | ".join(x.line() for x in a.pack if x.id in c.evidence))
            cite = f"<span class='cite' title='{tip}'>[{e(', '.join(c.evidence) or 'no evidence')}]</span>"
            warn = "" if c.grounded else f" <span class='badge critical'>unsupported: {e('; '.join(c.problems))}</span>"
            p.append(f"<li class='{'ok' if c.grounded else 'bad'}'>{e(c.text)} {cite}{warn}</li>")
        p.append("</ul>")
    if a.gaps:
        p.append(f"<h4>Evidence gaps</h4><p>{e(a.gaps)}</p>")
    p.append("</div>")
    return "".join(p)
