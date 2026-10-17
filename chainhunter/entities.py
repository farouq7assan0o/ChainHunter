"""Entity pages: one page per host, account and source, so an analyst can pivot the way investigations work.

    out/entities/index.html           every entity, sorted by risk, with search and a type filter
    out/entities/<kind>-<name>.html   timeline of every detection involving it (across incidents), its ATT&CK
                                      techniques, and related entities as links (host -> accounts seen on it,
                                      account -> hosts it touched and sources it came from)

The main report links here, so the path incident -> host -> account -> next host never leaves the browser.
"""
from __future__ import annotations

import hashlib
import html
import re
from collections import Counter
from dataclasses import dataclass, field

from .correlate import ALERT_LEVELS, Chain, _entities, risk_of
from .detect import Detection
from .sequence import norm_entity
from .story import short_host, show

KIND_LABEL = {"actor": "Account", "host": "Host", "source": "Source"}


def slug(kind: str, value: str) -> str:
    """Stable, filesystem-safe page name for an entity (same normalisation as correlation)."""
    norm = norm_entity(value, kind)
    safe = re.sub(r"[^a-z0-9._-]+", "_", norm.lower()).strip("_")[:60] or "x"
    return f"{KIND_LABEL[kind].lower()}-{safe}-{hashlib.sha1(norm.encode()).hexdigest()[:6]}"


@dataclass
class Entity:
    kind: str
    label: str
    detections: list[Detection] = field(default_factory=list)
    incidents: set[int] = field(default_factory=set)
    related: Counter = field(default_factory=Counter)   # (kind, norm) -> co-occurrence count
    _ids: set = field(default_factory=set)              # detection identity (dataclass == would compare deeply)

    @property
    def risk(self) -> int:
        return sum(risk_of(d) for d in self.detections)

    @property
    def techniques(self) -> list[str]:
        return sorted({t for d in self.detections for t in d.rule.attack_ids})

    @property
    def first(self):
        return min(d.time for d in self.detections)

    @property
    def last(self):
        return max(d.end for d in self.detections)


def collect(chains: list[Chain]) -> dict[tuple[str, str], Entity]:
    ents: dict[tuple[str, str], Entity] = {}
    for n, c in enumerate(chains, 1):
        for d in c.detections:
            keys = []
            for kind, value in _entities(d):
                k = (kind, norm_entity(value, kind))
                ent = ents.setdefault(k, Entity(kind, value))
                if id(d) not in ent._ids:
                    ent._ids.add(id(d))
                    ent.detections.append(d)
                ent.incidents.add(n)
                keys.append(k)
            for a in keys:
                for b in keys:
                    if a != b:
                        ents[a].related[b] += 1
    for e in ents.values():
        e.detections.sort(key=lambda d: d.time)
    return ents


def _page(title: str, body: str) -> str:
    from .report import _CSS
    return (f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' "
            f"content='width=device-width,initial-scale=1'><title>{html.escape(title)}</title><style>{_CSS}"
            "a{color:var(--host)}.crumbs{margin:0 0 6px;font-size:14px}</style></head><body><main>"
            f"{body}</main></body></html>")


def render_entity(ent: Entity, ents: dict[tuple[str, str], Entity]) -> str:
    e = html.escape
    label = show(ent.label)
    kind = KIND_LABEL[ent.kind]
    p = [f"<p class='crumbs'><a href='../report.html'>← report</a> · <a href='index.html'>all entities</a></p>",
         f"<h1>{e(label)}</h1><p class='muted'>{kind} · seen {ent.first:%Y-%m-%d %H:%M:%S} → {ent.last:%Y-%m-%d %H:%M:%S} UTC"
         f" · incident(s) {', '.join(str(i) for i in sorted(ent.incidents))}</p><div class='stats'>"]
    alerting = [d for d in ent.detections if d.rule.level in ALERT_LEVELS]
    for lbl, val in (("Risk", f"{ent.risk:,}"), ("Detections", len(ent.detections)), ("Medium+", len(alerting)),
                     ("ATT&CK techniques", len(ent.techniques)), ("Related entities", len(ent.related))):
        p.append(f"<div class='stat'><b>{e(str(val))}</b><span class='muted'>{lbl}</span></div>")
    p.append("</div>")
    if ent.techniques:
        p.append("<h3>ATT&amp;CK techniques</h3><div class='chips'>" + "".join(
            f"<a class='chip' href='https://attack.mitre.org/techniques/{e(t.replace('.', '/'))}/' target='_blank' "
            f"rel='noopener'>{e(t)}</a>" for t in ent.techniques) + "</div>")
    # related entities, grouped by kind (host -> accounts on it, account -> hosts it touched, ...)
    p.append("<h3>Related entities</h3>")
    groups = {"host": "Hosts", "actor": "Accounts", "source": "Sources"}
    any_rel = False
    for k, title in groups.items():
        rel = [(key, cnt) for key, cnt in ent.related.most_common() if key[0] == k and key in ents]
        if not rel:
            continue
        any_rel = True
        p.append(f"<h4>{title}</h4><div class='chips'>" + "".join(
            f"<a class='chip' href='{slug(key[0], ents[key].label)}.html' title='seen together in {cnt} detection(s)'>"
            f"{e(show(short_host(ents[key].label) if key[0] == 'host' else ents[key].label))} · {cnt}</a>"
            for key, cnt in rel[:40]) + "</div>")
    if not any_rel:
        p.append("<p class='muted'>None.</p>")
    # timeline
    p.append("<h3>Timeline</h3><div class='tbl'><table><tr><th>Time (UTC)</th><th>Severity</th><th>Detection</th>"
             "<th>Host</th><th>Account</th><th>Source</th></tr>")

    def link(kind_, value):
        if not value:
            return "-"
        shown = short_host(value) if kind_ == "host" else value
        return f"<a href='{slug(kind_, value)}.html'>{e(show(shown))}</a>"

    for d in ent.detections[:2000]:
        tag = f" <span class='tag {d.rule.kind}'>{d.rule.kind.upper()}</span>" if d.rule.kind != "signature" else ""
        p.append(f"<tr><td class='muted'>{d.time:%Y-%m-%d %H:%M:%S}</td><td class='lvl {e(d.rule.level)}'>{e(d.rule.level)}</td>"
                 f"<td>{e(d.rule.title)}{tag}<div class='muted'>{e(', '.join(d.rule.attack_ids[:3]))}</div></td>"
                 f"<td>{link('host', d.host)}</td><td>{link('actor', d.actor)}</td><td>{link('source', d.source)}</td></tr>")
    if len(ent.detections) > 2000:
        p.append(f"<tr><td colspan='6' class='muted'>… {len(ent.detections) - 2000} more</td></tr>")
    p.append("</table></div>")
    return _page(f"{label} · ChainHunter", "".join(p))


def render_index(ents: dict[tuple[str, str], Entity]) -> str:
    e = html.escape
    rows = sorted(ents.values(), key=lambda x: -x.risk)
    p = ["<p class='crumbs'><a href='../report.html'>← report</a></p><h1>Entities</h1>"
         f"<p class='muted'>{len(rows)} hosts, accounts and sources across all incidents, sorted by risk.</p>"
         "<div class='filters'><input type='search' class='f-q' placeholder='Search…'>"
         "<select class='f-k'><option value=''>All types</option><option>Host</option><option>Account</option>"
         "<option>Source</option></select></div><div class='tbl'><table><tr><th>Entity</th><th>Type</th><th>Risk</th>"
         "<th>Detections</th><th>Techniques</th><th>First seen</th><th>Last seen</th></tr>"]
    for x in rows:
        kind = KIND_LABEL[x.kind]
        p.append(f"<tr class='ent' data-k='{kind}' data-q='{e(x.label.lower())}'><td><a href='{slug(x.kind, x.label)}.html'>"
                 f"{e(show(x.label))}</a></td><td>{kind}</td><td>{x.risk:,}</td><td>{len(x.detections)}</td>"
                 f"<td>{len(x.techniques)}</td><td class='muted'>{x.first:%Y-%m-%d %H:%M}</td>"
                 f"<td class='muted'>{x.last:%Y-%m-%d %H:%M}</td></tr>")
    p.append("</table></div><script>const q=document.querySelector('.f-q'),k=document.querySelector('.f-k');"
             "const f=()=>document.querySelectorAll('tr.ent').forEach(r=>r.style.display=(!k.value||r.dataset.k===k.value)"
             "&&r.dataset.q.includes(q.value.toLowerCase())?'':'none');q.addEventListener('input',f);k.addEventListener('input',f);"
             "</script>")
    return _page("Entities · ChainHunter", "".join(p))


def write_pages(chains: list[Chain], out_dir) -> int:
    ents = collect(chains)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "index.html").write_text(render_index(ents), encoding="utf-8")
    for ent in ents.values():
        (out_dir / f"{slug(ent.kind, ent.label)}.html").write_text(render_entity(ent, ents), encoding="utf-8")
    return len(ents)
