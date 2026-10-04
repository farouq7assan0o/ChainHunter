"""Scale layer: a Parquet "lake" queried with DuckDB, so detection runs where the data is.

    chainhunter lake  <logs...> -o lake/        # ingest once: EVTX/JSON -> compressed columnar Parquet
    chainhunter hunt  --lake lake/ -r rules      # every rule becomes a SQL query; only hits reach Python

Design:
  * Ingest streams file by file and writes Parquet chunks, so memory is bounded by the chunk size, not by
    the dataset. Every field is stored as VARCHAR except EventID (INTEGER) and TimeCreated (TIMESTAMP, UTC).
  * Each Sigma rule compiles to a SQL WHERE clause that DuckDB evaluates over the lake with column pruning
    and EventID row-group pruning. The SQL is a *superset pre-filter*; every returned row is re-checked by
    the exact Python matcher. Results are therefore identical to the in-memory engine by construction,
    and rule features SQL can't express (cidr, keyword search) fall back to Python over candidate events.
  * Fields a rule references that don't exist in the lake compile to FALSE (NULL-safe), matching the
    engine's "absent field never matches" semantics, including under NOT.
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from .detect import (SERVICE_CHANNELS, Detection, Rule, apply_threshold, build_detection, candidate_eids,
                     parse_condition, rule_matches)
from .ingest import SUPPORTED, NoEventsError, load_evtx, load_json

import fnmatch


def _duckdb():
    try:
        import duckdb
    except ImportError as e:
        raise SystemExit("The lake needs DuckDB: python -m pip install duckdb") from e
    return duckdb


# ---------- build ----------

def _iter_files(paths: list[Path]):
    for p in paths:
        if not p.exists():
            raise NoEventsError(f"[x] input not found: {p}")
        files = [f for f in (sorted(p.rglob("*")) if p.is_dir() else [p]) if f.suffix.lower() in SUPPORTED]
        if not files:
            raise NoEventsError(f"[x] no supported log files in: {p}")
        yield from files


def _row(ev: dict) -> dict:
    out = {}
    for k, v in ev.items():
        if v in (None, ""):
            continue
        if k == "TimeCreated":
            out[k] = v.astimezone(timezone.utc).replace(tzinfo=None).isoformat(sep=" ")
        elif k == "EventID":
            out[k] = int(v)
        else:
            out[k] = str(v)
    return out


def build_lake(paths: list[Path], out: Path, chunk: int = 250_000) -> dict:
    """Stream logs into Parquet chunks sorted by (EventID, TimeCreated) for row-group pruning."""
    duckdb = _duckdb()
    out.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect()
    stats = {"events": 0, "files": 0, "chunks": 0, "seconds": 0.0}
    t0 = time.time()
    tmpdir = Path(tempfile.mkdtemp(prefix="chainhunter-lake-"))
    buf, keys = [], set()
    # DuckDB column names are case-insensitive, real logs are not (APT29 has both 'IpAddress' and 'Ipaddress').
    # Merge case-variants into one column and remember every spelling so rules can use any of them.
    canon: dict[str, str] = {}
    spellings: dict[str, set[str]] = {}

    def flush():
        nonlocal buf, keys
        if not buf:
            return
        n = stats["chunks"]
        src = tmpdir / f"chunk-{n:05d}.ndjson"
        with src.open("w", encoding="utf-8") as fh:
            for r in buf:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        cols = {k: "VARCHAR" for k in keys}
        cols.update({"EventID": "INTEGER", "TimeCreated": "TIMESTAMP"})
        dest = out / f"events-{n:05d}.parquet"
        offset = stats["events"] - len(buf)  # global, stable row id: lets detection return ids, not wide rows
        con.execute(
            f"COPY (SELECT *, ({offset} + row_number() OVER ())::BIGINT AS _rid "
            f"FROM read_json(?, format='newline_delimited', columns={cols!r}) "
            f"ORDER BY EventID, TimeCreated) TO '{dest.as_posix()}' (FORMAT parquet, COMPRESSION zstd, ROW_GROUP_SIZE 50000)",
            [src.as_posix()])
        src.unlink()
        stats["chunks"] += 1
        buf, keys = [], set()

    for f in _iter_files(paths):
        stats["files"] += 1
        for ev in (load_evtx(f) if f.suffix.lower() == ".evtx" else load_json(f)):
            if "TimeCreated" not in ev:
                continue
            r = {}
            for k, v in _row(ev).items():
                c = canon.setdefault(k.lower(), k)
                spellings.setdefault(c, set()).add(k)
                r.setdefault(c, v)
            buf.append(r)
            keys.update(r)
            stats["events"] += 1
            if len(buf) >= chunk:
                flush()
    flush()
    tmpdir.rmdir()
    variants = {c: sorted(s) for c, s in spellings.items() if len(s) > 1}
    (out / "_fields.json").write_text(json.dumps(variants, indent=1), encoding="utf-8")
    stats["case_merged_fields"] = len(variants)
    if not stats["events"]:
        raise NoEventsError("[x] 0 events loaded: nothing to write to the lake")
    stats["seconds"] = round(time.time() - t0, 1)
    stats["bytes"] = sum(p.stat().st_size for p in out.glob("events-*.parquet"))
    return stats


# ---------- Sigma -> SQL (superset pre-filter) ----------

class SqlUnsupported(Exception):
    pass


def _q(col: str) -> str:
    return '"' + col.replace('"', '""') + '"'


def _lit(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


def _like(pattern: str) -> str:
    """Sigma wildcard (* ?) -> LIKE pattern with \\ as escape."""
    out = []
    for ch in pattern:
        if ch == "*":
            out.append("%")
        elif ch == "?":
            out.append("_")
        elif ch in "%_\\":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


_RE_CACHE: dict[str, bool] = {}


def valid_re(pattern: str) -> bool:
    """Can DuckDB's RE2 compile this? SigmaHQ regexes are PCRE-flavoured (e.g. \u2800 escapes); one invalid
    pattern used to fail a whole 100-rule batch and force 100 single-rule rescans."""
    if pattern not in _RE_CACHE:
        try:
            # validate exactly as compiled: an inlined literal (a bound parameter is checked differently)
            _duckdb().execute(f"SELECT regexp_matches('', {_lit(pattern)})").fetchall()
            _RE_CACHE[pattern] = True
        except Exception:
            _RE_CACHE[pattern] = False
    return _RE_CACHE[pattern]


def _widen(pos: bool) -> str:
    """Stand-in for a term SQL can't express. Positive position -> TRUE, under NOT -> FALSE: either way the
    SQL can only admit *more* rows, never fewer, and the Python re-check restores exactness."""
    return "TRUE" if pos else "FALSE"


def _term(field: str, value, mods: list[str], cols: set[str], pos: bool = True) -> str:
    if field == "EventID":
        if value is None:
            return "FALSE"
        try:
            return f"EventID = {int(value)}"
        except (TypeError, ValueError):
            return "FALSE"
    if field not in cols:  # absent column: never matches (and a `null` expectation always does)
        return "TRUE" if value is None else "FALSE"
    c = _q(field)
    if value is None:
        return f"({c} IS NULL OR {c} = '')"
    if "cidr" in mods:
        return _widen(pos)
    if "re" in mods:
        return f"COALESCE(regexp_matches({c}, {_lit(value)}), FALSE)" if valid_re(str(value)) else _widen(pos)
    v = str(value)
    variants = {v, v.replace("-", "/"), v.replace("/", "-")} if "windash" in mods else {v}
    parts = []
    for x in variants:
        if not {"contains", "startswith", "endswith"} & set(mods) and "[" in x and ("*" in x or "?" in x):
            return _widen(pos)  # fnmatch character classes have no LIKE equivalent
        if "contains" in mods:
            pat = f"*{x}*"
        elif "startswith" in mods:
            pat = f"{x}*"
        elif "endswith" in mods:
            pat = f"*{x}"
        else:
            pat = x
        parts.append(f"COALESCE({c} ILIKE {_lit(_like(pat))} ESCAPE '\\', FALSE)")
    return parts[0] if len(parts) == 1 else "(" + " OR ".join(parts) + ")"


IOC_LIST_MIN = 16  # value lists this long compile to one regex alternation instead of N ILIKE terms


def _re_literal(s: str) -> str:
    """Escape for RE2 (ASCII punctuation only - RE2 rejects escaped non-ASCII), Sigma wildcards -> regex."""
    out = []
    for ch in s:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        elif ch.isascii() and not ch.isalnum() and ch not in " _-":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def _ioc_term(field: str, vals: list, mods: list[str], cols: set[str]) -> str | None:
    """IOC-style lists (thousands of hashes, tool names) as a single case-insensitive regex: DuckDB plans one
    expression instead of thousands of ORs. 'Vulnerable Driver Load' went from 10.7s of planning to milliseconds."""
    if (len(vals) < IOC_LIST_MIN or field == "EventID" or field not in cols or set(mods) - {"contains", "startswith", "endswith"}
            or any(v is None for v in vals)):
        return None
    alt = "|".join(_re_literal(str(v)) for v in vals)
    pre = "" if {"contains", "endswith"} & set(mods) else "^"
    post = "" if {"contains", "startswith"} & set(mods) else "$"
    pattern = f"(?i){pre}(?:{alt}){post}"
    return f"COALESCE(regexp_matches({_q(field)}, {_lit(pattern)}), FALSE)" if valid_re(pattern) else None


def _selection(sel, cols: set[str], pos: bool = True) -> str:
    if isinstance(sel, list):
        if sel and all(isinstance(s, (str, int)) for s in sel):
            # Sigma keyword search: the engine matches against every value of the event; so does this
            # `_blob` is a computed column on the scan view (DuckDB forbids *COLUMNS() under NOT). All keywords go
            # in ONE regex pass: the ~100-keyword AV rule otherwise rescans the blob 100 times.
            pattern = "(?i)(?:" + "|".join(_re_literal(str(k).strip("*")) for k in sel) + ")"
            if valid_re(pattern):
                return f"COALESCE(regexp_matches(\"_blob\", {_lit(pattern)}), FALSE)"
            return "(" + " OR ".join(f"COALESCE(\"_blob\" ILIKE {_lit(_like('*' + str(k).strip('*') + '*'))} ESCAPE '\\', FALSE)"
                                     for k in sel) + ")"
        maps = [s for s in sel if isinstance(s, dict)]
        return "(" + " OR ".join(_selection(m, cols, pos) for m in maps) + ")" if maps else "FALSE"
    parts = []
    for key, expected in sel.items():
        f, *mods = key.split("|")
        vals = expected if isinstance(expected, list) else [expected]
        ioc = _ioc_term(f, vals, mods, cols)
        if ioc:
            parts.append(ioc)
            continue
        terms = [_term(f, v, mods, cols, pos) for v in vals]
        parts.append("(" + (" AND " if "all" in mods else " OR ").join(terms) + ")")
    return "(" + " AND ".join(parts) + ")" if parts else "TRUE"


def _ast(node, sels: dict[bool, dict[str, str]], pos: bool = True) -> str:
    op = node[0]
    if op == "ref":
        return sels[pos][node[1]]
    if op == "not":
        return f"(NOT {_ast(node[1], sels, not pos)})"
    if op in ("and", "or"):
        return f"({_ast(node[1], sels, pos)} {op.upper()} {_ast(node[2], sels, pos)})"
    names = [k for k in sels[pos] if fnmatch.fnmatchcase(k, node[1])]
    if not names:
        return "FALSE"
    return "(" + (" OR " if op == "any" else " AND ").join(sels[pos][k] for k in names) + ")"


def _squash(s: str) -> str:
    return s.lower().replace("-", "").replace(" ", "").replace("/", "")


def _channel_sql(rule: Rule, present_channels: set[str] | None) -> str | None:
    """Mirror of detect._channel_ok as SQL. Returns 'FALSE' when the rule's log channel isn't in the lake at all,
    None when there's nothing to restrict. Events without a channel always pass (as in the engine)."""
    service = str(rule.logsource.get("service", "")).lower()
    if not service:
        return None
    known = SERVICE_CHANNELS.get(service)
    if present_channels is not None:
        seen = [c for c in present_channels if c and (c in known if known else _squash(service) in _squash(c))]
        if not seen and "" not in present_channels:
            return "FALSE"
    ch = "lower(COALESCE(Channel, ''))"
    if known:
        return f"({ch} = '' OR {ch} IN ({', '.join(_lit(c) for c in sorted(known))}))"
    return f"({ch} = '' OR replace(replace(replace({ch}, '-', ''), ' ', ''), '/', '') LIKE {_lit('%' + _squash(service) + '%')})"


def compile_where(rule: Rule, cols: set[str], present_eids: set[int] | None = None,
                  present_channels: set[str] | None = None) -> str:
    """Compile a rule to a SQL superset of what it matches. Never raises for unsupported Sigma features: those
    terms are widened by polarity. `present_eids` / `present_channels` describe the lake: a rule whose event
    types or log channel are absent compiles to FALSE without building SQL (Blindspot's dead-rule logic
    applied to execution)."""
    eids = candidate_eids(rule)
    if eids is not None and present_eids is not None:
        eids = eids & present_eids
        if not eids:
            return "FALSE"
    chan = _channel_sql(rule, present_channels) if "Channel" in cols or present_channels is not None else None
    if chan == "FALSE":
        return "FALSE"
    det = rule.detection
    sels = {pol: {k: _selection(v, cols, pol) for k, v in det.items() if k != "condition"} for pol in (True, False)}
    where = _ast(parse_condition(det["condition"]), sels)
    if chan and "Channel" in cols:
        where = f"{chan} AND {where}"
    if eids is not None:
        where = f"EventID IN ({', '.join(str(e) for e in sorted(eids))}) AND {where}" if eids else "FALSE"
    return where


# ---------- query ----------

class Lake:
    def __init__(self, path: Path, files: list[Path] | None = None, threads: int | None = None):
        duckdb = _duckdb()
        files = files or (sorted(path.glob("events-*.parquet")) if path.is_dir() else [])
        if not files:
            raise NoEventsError(f"[x] no lake at {path} (build one with: chainhunter lake <logs> -o {path})")
        self.path = path
        self.files = files
        self.con = duckdb.connect()
        if threads:
            self.con.execute(f"SET threads = {int(threads)}")
        flist = ", ".join(_lit(f.as_posix()) for f in files)
        self.con.execute(f"CREATE VIEW events AS SELECT * FROM read_parquet([{flist}], union_by_name=true)")
        self.columns = {r[0] for r in self.con.execute("DESCRIBE events").fetchall()}
        # detection scans read this view: `_blob` (every value, for Sigma keyword search) is only computed
        # when a rule references it, thanks to projection pushdown
        self.con.execute("CREATE VIEW scan AS SELECT *, concat_ws(' ', *COLUMNS(* EXCLUDE (_rid))) AS _blob FROM events"
                         if "_rid" in self.columns else "CREATE VIEW scan AS SELECT * FROM events")
        side = path / "_fields.json"
        self.variants: dict[str, list[str]] = json.loads(side.read_text(encoding="utf-8")) if side.exists() else {}
        for spells in self.variants.values():
            self.columns |= set(spells)  # a rule may use any spelling; DuckDB resolves it case-insensitively

    def count(self) -> int:
        return self.con.execute("SELECT count(*) FROM events").fetchone()[0]

    def select_list(self, fields: set[str] | None) -> str:
        """Projection: only the columns asked for (any spelling), or * when fields is None."""
        if fields is None:
            return "*"
        lower = {c.lower(): c for c in self.columns - {"_blob"}}
        cols = {lower[f.lower()] for f in fields if f.lower() in lower} | {"EventID", "TimeCreated", "_rid"}
        return ", ".join(_q(c) for c in sorted(cols & (self.columns | {"_rid"})))

    def query(self, where: str, limit: int | None = None, fields: set[str] | None = None) -> list[dict]:
        sql = (f"SELECT {self.select_list(fields)} FROM events WHERE {where} ORDER BY TimeCreated"
               + (f" LIMIT {limit}" if limit else ""))
        cur = self.con.execute(sql)
        names = [d[0] for d in cur.description]
        return [self._event(names, row) for row in cur.fetchall()]

    def _event(self, names: list[str], row) -> dict:
        """DuckDB row -> engine event: drop NULLs and _rid, restore every field spelling, UTC-aware time."""
        ev = {k: v for k, v in zip(names, row) if v is not None and k != "_rid"}
        for k in [k for k in ev if k in self.variants]:
            for alt in self.variants[k]:
                ev.setdefault(alt, ev[k])
        t = ev.get("TimeCreated")
        if isinstance(t, datetime):
            ev["TimeCreated"] = t.replace(tzinfo=timezone.utc)
        return ev

    def events_for_eids(self, eids, fields: set[str] | None = None) -> list[dict]:
        eids = sorted({int(e) for e in eids})
        return self.query(f"EventID IN ({', '.join(map(str, eids))})", fields=fields) if eids else []


# Fields every later stage may read (entity extraction, correlation, reports, process tree)
CORE_FIELDS = {"EventID", "TimeCreated", "Channel", "Provider", "Provider_Name", "Computer",
               "SubjectUserName", "SubjectDomainName", "TargetUserName", "TargetDomainName", "User", "IpAddress",
               "WorkstationName", "LogonType", "ProcessGuid", "ParentProcessGuid", "SourceProcessGuid",
               "SourceProcessGUID", "Image", "ParentImage", "CommandLine", "ParentCommandLine", "SourceImage",
               "TargetImage", "SourceUser", "ServiceName", "TicketEncryptionType", "Status"}


def rule_fields(rule: Rule) -> set[str] | None:
    """Every field a rule's matcher, entity extraction or threshold reads. None = needs all (keyword search)."""
    out: set[str] = set()

    def walk(sel):
        nonlocal out
        if isinstance(sel, dict):
            out |= {k.split("|")[0] for k in sel}
        elif isinstance(sel, list):
            if sel and all(isinstance(s, (str, int)) for s in sel):
                return False
            for s in sel:
                if walk(s) is False:
                    return False
        return True

    for k, v in rule.detection.items():
        if k != "condition" and walk(v) is False:
            return None
    m = rule.meta
    for key in ("actor_field", "host_field", "source_field", "collect_targets"):
        v = m.get(key)
        out |= set(v) if isinstance(v, list) else ({v} if v else set())
    thr = m.get("threshold") or {}
    out |= set(thr.get("group_by", [])) | ({thr["distinct"]} if thr.get("distinct") else set())
    return out


def lake_profile(lake: Lake):
    """Blindspot's telemetry profile computed inside DuckDB (counts and field presence), no rows in Python."""
    from .blindspot import Profile
    p = Profile(events=lake.count())
    con = lake.con
    has_ch = "Channel" in lake.columns
    ch = "lower(COALESCE(Channel, ''))" if has_ch else "''"
    sysmon_only = f"(EventID > 29 AND EventID <> 255) OR {ch} = '' OR {ch} LIKE '%sysmon%'"
    for eid, n in con.execute(f"SELECT EventID, count(*) FROM events WHERE {sysmon_only} GROUP BY 1").fetchall():
        p.by_eid[eid] = n
    for c, n in con.execute(f"SELECT {ch}, count(*) FROM events GROUP BY 1").fetchall():
        p.channels[c] += n
    if "Computer" in lake.columns:
        for h, c, n in con.execute(f"SELECT upper(split_part(COALESCE(Computer, ''), '.', 1)), {ch}, count(*) "
                                   f"FROM events GROUP BY 1, 2").fetchall():
            p.host_channels[h][c] += n
    fields = sorted(lake.columns - {"EventID"})
    for i in range(0, len(fields), 400):  # field presence per EventID, in column batches
        batch = fields[i:i + 400]
        sel = ", ".join(f"count(NULLIF(CAST({_q(f)} AS VARCHAR), ''))" for f in batch)
        for row in con.execute(f"SELECT EventID, {sel} FROM events WHERE {sysmon_only} GROUP BY 1").fetchall():
            present = {f for f, n in zip(batch, row[1:]) if n}
            p.fields_by_eid[row[0]] |= present | {"EventID"}
            p.all_fields |= present
    lo, hi = con.execute("SELECT min(TimeCreated), max(TimeCreated) FROM events").fetchone()
    p.start, p.end = (lo.replace(tzinfo=timezone.utc) if lo else None), (hi.replace(tzinfo=timezone.utc) if hi else None)
    return p


def _rids(lake: Lake, wheres: list[str]) -> list[set[int]]:
    """One vectorised scan for a batch of rules: returns, per rule, the ids of rows its SQL matched.
    Only (_rid, booleans) leave DuckDB - never the wide rows."""
    cols = ", ".join(f"({w}) AS m{i}" for i, w in enumerate(wheres))
    any_ = " OR ".join(f"({w})" for w in wheres)
    out = [set() for _ in wheres]
    for row in lake.con.execute(f"SELECT _rid, {cols} FROM scan WHERE {any_}").fetchall():
        for i, hit in enumerate(row[1:]):
            if hit:
                out[i].add(row[0])
    return out


def lake_hits(rules: list[Rule], lake: Lake, verbose: bool = False, batch: int = 100) -> tuple[dict[str, list[dict]], dict]:
    """Signature matching over the lake -> {rule id: matching events} (thresholds are applied by the caller).

    Phase 1: rules compiled to SQL are evaluated ~100 per scan, returning only row ids.
    Phase 2: the matched rows are fetched once, then every rule's hits are re-checked by the exact
    Python matcher.
    """
    stats = {"sql_rules": 0, "fallback_rules": 0, "skipped_rules": 0, "rows_returned": 0}
    sigs = [r for r in rules if r.kind == "signature"]
    present = {e for (e,) in lake.con.execute("SELECT DISTINCT EventID FROM events").fetchall()}
    channels = ({c for (c,) in lake.con.execute("SELECT DISTINCT lower(COALESCE(Channel, '')) FROM events").fetchall()}
                if "Channel" in lake.columns else None)
    compiled, fallback = [], []
    stats["pruned_rules"] = 0
    for rule in sigs:
        try:
            w = compile_where(rule, lake.columns, present, channels)
        except SqlUnsupported:
            fallback.append(rule)
            continue
        if w == "FALSE":
            stats["pruned_rules"] += 1  # none of its event types exist here: costs nothing
            continue
        compiled.append((rule, w))

    if "_rid" not in lake.columns:
        raise SystemExit(f"[x] {lake.path} was built by an older ChainHunter (no _rid column). Rebuild it: "
                         f"python -m chainhunter lake <logs> -o {lake.path}")
    # Homogeneous batches: group rules by the event types they read. The lake is sorted by EventID, so a batch
    # that only touches (say) EventID 1 lets DuckDB skip every row group whose min/max excludes it.
    def eid_key(item):
        e = candidate_eids(item[0])
        e = sorted(e & present) if e is not None else None
        return (e is None, e or [])
    compiled.sort(key=eid_key)
    matched: dict[str, set[int]] = {}
    for i in range(0, len(compiled), batch):
        chunk = compiled[i:i + batch]
        try:
            for (rule, _), ids in zip(chunk, _rids(lake, [w for _, w in chunk])):
                matched[rule.id] = ids
        except Exception:  # one rule DuckDB rejects (e.g. an RE2-incompatible regex): isolate it
            for rule, w in chunk:
                try:
                    matched[rule.id] = _rids(lake, [w])[0]
                except Exception:
                    fallback.append(rule)
    stats["sql_rules"] = len(matched)

    rows_by_rid: dict[int, dict] = {}
    all_ids = sorted(set().union(*matched.values())) if matched else []
    if all_ids:
        # projection: only the fields the *matched* rules read, plus what correlation/reports use.
        # A keyword rule (needs every value) that matched forces a full-width fetch.
        # A matched keyword rule (needs every value to re-check) gets full-width rows for *its* matches only;
        # everything else is fetched with just the columns the matched rules read.
        by_id = {r.id: r for r, _ in compiled}
        need: set[str] = set(CORE_FIELDS)
        wide_ids: set[int] = set()
        for rid, ids in matched.items():
            if ids:
                f = rule_fields(by_id[rid])
                if f is None:
                    wide_ids |= ids
                else:
                    need |= f
        narrow_ids = [i for i in all_ids if i not in wide_ids]
        stats["fetched_columns"] = len(lake.select_list(need).split(","))
        stats["wide_rows"] = len(wide_ids)
        for ids, cols in ((narrow_ids, lake.select_list(need)), (sorted(wide_ids), "*")):
            if not ids:
                continue
            lake.con.execute("CREATE OR REPLACE TEMP TABLE _hit AS SELECT unnest(?::BIGINT[]) AS _rid", [ids])
            cur = lake.con.execute(f"SELECT {cols} FROM events WHERE _rid IN (SELECT _rid FROM _hit)")
            names = [d[0] for d in cur.description]
            rid_col = names.index("_rid")
            for row in cur.fetchall():
                rows_by_rid[row[rid_col]] = lake._event(names, row)
    stats["rows_returned"] = len(rows_by_rid)

    eid_cache: dict[tuple, list[dict]] = {}
    work = [(rule, sorted((rows_by_rid[i] for i in matched[rule.id] if i in rows_by_rid), key=lambda e: e["TimeCreated"]))
            for rule, _ in compiled if rule.id in matched]
    for rule in fallback:
        eids = candidate_eids(rule)
        if eids is not None:
            eids &= present
            if not eids:
                stats["pruned_rules"] += 1
                continue
        if eids is None:  # would need a full scan in Python: refuse loudly rather than silently thrash
            stats["skipped_rules"] += 1
            if verbose:
                print(f"[!] lake: skipped '{rule.title}' (not expressible in SQL; would need a full Python scan)",
                      file=sys.stderr)
            continue
        key = tuple(sorted(eids))
        if key not in eid_cache:
            f = rule_fields(rule)
            eid_cache[key] = lake.events_for_eids(eids, None if f is None else f | CORE_FIELDS)
        work.append((rule, eid_cache[key]))
        stats["fallback_rules"] += 1

    hits_by_rule: dict[str, list[dict]] = {}
    for rule, rows in work:
        hits = [ev for ev in rows if rule_matches(rule, ev)]
        if hits:
            hits_by_rule[rule.id] = hits
    return hits_by_rule, stats


def _detections(rules: list[Rule], hits_by_rule: dict[str, list[dict]]) -> list[Detection]:
    """Hits -> detections. Thresholds run here, on the merged hits, so a burst split across files still counts."""
    detections: list[Detection] = []
    for rule in rules:
        hits = sorted(hits_by_rule.get(rule.id, ()), key=lambda e: e["TimeCreated"])
        if not hits:
            continue
        thr = rule.meta.get("threshold")
        detections.extend(apply_threshold(rule, hits, thr) if thr else (build_detection(rule, [h]) for h in hits))
    detections.sort(key=lambda d: d.time)
    return detections


def run_lake(rules: list[Rule], lake: Lake, verbose: bool = False, batch: int = 100) -> tuple[list[Detection], dict]:
    hits, stats = lake_hits(rules, lake, verbose, batch)
    return _detections(rules, hits), stats


def _worker(args):
    """One process: its own DuckDB over a slice of the lake's files, plus the Python re-check for that slice."""
    rules, path, files, threads, verbose = args
    return lake_hits(rules, Lake(path, files, threads), verbose)


def run_lake_parallel(rules: list[Rule], path: Path, workers: int, verbose: bool = False) -> tuple[list[Detection], dict]:
    """Fan the lake's files out to worker processes and merge their hits before thresholds/correlation.
    Each worker gets cpu_count // workers DuckDB threads so processes don't oversubscribe the CPU."""
    import os
    from concurrent.futures import ProcessPoolExecutor
    files = sorted(path.glob("events-*.parquet"))
    if not files:
        raise NoEventsError(f"[x] no lake at {path}")
    workers = max(1, min(workers, len(files)))
    if workers == 1:
        return run_lake(rules, Lake(path), verbose)
    slices = [files[i::workers] for i in range(workers)]
    threads = max(1, (os.cpu_count() or workers) // workers)
    merged: dict[str, list[dict]] = {}
    stats: dict = {"workers": workers}
    with ProcessPoolExecutor(max_workers=workers) as pool:
        for hits, st in pool.map(_worker, [(rules, path, s, threads, verbose) for s in slices]):
            for rid, evs in hits.items():
                merged.setdefault(rid, []).extend(evs)
            for k, v in st.items():
                if isinstance(v, int):
                    stats[k] = stats.get(k, 0) + v if k == "rows_returned" else max(stats.get(k, 0), v)
    return _detections(rules, merged), stats
