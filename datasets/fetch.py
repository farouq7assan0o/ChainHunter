"""Download the public attack datasets listed in manifest.yml into datasets/cache/ (gitignored).

    python datasets/fetch.py            # download missing files, verify sha256 pins
    python datasets/fetch.py --pin      # record sha256 of downloaded files into the manifest

Samples are fetched, not vendored: EVTX-ATTACK-SAMPLES is GPL-3.0, OTRF Security-Datasets is MIT.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
CACHE = HERE / "cache"
MANIFEST = HERE / "manifest.yml"
SOURCES = {
    "evtx-attack-samples": "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/",
    "otrf": "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/",
}


def local_path(entry: dict) -> Path:
    return CACHE / entry["source"] / Path(entry["path"]).name


def data_files(entry: dict) -> list[Path]:
    """Files ChainHunter should ingest for this entry (zips are extracted next to themselves)."""
    p = local_path(entry)
    if p.suffix.lower() == ".zip":  # OTRF uses both .zip and .Zip
        return sorted(f for f in p.parent.glob(p.stem + "*") if f.suffix.lower() in {".json", ".jsonl"})
    return [p]


def extracted_name(zip_path: Path, member: str) -> Path:
    """Members with generic names (e.g. WindowsEvents.json) get the zip's name as prefix, so datasets can't collide."""
    name = Path(member).name
    return zip_path.parent / (name if name.startswith(zip_path.stem) else f"{zip_path.stem}__{name}")


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pin", action="store_true", help="write sha256 pins into manifest.yml")
    ap.add_argument("--skip-campaigns", action="store_true",
                    help="only the per-technique benchmark samples (CI: skips the 385 MB APT29 campaign)")
    a = ap.parse_args()
    doc = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    bad = 0
    for entry in doc["samples"]:
        if a.skip_campaigns and entry.get("campaign"):
            continue
        dest = local_path(entry)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.exists():
            url = SOURCES[entry["source"]] + urllib.parse.quote(entry["path"])
            print(f"[v] {entry['path']}")
            with urllib.request.urlopen(url, timeout=60) as r:
                dest.write_bytes(r.read())
        digest = sha256(dest)
        if a.pin:
            entry["sha256"] = digest
        elif entry.get("sha256") and entry["sha256"] != digest:
            print(f"[!] sha256 mismatch: {dest.name}", file=sys.stderr)
            bad += 1
        if dest.suffix.lower() == ".zip":
            with zipfile.ZipFile(dest) as z:
                for m in z.namelist():
                    target = extracted_name(dest, m)
                    if m.lower().endswith((".json", ".jsonl")) and not target.exists():
                        target.write_bytes(z.read(m))
    if a.pin:
        MANIFEST.write_text(yaml.safe_dump(doc, sort_keys=False, width=120), encoding="utf-8")
        print("[+] pins written")
    print(f"[+] {len(doc['samples'])} samples ready in {CACHE}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
