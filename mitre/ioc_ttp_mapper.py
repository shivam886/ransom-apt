# mitre/ioc_ttp_mapper.py
"""
Dual-path IOC → MITRE TTP mapper

Primary:  IOC.family / IOC.source / IOC.vendor / IOC.campaign  → MITRE software → techniques (via relationships.json)
Fallback: Heuristics by IOC type (domain/ip/registry/…)
Optional: Attach CIA scores from attack_patterns_cia.json

Input  : data/samples/iocs_merged.json   (array of {type,value,source?,family?,...})
MITRE  : data/mitre_cti/processed        (attack_patterns.json, relationships.json, software.json)
Output : data/mapped/ioc_ttp_mapped.json
"""

from __future__ import annotations
import json
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Any
from difflib import get_close_matches
import re

# ----------------------------
# Heuristic IOC → TTP rules (fallbacks; tune as needed)
# ----------------------------
HEURISTIC_MAP: Dict[str, List[Tuple[str, float]]] = {
    # Network infra / C2 / staging
    "ip":       [("T1071.001", 0.6), ("T1105", 0.45)],   # Web Prot., Ingress Tool Transfer
    "ipv4":     [("T1071.001", 0.6), ("T1105", 0.45)],
    "ipv6":     [("T1071.001", 0.6), ("T1105", 0.45)],
    "domain":   [("T1071.004", 0.6), ("T1583.001", 0.45)],  # DNS, Acquire Infrastructure: Domains
    "url":      [("T1071.001", 0.6), ("T1105", 0.45)],
    # Delivery / phishing
    "email":    [("T1566", 0.7)],
    # Filesystem / execution
    "filepath": [("T1059", 0.6), ("T1105", 0.45)],
    "file_path":[("T1059", 0.6), ("T1105", 0.45)],
    # Registry
    "registry":     [("T1112", 0.6), ("T1012", 0.45)],   # Modify / Query Registry
    "registry_key": [("T1112", 0.6), ("T1012", 0.45)],
    # Process / service (very coarse)
    "process": [("T1059", 0.6), ("T1569.002", 0.45)],    # Command Exec / Service Exec
    "service": [("T1569.002", 0.7)],
    # Hashes (no TTP without context)
    "md5": [], "sha1": [], "sha256": [], "hash": []
}

# Lightweight type inference in case `type` is missing/messy
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$")
URL_RE  = re.compile(r"^https?://", re.I)
DOMAIN_RE = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
REG_RE  = re.compile(r"^(HKLM|HKCU|HKEY_|Software\\|SYSTEM\\|SOFTWARE\\)", re.I)
FILE_RE = re.compile(r"[\\/].+\.[A-Za-z0-9]{1,6}$")

# ----------------------------
# Utilities
# ----------------------------
def load_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(obj: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)

def norm(s: str) -> str:
    return (s or "").strip()

def infer_type(value: str) -> str:
    v = norm(value)
    if IPV4_RE.match(v): return "ip"
    if URL_RE.match(v): return "url"
    if DOMAIN_RE.match(v): return "domain"
    if REG_RE.match(v): return "registry"
    if FILE_RE.match(v): return "filepath"
    return ""

# ----------------------------
# MITRE indexes
# ----------------------------
def index_attack_patterns(attack_patterns: List[Dict]) -> Tuple[Dict[str, Dict], Dict[str, str]]:
    """Return: technique_by_id (external_id -> AP obj), stix_to_external (stix_id -> external_id)."""
    technique_by_id: Dict[str, Dict] = {}
    stix_to_external: Dict[str, str] = {}
    for ap in attack_patterns:
        ext_id = ""
        for ref in ap.get("external_references", []):
            if ref.get("source_name", "").startswith("mitre"):
                if ref.get("external_id"):
                    ext_id = ref["external_id"]
                    break
        if not ext_id:
            continue
        technique_by_id[ext_id] = ap
        stix_to_external[ap["id"]] = ext_id
    return technique_by_id, stix_to_external

def index_software(software: List[Dict]) -> Tuple[Dict[str, Dict], Dict[str, str]]:
    """Return: software_by_id (stix_id -> sw obj), name_to_id (lowered name/alias -> stix_id)."""
    software_by_id: Dict[str, Dict] = {}
    name_to_id: Dict[str, str] = {}
    for sw in software:
        sid = sw["id"]
        software_by_id[sid] = sw
        names = [sw.get("name", "")]
        names += sw.get("x_mitre_aliases", [])
        for n in names:
            if n:
                name_to_id[n.lower()] = sid
    return software_by_id, name_to_id

def build_software_to_ttps(relationships: List[Dict], stix_to_external: Dict[str, str]) -> Dict[str, List[str]]:
    """Map software STIX id -> list of technique external_ids via 'uses' relationships."""
    sw_to_ttps: Dict[str, List[str]] = {}
    for rel in relationships:
        if rel.get("relationship_type") != "uses":
            continue
        src = rel.get("source_ref", "")
        tgt = rel.get("target_ref", "")
        if not (src and tgt):
            continue
        if (src.startswith("malware--") or src.startswith("tool--")) and tgt in stix_to_external:
            tid = stix_to_external[tgt]
            sw_to_ttps.setdefault(src, []).append(tid)
    return sw_to_ttps

def best_software_match(name: str, name_to_id: Dict[str, str]) -> str:
    if not name: return ""
    direct = name_to_id.get(name.lower())
    if direct:
        return direct
    # fuzzy for minor variant names
    keys = list(name_to_id.keys())
    matches = get_close_matches(name.lower(), keys, n=1, cutoff=0.86)
    return name_to_id[matches[0]] if matches else ""

# ----------------------------
# Primary path: IOC via software
# ----------------------------
PRIORITY_KEYS = ("family", "source", "vendor", "campaign", "malware", "tool")

def map_ioc_via_software(
    ioc: Dict, name_to_id: Dict[str, str],
    sw_to_ttps: Dict[str, List[str]],
    technique_by_id: Dict[str, Dict]
) -> List[Dict]:
    names = [norm(ioc.get(k)) for k in PRIORITY_KEYS if norm(ioc.get(k))]
    results: List[Dict] = []
    for n in names:
        sw_id = best_software_match(n, name_to_id)
        if not sw_id:
            continue
        for tid in sorted(set(sw_to_ttps.get(sw_id, []))):
            ap = technique_by_id.get(tid, {})
            results.append({
                "technique_id": tid,
                "technique": ap.get("name", ""),
                "via": "software_map",
                "confidence": 0.92
            })
    return results

# ----------------------------
# Fallback path: IOC via heuristics
# ----------------------------
def map_ioc_via_heuristics(ioc: Dict, technique_by_id: Dict[str, Dict]) -> List[Dict]:
    ioc_type = norm(ioc.get("type")).lower()
    if not ioc_type:
        ioc_type = infer_type(ioc.get("value", ""))
    matches: List[Dict] = []
    for tid, conf in HEURISTIC_MAP.get(ioc_type, []):
        ap = technique_by_id.get(tid, {})
        if ap:
            matches.append({
                "technique_id": tid,
                "technique": ap.get("name", ""),
                "via": "heuristic",
                "confidence": conf
            })
    return matches

# ----------------------------
# Merge + optional CIA enrichment
# ----------------------------
def attach_cia(matches: List[Dict], cia_by_tid: Dict[str, Dict]) -> None:
    for m in matches:
        if m["technique_id"] in cia_by_tid:
            m["cia_score"] = cia_by_tid[m["technique_id"]]

def merge_matches(m1: List[Dict], m2: List[Dict]) -> List[Dict]:
    by_tid: Dict[str, Dict] = {}
    for m in (m1 + m2):
        tid = m["technique_id"]
        # prefer higher confidence and software_map over heuristic if equal
        if tid not in by_tid:
            by_tid[tid] = m
        else:
            prev = by_tid[tid]
            if m["confidence"] > prev["confidence"] or (
                m["confidence"] == prev["confidence"] and m["via"] == "software_map"
            ):
                by_tid[tid] = m
    return list(by_tid.values())

# ----------------------------
# Main
# ----------------------------
def map_iocs_to_ttps(iocs_path: Path, mitre_dir: Path, out_path: Path, cia_path: Path | None, min_conf: float):
    print(f"📥 IOCs: {iocs_path}")
    iocs = load_json(iocs_path)

    print(f"📥 MITRE: {mitre_dir}")
    attack_patterns = load_json(mitre_dir / "attack_patterns.json")
    relationships   = load_json(mitre_dir / "relationships.json")
    software        = load_json(mitre_dir / "software.json")

    technique_by_id, stix_to_external = index_attack_patterns(attack_patterns)
    _, name_to_id = index_software(software)
    sw_to_ttps = build_software_to_ttps(relationships, stix_to_external)

    cia_by_tid: Dict[str, Dict] = {}
    if cia_path and cia_path.exists():
        print(f"📥 CIA: {cia_path}")
        cia_list = load_json(cia_path)
        cia_by_tid = {row["id"]: row.get("cia_score", {}) for row in cia_list}

    output: List[Dict] = []
    matched_count = 0

    for i, ioc in enumerate(iocs, 1):
        via_sw = map_ioc_via_software(ioc, name_to_id, sw_to_ttps, technique_by_id)
        via_h  = map_ioc_via_heuristics(ioc, technique_by_id)
        merged = [m for m in merge_matches(via_sw, via_h) if m["confidence"] >= min_conf]
        if cia_by_tid:
            attach_cia(merged, cia_by_tid)
        if merged:
            matched_count += 1
            output.append({"ioc": ioc, "matches": merged})

        if i % 200 == 0:
            print(f"  … processed {i} IOCs")

    save_json(output, out_path)
    print(f"✅ Saved {len(output)} mapped IOCs (with matches: {matched_count}) → {out_path}")

# ----------------------------
# CLI
# ----------------------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Dual-path IOC → TTP mapper (software first, heuristics fallback).")
    ap.add_argument("--iocs", required=True, help="Path to processed IOC JSON (array)")
    ap.add_argument("--mitre", required=True, help="Folder with processed MITRE CTI JSONs")
    ap.add_argument("--out", required=True, help="Output JSON path")
    ap.add_argument("--cia", default="", help="(Optional) attack_patterns_cia.json for CIA enrichment")
    ap.add_argument("--min-conf", type=float, default=0.45, help="Minimum confidence to keep a mapping (default 0.45)")
    args = ap.parse_args()

    iocs_path = Path(args.iocs)
    mitre_dir = Path(args.mitre)
    out_path  = Path(args.out)
    cia_path  = Path(args.cia) if args.cia else None

    map_iocs_to_ttps(iocs_path, mitre_dir, out_path, cia_path, args.min_conf)
