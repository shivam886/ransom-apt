# ingest/ioc_ingestor.py
import argparse
import csv
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List

# -------- Strict validators --------
MD5_RE    = re.compile(r'^[A-Fa-f0-9]{32}$')
SHA1_RE   = re.compile(r'^[A-Fa-f0-9]{40}$')
SHA256_RE = re.compile(r'^[A-Fa-f0-9]{64}$')
IPV4_RE   = re.compile(r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$')
URL_RE    = re.compile(r'^(?:https?://)[^\s]+$', re.I)
# Domain: total ≤253, each label 1–63, no leading/trailing hyphen, no underscores
DOMAIN_RE = re.compile(
    r'^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$'
)

# Columns we do NOT scan by default
DEFAULT_IGNORE_COLS = {'name', 'type', 'first_seen', 'timestamp', 'date'}

# Columns we DO scan if present (case-insensitive). If you provide --whitelist, we use that instead.
DEFAULT_SCAN_COLS = {
    'hash', 'md5', 'sha1', 'sha256',
    'ip', 'ipv4', 'domain', 'url',
    'ioc', 'indicator', 'artifact', 'value'
}

HEX_BLOB_RE = re.compile(r'\b([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b')

def classify_hash(s: str) -> str:
    if MD5_RE.fullmatch(s): return 'md5'
    if SHA1_RE.fullmatch(s): return 'sha1'
    if SHA256_RE.fullmatch(s): return 'sha256'
    return ''

def detect_ioc(value: str):
    """Return (type, normalized_value) or ('','') if not IOC."""
    if not value: return ('','')
    v = value.strip()

    # Hash first (unambiguous)
    h = classify_hash(v)
    if h: return (h, v.lower())

    # IP
    if IPV4_RE.fullmatch(v): return ('ip', v)

    # URL
    if URL_RE.fullmatch(v): return ('url', v)

    # Domain (strict) — rejects 64-hex labels like '....sample'
    if DOMAIN_RE.fullmatch(v): return ('domain', v.lower())

    return ('','')

def read_csv_rows(path: Path) -> Iterable[Dict[str, str]]:
    """CSV reader with encoding + delimiter sniffing."""
    for enc in ('utf-8-sig', 'utf-8', 'latin-1'):
        try:
            with open(path, 'r', encoding=enc, newline='') as f:
                sample = f.read(4096)
                f.seek(0)
                try:
                    dialect = csv.Sniffer().sniff(sample)
                except csv.Error:
                    dialect = csv.excel
                reader = csv.DictReader(f, dialect=dialect)
                for row in reader:
                    yield { (k or '').strip(): (v.strip() if isinstance(v,str) else v)
                            for k,v in row.items() }
            return
        except UnicodeDecodeError:
            continue
    raise UnicodeDecodeError("Unable to decode CSV with utf-8/latin-1")

def parse_csv(path: Path, whitelist: List[str] | None, ignore_cols: set,
              extract_hash_from_name: bool) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    wl = {c.lower() for c in whitelist} if whitelist else None

    for row in read_csv_rows(path):
        source = path.name
        # Optionally extract hash from Name column (e.g., "<64hex>.sample")
        if extract_hash_from_name:
            for key in row.keys():
                if key and key.lower() == 'name':
                    raw = row.get(key) or ''
                    m = HEX_BLOB_RE.search(raw)
                    if m:
                        blob = m.group(1)
                        htype = classify_hash(blob)
                        if htype:
                            out.append({"value": blob.lower(), "type": htype, "source": source,
                                        "row_meta": {"column": key}})

        for key, val in row.items():
            if not key: 
                continue
            k = key.lower()
            if not isinstance(val, str):
                continue
            v = val.strip()
            if not v:
                continue

            # Skip ignored columns (prevents 'Name' misclassification)
            if k in ignore_cols:
                continue

            # If whitelist provided, only scan those columns
            if wl is not None and k not in wl:
                continue

            # Else, only scan known IOC-relevant columns
            if wl is None and k not in DEFAULT_SCAN_COLS:
                continue

            # Hash columns get classified strictly
            if k in ('hash', 'md5', 'sha1', 'sha256'):
                h = classify_hash(v)
                if h:
                    out.append({"value": v.lower(), "type": h, "source": source,
                                "row_meta": {"column": key}})
                continue

            # Known IOC columns
            if k in ('ip', 'ipv4', 'domain', 'url', 'ioc', 'indicator', 'artifact', 'value'):
                ioc_type, ioc_val = detect_ioc(v)
                if ioc_type:
                    out.append({"value": ioc_val, "type": ioc_type, "source": source,
                                "row_meta": {"column": key}})

    return out

def parse_txt(path: Path) -> List[Dict[str, Any]]:
    out = []
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            v = line.strip()
            if not v:
                continue
            t, norm = detect_ioc(v)
            if t:
                out.append({"value": norm, "type": t, "source": path.name})
    return out

def parse_json_any(path: Path) -> List[Dict[str, Any]]:
    """Supports JSON array or JSON Lines (.jsonl/.ndjson)."""
    out = []
    # JSONL if extension suggests it, else try to parse as array then fallback to lines
    if path.suffix.lower() in ('.jsonl', '.ndjson'):
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                out.extend(_extract_iocs_from_obj(obj, path.name))
        return out

    # Try array/object JSON
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            data = json.load(f)
        out.extend(_extract_iocs_from_obj(data, path.name))
        return out
    except json.JSONDecodeError:
        # Fallback to line-by-line
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                out.extend(_extract_iocs_from_obj(obj, path.name))
        return out

def _extract_iocs_from_obj(obj: Any, source_name: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if isinstance(obj, dict):
        # Only scan common IOC fields; do not sweep everything
        for key in list(obj.keys()):
            k = key.lower()
            if k in DEFAULT_IGNORE_COLS:
                continue
            if k in DEFAULT_SCAN_COLS:
                v = obj.get(key)
                if isinstance(v, str):
                    t, norm = detect_ioc(v.strip())
                    if t:
                        out.append({"value": norm, "type": t, "source": source_name,
                                    "row_meta": {"column": key}})
    elif isinstance(obj, list):
        for item in obj:
            out.extend(_extract_iocs_from_obj(item, source_name))
    elif isinstance(obj, str):
        t, norm = detect_ioc(obj.strip())
        if t:
            out.append({"value": norm, "type": t, "source": source_name})
    return out

def dedup(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out = []
    for r in records:
        key = (r.get('type'), r.get('value'))
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out

def ingest_folder(folder: Path, whitelist: List[str] | None,
                  ignore_cols: List[str], extract_hash_from_name: bool) -> List[Dict[str, Any]]:
    all_recs: List[Dict[str, Any]] = []
    ignore_set = {c.lower() for c in (ignore_cols or [])}
    files = list(folder.rglob('*'))
    if not files:
        print(f'⚠️ No files found in {folder}')
    for p in files:
        if not p.is_file():
            continue
        ext = p.suffix.lower()
        try:
            if ext in ('.csv',):
                all_recs.extend(parse_csv(p, whitelist, ignore_set, extract_hash_from_name))
            elif ext in ('.json', '.jsonl', '.ndjson'):
                all_recs.extend(parse_json_any(p))
            elif ext in ('.txt',):
                all_recs.extend(parse_txt(p))
            else:
                # skip other extensions
                continue
        except Exception as e:
            print(f'⚠️ Skipping {p.name}: {e}')
    return dedup(all_recs)

def save_json_array(data: List[Dict[str, Any]], out_path: Path):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    print(f'✅ Saved {len(data)} unique IOCs → {out_path}')

def main():
    ap = argparse.ArgumentParser(description='Robust IOC ingestor (recursive, strict validators, safe columns).')
    ap.add_argument('--folder', required=True, help='Folder containing IOC files (recursive)')
    ap.add_argument('--output', required=True, help='Output JSON path')
    ap.add_argument('--whitelist', nargs='*', default=None,
                    help='Only scan these CSV column names (case-insensitive). Example: --whitelist Hash MD5 Domain')
    ap.add_argument('--ignore', nargs='*', default=list(DEFAULT_IGNORE_COLS),
                    help='Ignore these CSV column names (case-insensitive). Default: Name Type First_Seen Timestamp Date')
    ap.add_argument('--extract-hash-from-name', action='store_true',
                    help='Attempt to extract 32/40/64-hex from Name column (e.g., strip .sample)')
    args = ap.parse_args()

    folder = Path(args.folder)
    out    = Path(args.output)

    recs = ingest_folder(folder, args.whitelist, args.ignore, args.extract_hash_from_name)
    save_json_array(recs, out)

if __name__ == '__main__':
    main()

