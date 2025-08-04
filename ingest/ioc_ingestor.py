# import csv

# def parse_custom_ioc_file(file_path):
#     iocs = []

#     with open(file_path, newline='', encoding='utf-8', errors='replace') as csvfile:
#         reader = csv.DictReader(csvfile)
#         for row in reader:
#             iocs.append({
#                 "type": row.get("Type", "").strip().lower(),
#                 "value": row.get("Hash", "").strip(),
#                 "family": row.get("Family", "").strip(),
#                 "name": row.get("Name", "").strip(),
#                 "date": row.get("First_Seen", "").strip(),
#                 "source": "uploaded_csv"
#             })

#     return iocs

import csv
import json
import re
import argparse
from pathlib import Path

# IOC Type Detection Regexes
IOC_PATTERNS = {
    "md5": re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE),
    "sha1": re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE),
    "sha256": re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE),
    "ip": re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$"),
    "domain": re.compile(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}"),
    "url": re.compile(r"^https?://[^\s]+$")
}

def detect_ioc_type(value):
    value = str(value).strip()
    for ioc_type, pattern in IOC_PATTERNS.items():
        if pattern.fullmatch(value):
            return ioc_type
    return "unknown"

def normalize_ioc(value, source):
    if isinstance(value, list):
        value = ",".join(map(str, value))
    elif not isinstance(value, str):
        value = str(value)

    value = value.strip()
    return {
        "value": value,
        "type": detect_ioc_type(value),
        "source": source
    }

def deduplicate_iocs(ioc_list):
    seen = set()
    unique = []
    for ioc in ioc_list:
        key = (ioc["value"], ioc["type"])
        if key not in seen and ioc["type"] != "unknown":
            seen.add(key)
            unique.append(ioc)
    return unique

# --- Parsers ---
def parse_csv(file_path):
    iocs = []
    with open(file_path, encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            for val in row.values():
                if val:
                    ioc = normalize_ioc(val, source=file_path.name)
                    if ioc["type"] != "unknown":
                        iocs.append(ioc)
    return iocs

def parse_txt(file_path):
    iocs = []
    with open(file_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line:
                ioc = normalize_ioc(line, source=file_path.name)
                if ioc["type"] != "unknown":
                    iocs.append(ioc)
    return iocs

def parse_json(file_path):
    iocs = []
    with open(file_path, encoding="utf-8", errors="replace") as f:
        data = json.load(f)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    for val in item.values():
                        ioc = normalize_ioc(val, source=file_path.name)
                        if ioc["type"] != "unknown":
                            iocs.append(ioc)
                elif isinstance(item, str):
                    ioc = normalize_ioc(item, source=file_path.name)
                    if ioc["type"] != "unknown":
                        iocs.append(ioc)
    return iocs

# --- Master Ingestor ---
def ingest_iocs_from_folder(folder_path):
    all_iocs = []
    folder = Path(folder_path)
    for file in folder.glob("*"):
        if file.suffix == ".csv":
            all_iocs.extend(parse_csv(file))
        elif file.suffix == ".txt":
            all_iocs.extend(parse_txt(file))
        elif file.suffix == ".json":
            all_iocs.extend(parse_json(file))
        else:
            print(f"⚠️ Skipping unsupported: {file.name}")
    return deduplicate_iocs(all_iocs)

# --- Save to JSON ---
def save_iocs(iocs, output_path):
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(iocs, f, indent=2)
    print(f"✅ Saved {len(iocs)} unique IOCs to: {output_path}")

# --- CLI ---
def main():
    parser = argparse.ArgumentParser(description="Multi-Format IOC Ingestor")
    parser.add_argument("--folder", required=True, help="Folder with IOC files")
    parser.add_argument("--output", required=True, help="Path to output JSON file")
    args = parser.parse_args()

    print(f"🔍 Scanning: {args.folder}")
    iocs = ingest_iocs_from_folder(args.folder)
    print(f"✅ Found {len(iocs)} IOCs after deduplication.")
    save_iocs(iocs, args.output)

if __name__ == "__main__":
    main()
