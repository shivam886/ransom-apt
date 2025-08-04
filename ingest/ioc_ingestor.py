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


# === IOC Type Detection ===
def detect_ioc_type(value):
    value = value.strip().lower()
    if re.fullmatch(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", value):
        return "ip"
    elif re.fullmatch(r"[a-f0-9]{32}", value):
        return "md5"
    elif re.fullmatch(r"[a-f0-9]{40}", value):
        return "sha1"
    elif re.fullmatch(r"[a-f0-9]{64}", value):
        return "sha256"
    elif re.fullmatch(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}", value):
        return "domain"
    elif value.startswith("http"):
        return "url"
    else:
        return "unknown"

# === Normalize IOC ===
def normalize_ioc(value, source):
    if isinstance(value, list):
        value = ",".join(map(str, value))  # Flatten list into comma-separated string
    elif not isinstance(value, str):
        value = str(value)
        
    return {
        "value": value.strip(),
        "type": detect_ioc_type(value),
        "source": source,
        "valid": bool(value.strip()),
    }

# === Deduplication Based on IOC Value + Type ===
def deduplicate_iocs(iocs):
    seen = set()
    unique = []
    for ioc in iocs:
        key = (ioc["value"], ioc["type"])
        if key not in seen:
            seen.add(key)
            unique.append(ioc)
    return unique

# === Parsers ===
def ingest_csv(file_path):
    iocs = []
    with open(file_path, newline='', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            for key, val in row.items():
                if val:
                    ioc = normalize_ioc(val, source=file_path.name)
                    if ioc:
                        iocs.append(ioc)
    return iocs

def ingest_txt(file_path):
    iocs = []
    with open(file_path, encoding='utf-8', errors='replace') as f:
        for line in f:
            val = line.strip()
            if val:
                iocs.append(normalize_ioc(val, source=file_path.name))
    return iocs

def ingest_json(file_path):
    iocs = []
    with open(file_path, encoding='utf-8', errors='replace') as f:
        content = json.load(f)
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict):
                    for val in item.values():
                        if isinstance(val, str):
                            iocs.append(normalize_ioc(val, source=file_path.name))
                elif isinstance(item, str):
                    iocs.append(normalize_ioc(item, source=file_path.name))
    return iocs

# === Master Loader ===
def ingest_all_ioc_files(folder):
    iocs = []
    for file_path in Path(folder).glob("*"):
        if file_path.suffix == ".csv":
            iocs.extend(ingest_csv(file_path))
        elif file_path.suffix == ".json":
            iocs.extend(ingest_json(file_path))
        elif file_path.suffix == ".txt":
            iocs.extend(ingest_txt(file_path))
        else:
            print(f"⚠️ Skipping unsupported file: {file_path.name}")
    return iocs

# === Save Output ===
def save_iocs(iocs, output_path):
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(iocs, f, indent=2)
    print(f"✅ Saved {len(iocs)} unique IOCs to {output_path}")

# === CLI Entry ===
def main():
    parser = argparse.ArgumentParser(description="Dynamic IOC Ingestor with Deduplication")
    parser.add_argument("--folder", required=True, help="Path to IOC input folder")
    parser.add_argument("--output", required=True, help="Path to output JSON file")
    args = parser.parse_args()

    print(f"🔍 Scanning folder: {args.folder}")
    all_iocs = ingest_all_ioc_files(args.folder)
    print(f"🧱 Total IOCs collected: {len(all_iocs)}")

    unique_iocs = deduplicate_iocs(all_iocs)
    print(f"✅ Unique after deduplication: {len(unique_iocs)}")

    save_iocs(unique_iocs, args.output)

if __name__ == "__main__":
    main()

