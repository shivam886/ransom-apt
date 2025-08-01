from ingest.ioc_ingestor import parse_custom_ioc_file
from ingest.normalizer import normalize_ioc_list
import json

raw_iocs = parse_custom_ioc_file("data/samples/APT41_hash.csv")
normalized = normalize_ioc_list(raw_iocs)

with open("data/samples/normalized_iocs.json", "w") as f:
    json.dump(normalized, f, indent=2)

print("✅ Normalized IOCs saved to: data/samples/normalized_iocs.json")
