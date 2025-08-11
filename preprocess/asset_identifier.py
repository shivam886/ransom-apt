# preprocess/asset_identifier.py

import json
from pathlib import Path
from typing import List, Dict

ASSET_KEYS = {
    "ip": ["source.ip", "destination.ip", "client.ip", "server.ip"],
    "user": ["user.name", "user.email", "user.domain", "user.id"],
    "host": ["host.name", "host.id", "orchestrator.name"],
    "file": ["file.name", "file.path", "file.hash.sha256"],
    "process": ["process.name", "process.command_line"],
    "service": ["service.name", "service.type"]
}


def extract_assets(log: Dict) -> Dict[str, List[str]]:
    """Extract key assets from a single ECS log."""
    assets = {k: [] for k in ASSET_KEYS}

    def deep_get(obj, key_path):
    # First try flat key
        if key_path in obj:
            return obj[key_path] if isinstance(obj[key_path], str) else None

    # Then try nested access
        keys = key_path.split(".")
        for key in keys:
            if isinstance(obj, dict) and key in obj:
                obj = obj[key]
            else:
                return None
        return obj if isinstance(obj, str) else None


    for asset_type, keys in ASSET_KEYS.items():
        for key in keys:
            value = deep_get(log, key)
            if value and value not in assets[asset_type]:
                assets[asset_type].append(value)

    return {k: v for k, v in assets.items() if v}  # Remove empty lists


def enrich_logs_with_assets(logs: List[Dict]) -> List[Dict]:
    """Enrich each log with extracted asset fields under `log["assets"]`."""
    enriched = []
    for log in logs:
        log["assets"] = extract_assets(log)
        enriched.append(log)
    return enriched


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Extract and enrich ECS logs with asset identifiers")
    parser.add_argument("--input", type=str, required=True, help="Path to ECS JSON log file")
    parser.add_argument("--output", type=str, required=True, help="Path to save enriched logs")

    args = parser.parse_args()

    with open(args.input, "r") as f:
        logs = json.load(f)

    enriched = enrich_logs_with_assets(logs)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(enriched, f, indent=2)

    print(f"✅ Enriched {len(enriched)} logs with asset identifiers at: {args.output}")


if __name__ == "__main__":
    main()
