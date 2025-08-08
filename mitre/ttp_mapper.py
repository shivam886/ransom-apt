# mitre/ttp_mapper.py

import json
from pathlib import Path
from typing import List, Dict
from mitre.mitre_loader import extract_all_from_folder

MITRE_DATA_DIR = "data/mitre_cti/processed"

# === Load MITRE patterns ===
def load_attack_patterns() -> List[Dict]:
    path = Path(MITRE_DATA_DIR) / "attack_patterns.json" 
    with open(path, "r") as f:
        return json.load(f)

# === Pattern Matching ===
def match_ttp(log: Dict, patterns: List[Dict]) -> List[Dict]:
    matches = []
    log_text = json.dumps(log).lower()

    for pattern in patterns:
        keywords = []

        # Match by name or description
        if "name" in pattern:
            keywords.append(pattern["name"].lower())
        if "description" in pattern:
            keywords.append(pattern["description"].lower())

        # Use kill_chain_phases for tactical context
        if "kill_chain_phases" in pattern:
            for phase in pattern["kill_chain_phases"]:
                if "phase_name" in phase:
                    keywords.append(phase["phase_name"].lower())

        # Use aliases or command examples if available
        if "x_mitre_aliases" in pattern:
            keywords.extend([alias.lower() for alias in pattern["x_mitre_aliases"]])

        if "x_mitre_data_sources" in pattern:
            keywords.extend([src.lower() for src in pattern["x_mitre_data_sources"]])

        # Basic keyword match
        if any(keyword in log_text for keyword in keywords):
            matches.append({
                "technique_id": pattern.get("external_references", [{}])[0].get("external_id", ""),
                "technique": pattern.get("name", ""),
                "tactic": pattern.get("kill_chain_phases", [{}])[0].get("phase_name", ""),
                "matched_keywords": [k for k in keywords if k in log_text]
            })

    return matches

# === CLI ===
def main():
    import argparse

    parser = argparse.ArgumentParser(description="Map logs to MITRE TTPs")
    parser.add_argument("--input", type=str, required=True, help="Path to ECS log file (JSON array)")
    parser.add_argument("--output", type=str, required=True, help="Path to save mapped TTPs")
    args = parser.parse_args()

    with open(args.input, "r") as f:
        logs = json.load(f)

    patterns = load_attack_patterns()
    all_matches = []

    for log in logs:
        matches = match_ttp(log, patterns)
        if matches:
            all_matches.append({
                "log": log,
                "matches": matches
            })

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(all_matches, f, indent=2)

    print(f"✅ Mapped {len(all_matches)} logs to TTPs. Output saved to {args.output}")


if __name__ == "__main__":
    main()
