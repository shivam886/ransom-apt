# File: preprocess/feature_extractor.py
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import json
from mitre.ttp_mapper import load_attack_patterns, match_ttp
from mitre.cia_scorer import score_cia
from pathlib import Path
from typing import List, Dict


def extract_features_from_logs(logs: List[Dict]) -> List[Dict]:
    patterns = load_attack_patterns()
    enriched = []

    for log in logs:
        ttp_matches = match_ttp(log, patterns)
        cia_impact = score_cia(json.dumps(log))

        enriched.append({
            "log": log,
            "ttp_matches": ttp_matches,
            "cia_score": cia_impact
        })

    return enriched


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Extract TTPs and CIA scores from ECS logs")
    parser.add_argument("--input", required=True, help="Path to ECS log file (JSON)")
    parser.add_argument("--output", required=True, help="Path to save extracted features")
    args = parser.parse_args()

    with open(args.input, "r") as f:
        logs = json.load(f)

    results = extract_features_from_logs(logs)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    print(f"✅ Features extracted for {len(results)} logs and saved to {args.output}")


if __name__ == "__main__":
    main()
