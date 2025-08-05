import json
from pathlib import Path
from typing import Dict, List


# Basic keyword mappings to CIA categories
CIA_KEYWORDS = {
    "confidentiality": [
        "steal", "leak", "exfiltrate", "access sensitive", "dump", "credential", "keylogging", "sniff"
    ],
    "integrity": [
        "modify", "tamper", "replace", "inject", "hook", "alter", "unauthorized change"
    ],
    "availability": [
        "delete", "destroy", "encrypt", "lock", "deny", "ransom", "shutdown", "dos", "disable"
    ]
}


def score_cia(description: str) -> Dict[str, int]:
    """Score the TTP description based on CIA impact."""
    score = {"confidentiality": 0, "integrity": 0, "availability": 0}
    desc = description.lower()

    for cia, keywords in CIA_KEYWORDS.items():
        for keyword in keywords:
            if keyword in desc:
                score[cia] += 1

    return score


def map_cia_to_ttps(attack_patterns: List[Dict]) -> List[Dict]:
    """Attach CIA scores to MITRE ATT&CK patterns."""
    scored_ttps = []

    for ap in attack_patterns:
        desc = ap.get("description", "") + " " + ap.get("x_mitre_detection", "")
        score = score_cia(desc)
        scored_ttps.append({
            "id": ap.get("external_references", [{}])[0].get("external_id", ""),
            "name": ap.get("name", ""),
            "description": ap.get("description", ""),
            "cia_score": score
        })

    return scored_ttps


def load_attack_patterns(path: str) -> List[Dict]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_scored_ttps(scored: List[Dict], output_path: str):
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(scored, f, indent=2)
    print(f"✅ Saved CIA-scored TTPs to {output_path}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Score MITRE ATT&CK TTPs using CIA triad.")
    parser.add_argument("--input", type=str, default="data/mitre/processed/attack_patterns.json", help="Path to attack_patterns.json")
    parser.add_argument("--output", type=str, default="data/mitre/processed/attack_patterns_cia.json", help="Output path for scored TTPs")

    args = parser.parse_args()

    attack_patterns = load_attack_patterns(args.input)
    scored = map_cia_to_ttps(attack_patterns)
    save_scored_ttps(scored, args.output)
