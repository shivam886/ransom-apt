# graph/weight_assigner.py

import networkx as nx
import json
from typing import Dict

# === CIA impact weights ===
CIA_WEIGHTS = {
    "confidentiality": 1.5,
    "integrity": 1.2,
    "availability": 1.0,
}

# === Tactic priority scores (can be tuned) ===
TACTIC_PRIORITY = {
    "initial-access": 1,
    "execution": 2,
    "persistence": 3,
    "privilege-escalation": 4,
    "defense-evasion": 5,
    "credential-access": 6,
    "discovery": 7,
    "lateral-movement": 8,
    "collection": 9,
    "command-and-control": 10,
    "exfiltration": 11,
    "impact": 12,
}


def calculate_weight(cia: Dict, tactic: str) -> float:
    """Combine CIA impact scores with tactic priority to assign edge weight."""
    cia_score = sum(cia[cat] * CIA_WEIGHTS[cat] for cat in CIA_WEIGHTS)
    tactic_score = TACTIC_PRIORITY.get(tactic.lower(), 10)
    weight = cia_score * (1 + tactic_score / 10)
    return round(weight, 2)


def assign_weights_to_gml(graph_path: str, cia_path: str, output_path: str):
    print(f"📥 Loading graph from {graph_path}")
    G = nx.read_gml(graph_path)

    print(f"📥 Loading CIA scores from {cia_path}")
    with open(cia_path, "r") as f:
        cia_data = json.load(f)

    # Build a lookup: technique_id → CIA score
    cia_lookup = {item["id"]: item["cia_score"] for item in cia_data}

    for u, v, data in G.edges(data=True):
        technique_id = data.get("technique_id")
        tactic = data.get("tactic", "")

        cia_score = cia_lookup.get(technique_id, {
            "confidentiality": 0,
            "integrity": 0,
            "availability": 0
        })

        weight = calculate_weight(cia_score, tactic)
        data["weight"] = weight

    print(f"💾 Saving weighted graph to {output_path}")
    nx.write_gml(G, output_path)
    print("✅ Graph weighting complete.")


# === CLI ===
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Assign CIA-based weights to attack graph edges.")
    parser.add_argument("--graph", required=True, help="Path to attack_graph.gml")
    parser.add_argument("--cia", required=True, help="Path to attack_patterns_cia.json")
    parser.add_argument("--output", required=True, help="Path to save weighted GML")

    args = parser.parse_args()

    assign_weights_to_gml(args.graph, args.cia, args.output)
