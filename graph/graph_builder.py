# graph/graph_builder.py

import json
import networkx as nx
from pathlib import Path
from typing import List, Dict, Tuple


def load_mitre_relationships(path: str) -> List[Dict]:
    with open(path, "r") as f:
        return json.load(f)


def load_ttp_matches(path: str) -> List[Dict]:
    with open(path, "r") as f:
        return json.load(f)


def build_attack_graph(
    relationships: List[Dict],
    matched_logs: List[Dict]
) -> nx.DiGraph:
    graph = nx.DiGraph()

    # Step 1: Add nodes from matched logs
    for entry in matched_logs:
        log = entry["log"]
        for match in entry["matches"]:
            ttp_id = match["technique_id"]
            asset = log.get("host.name") or log.get("user.name") or "unknown"

            graph.add_node(ttp_id, type="ttp", label=match["technique"])
            graph.add_node(asset, type="asset")
            graph.add_edge(asset, ttp_id, label="observed_in")

    # Step 2: Add relationships from MITRE
    for rel in relationships:
        if rel.get("relationship_type") == "uses":
            src = rel.get("source_ref", "")
            dst = rel.get("target_ref", "")

            if src.startswith("attack-pattern--") and dst.startswith("attack-pattern--"):
                src_id = src.split("--")[-1]
                dst_id = dst.split("--")[-1]

                # You can later map these UUIDs to actual external_id like T1059
                graph.add_edge(src_id, dst_id, label="uses")

    return graph


def save_graph(graph: nx.DiGraph, output_path: str):
    nx.write_gml(graph, output_path)
    print(f"✅ Graph saved to {output_path}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--relationships", required=True, help="Path to MITRE relationships.json")
    parser.add_argument("--mapped_logs", required=True, help="Path to ECS + TTP matched log file")
    parser.add_argument("--output", required=True, help="Path to save graph (GML format)")

    args = parser.parse_args()

    relationships = load_mitre_relationships(args.relationships)
    matched_logs = load_ttp_matches(args.mapped_logs)

    graph = build_attack_graph(relationships, matched_logs)
    save_graph(graph, args.output)
