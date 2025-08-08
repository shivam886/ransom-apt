# graph/dijkstra_path.py

import networkx as nx
import argparse

def find_shortest_attack_path(graph_path: str, source: str, target: str):
    print(f"📥 Loading weighted graph: {graph_path}")
    G = nx.read_gml(graph_path)

    # Ensure source and target exist
    if source not in G or target not in G:
        print(f"❌ Source ({source}) or target ({target}) not found in the graph.")
        print(f"Available nodes: {list(G.nodes)[:10]}...")
        return

    print(f"🔍 Calculating shortest path from {source} to {target}...")
    try:
        path = nx.dijkstra_path(G, source=source, target=target, weight="weight")
        total_weight = nx.dijkstra_path_length(G, source=source, target=target, weight="weight")

        print("\n🚨 Shortest Attack Path:")
        for i, node in enumerate(path):
            print(f"{i + 1}. {node} ({G.nodes[node].get('label', '')})")
        print(f"\n✅ Total Path Risk Weight: {total_weight:.2f}")

        return path, total_weight

    except nx.NetworkXNoPath:
        print("❌ No path found between the given nodes.")
        return None, None


# === CLI ===
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find shortest attack path using Dijkstra’s algorithm")
    parser.add_argument("--graph", required=True, help="Path to weighted attack_graph.gml")
    parser.add_argument("--source", required=True, help="Source node (technique ID)")
    parser.add_argument("--target", required=True, help="Target node (technique ID)")

    args = parser.parse_args()

    find_shortest_attack_path(args.graph, args.source, args.target)
