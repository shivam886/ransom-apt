import json
import faiss
import numpy as np
from vectorizer import embed_single, embed_text
from pathlib import Path

INDEX_PATH = "vectorstore/index.faiss"
METADATA_PATH = "vectorstore/index_metadata.json"

def load_index():
    return faiss.read_index(INDEX_PATH)

def load_metadata():
    with open(METADATA_PATH, "r") as f:
        return json.load(f)

def retrieve_top_k(query, k=5):
    index = load_index()
    metadata = load_metadata()

    print(f"🔍 Embedding query: {query}")
    query_vec = np.array([embed_single(query)], dtype="float32")

    distances, indices = index.search(query_vec, k)

    print("\n📄 Top results:")
    results = []
    for dist, idx in zip(distances[0], indices[0]):
        item = metadata[idx]
        item["score"] = float(dist)
        results.append(item)
        print(f"- {item['id']} - {item['name']} (score: {dist:.4f})")

    return results

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--query", type=str, required=True)
    parser.add_argument("--topk", type=int, default=5)
    args = parser.parse_args()

    retrieve_top_k(args.query, args.topk)
