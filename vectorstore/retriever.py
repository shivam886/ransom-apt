# vectorstore/retriever.py
import json
import faiss
import numpy as np
from pathlib import Path
from vectorizer import embed_single

INDEX_PATH = "vectorstore/index.faiss"
METADATA_PATH = "vectorstore/index_metadata.json"

def load_index():
    return faiss.read_index(str(Path(INDEX_PATH)))

def load_metadata():
    with open(METADATA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def retrieve_top_k(query: str, k: int = 5):
    index = load_index()
    metadata = load_metadata()

    print(f"🔍 Embedding query: {query}")
    q = np.array([embed_single(query)], dtype="float32")
    try:
        faiss.normalize_L2(q)  # for cosine/IP
    except Exception:
        pass

    distances, indices = index.search(q, max(k * 3, k))  # overfetch to allow dedupe

    print("\n📄 Top results:")
    results, seen = [], set()
    for dist, idx in zip(distances[0], indices[0]):
        if idx < 0: 
            continue
        item = metadata[idx]
        tid = item.get("id")
        if not tid or tid in seen:
            continue
        seen.add(tid)
        out = {
            "id": tid,
            "name": item.get("name", ""),
            "description": item.get("description", ""),
            "score": float(dist),
        }
        results.append(out)
        print(f"- {out['id']} - {out['name']} (score: {out['score']:.4f})")
        if len(results) >= k:
            break

    return results

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--query", required=True)
    p.add_argument("--topk", type=int, default=5)
    args = p.parse_args()
    retrieve_top_k(args.query, args.topk)
