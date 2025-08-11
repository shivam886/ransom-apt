import json
import faiss
import numpy as np
from vectorizer import embed_text
from pathlib import Path

INDEX_PATH = "vectorstore/index.faiss"
METADATA_PATH = "vectorstore/index_metadata.json"

def load_ttp_texts(path):
    with open(path, "r") as f:
        data = json.load(f)
    texts = [f"{item['id']} - {item['name']}: {item['description']}" for item in data]
    return texts, data

def build_and_save_index(input_json="data/mitre_cti/processed/attack_patterns_cia.json"):
    print("📥 Loading TTPs...")
    texts, metadata = load_ttp_texts(input_json)

    print("🧠 Embedding TTPs...")
    vectors = embed_text(texts)
    vectors = np.array(vectors).astype("float32")

    print("📦 Building FAISS index...")
    index = faiss.IndexFlatL2(vectors.shape[1])
    index.add(vectors)

    print(f"💾 Saving index to {INDEX_PATH}")
    faiss.write_index(index, INDEX_PATH)

    with open(METADATA_PATH, "w") as f:
        json.dump(metadata, f, indent=2)

    print("✅ Vector index built successfully.")

if __name__ == "__main__":
    build_and_save_index()
