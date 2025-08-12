# vectorstore/build_index.py (drop-in replacement for load_ttp_texts + build)
import json
import faiss
import numpy as np
from pathlib import Path
from datetime import datetime
from vectorizer import embed_text

INDEX_PATH = "vectorstore/index.faiss"
METADATA_PATH = "vectorstore/index_metadata.json"

def _is_active(item: dict) -> bool:
    if item.get("revoked") is True: return False
    if item.get("x_mitre_deprecated") is True: return False
    return True

def _dt(s: str) -> datetime:
    # safe date parser; unknown -> minimal time so newer wins
    try:
        return datetime.fromisoformat(s.replace("Z",""))
    except Exception:
        return datetime.min

def _dedupe_latest(items):
    """Keep the latest active object per external technique id."""
    by_id = {}
    for it in items:
        tid = it.get("id") or it.get("external_id") or ""
        if not tid: 
            # try to pull from STIX external_references if present
            for ref in it.get("external_references", []):
                if ref.get("external_id"):
                    tid = ref["external_id"]; break
        if not tid: 
            continue
        if not _is_active(it):
            continue
        prev = by_id.get(tid)
        if not prev or _dt(it.get("modified","")) > _dt(prev.get("modified","")):
            by_id[tid] = it
    return list(by_id.values())

def load_ttp_texts(path: str):
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    items = _dedupe_latest(raw)

    texts = []
    metadata = []
    for item in items:
        tid = item.get("id") or ""
        name = item.get("name", "")
        desc = item.get("description", "") or ""
        cia = item.get("cia_cvss", {})
        cia_str = f" [CIA: C={cia.get('C','N')} I={cia.get('I','N')} A={cia.get('A','N')} Impact={cia.get('Impact_Subscore','-')}]" if cia else ""
        texts.append(f"{tid} - {name}: {desc}{cia_str}")
        metadata.append({
            "id": tid,
            "name": name,
            "description": desc,
            "cia_cvss": cia
        })
    return texts, metadata

def build_and_save_index(input_json=None):
    if input_json is None:
        cvss = Path("data/mitre_cti/processed/attack_patterns_cia_cvss.json")
        basic = Path("data/mitre_cti/processed/attack_patterns_cia.json")
        raw   = Path("data/mitre_cti/processed/attack_patterns.json")
        input_json = str(cvss if cvss.exists() else (basic if basic.exists() else raw))

    print(f"📥 Loading TTPs from {input_json} ...")
    texts, metadata = load_ttp_texts(input_json)

    print("🧠 Embedding TTPs...")
    vectors = np.array(embed_text(texts)).astype("float32")

    print("📦 Building FAISS (cosine/IP)...")
    faiss.normalize_L2(vectors)
    index = faiss.IndexFlatIP(vectors.shape[1])
    index.add(vectors)

    print(f"💾 Saving index → {INDEX_PATH}")
    faiss.write_index(index, INDEX_PATH)
    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"✅ Vector index built. Items indexed: {len(metadata)}")
