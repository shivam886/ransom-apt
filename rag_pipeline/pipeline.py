# rag_pipeline/pipeline.py
import os, json, argparse, requests
from pathlib import Path
from typing import List, Dict, Any
import numpy as np
import faiss

from vectorstore.vectorizer import embed_single
from rag_pipeline.config import (
    OLLAMA_URL, OLLAMA_MODEL, FAISS_INDEX, FAISS_METADATA,
    MITRE_CIA_JSON, TOP_K, SYSTEM_PREAMBLE, USER_TEMPLATE,
    MAPPED_LOGS_JSON, MAPPED_IOCS_JSON
)

# ---------- Loaders ----------
def load_index():
    return faiss.read_index(str(FAISS_INDEX))

def load_metadata() -> List[Dict]:
    with open(FAISS_METADATA, "r", encoding="utf-8") as f:
        return json.load(f)

def load_json_optional(p: Path | None) -> List[Dict]:
    if not p: return []
    if not Path(p).exists(): return []
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)

def load_cia_map() -> Dict[str, Dict]:
    if not Path(MITRE_CIA_JSON).exists():
        return {}
    with open(MITRE_CIA_JSON, "r", encoding="utf-8") as f:
        items = json.load(f)
    # items like {"id": "T1059", "cia_cvss": {...}}
    return {it["id"]: it.get("cia_cvss", {}) for it in items}

# ---------- Retrieval ----------
def retrieve_ttps(query: str, top_k: int = TOP_K) -> List[Dict]:
    idx = load_index()
    meta = load_metadata()
    q = np.array([embed_single(query)], dtype="float32")
    try:
        faiss.normalize_L2(q)  # safe if using IP; harmless if already L2
    except Exception:
        pass
    D, I = idx.search(q, top_k)
    out = []
    for dist, ix in zip(D[0], I[0]):
        item = meta[ix].copy()  # contains id, name, description (as you wrote it)
        item["_score"] = float(dist)
        out.append(item)
    return out

# ---------- Evidence join (Logs/IOCs) ----------
def evidence_for_tids(tids: List[str],
                      logs: List[Dict], iocs: List[Dict],
                      max_per_tid: int = 3) -> Dict[str, Dict[str, List[Dict]]]:
    ev = {tid: {"logs": [], "iocs": []} for tid in tids}
    # logs are shaped like {"log": {...}, "matches":[{"technique_id":"Txxxx",...}]}
    for entry in logs or []:
        for m in entry.get("matches", []):
            tid = m.get("technique_id")
            if tid in ev and len(ev[tid]["logs"]) < max_per_tid:
                ev[tid]["logs"].append({"log": entry.get("log", {}), "why": m})
    # iocs similar: {"ioc": {...}, "matches":[{"technique_id":"Txxxx",...}]}
    for entry in iocs or []:
        for m in entry.get("matches", []):
            tid = m.get("technique_id")
            if tid in ev and len(ev[tid]["iocs"]) < max_per_tid:
                ev[tid]["iocs"].append({"ioc": entry.get("ioc", {}), "why": m})
    return ev

# ---------- Prompt building ----------
def format_ttp_block(ttps: List[Dict], cia_map: Dict[str, Dict]) -> str:
    lines = []
    for t in ttps:
        tid = t.get("id")
        name = t.get("name")
        desc = (t.get("description") or "")[:500].replace("\n", " ")
        cia = cia_map.get(tid, {})
        impact = ""
        if cia:
            impact = f' | CIA: C={cia.get("C","N")}, I={cia.get("I","N")}, A={cia.get("A","N")} | Impact={cia.get("Impact_Subscore","-")}'
        lines.append(f"- [{tid}] {name} | score={t.get('_score',0):.3f}{impact}\n  {desc}")
    return "\n".join(lines)

def format_evidence_block(ev_map: Dict[str, Dict[str, List[Dict]]]) -> str:
    parts = []
    for tid, buckets in ev_map.items():
        if not buckets["logs"] and not buckets["iocs"]:
            continue
        parts.append(f"[{tid}]")
        for e in buckets["logs"]:
            parts.append(f"  - Log: {json.dumps(e['log'])[:220]} … (via={e['why'].get('via','log_match')})")
        for e in buckets["iocs"]:
            parts.append(f"  - IOC: {json.dumps(e['ioc'])[:220]} … (via={e['why'].get('via','ioc_match')})")
    return "\n".join(parts) if parts else "No supporting logs/IOCs found in current dataset."

def build_prompt(query: str, ttps: List[Dict],
                 logs: List[Dict], iocs: List[Dict],
                 cia_map: Dict[str, Dict]) -> str:
    tids = [t.get("id") for t in ttps if t.get("id")]
    ev = evidence_for_tids(tids, logs, iocs)
    ttp_block = format_ttp_block(ttps, cia_map)
    evidence_block = format_evidence_block(ev)
    return USER_TEMPLATE.format(query=query, ttp_block=ttp_block, evidence_block=evidence_block)

# ---------- Ollama ----------
def ollama_generate(prompt: str, system: str = SYSTEM_PREAMBLE,
                    model: str = OLLAMA_MODEL, url: str = OLLAMA_URL,
                    temperature: float = 0.2, max_tokens: int = 700) -> str:
    # streaming API; assemble
    resp = requests.post(url, json={
        "model": model,
        "prompt": f"<<SYS>>\n{system}\n<</SYS>>\n{prompt}",
        "options": {"temperature": temperature},
        "stream": True
    }, timeout=120)
    resp.raise_for_status()
    out = []
    for line in resp.iter_lines():
        if not line: continue
        try:
            obj = json.loads(line.decode("utf-8"))
            chunk = obj.get("response", "")
            out.append(chunk)
            if obj.get("done"): break
        except Exception:
            continue
    return "".join(out).strip()

# ---------- CLI ----------
def main():
    pa = argparse.ArgumentParser(description="RAG pipeline over MITRE ATT&CK + CIA + (optional) Logs/IOCs")
    pa.add_argument("--query", required=True, help="Analyst question")
    pa.add_argument("--topk", type=int, default=TOP_K)
    pa.add_argument("--logs", default=MAPPED_LOGS_JSON, help="Path to mapped logs JSON (optional)")
    pa.add_argument("--iocs", default=MAPPED_IOCS_JSON, help="Path to mapped IOCs JSON (optional)")
    args = pa.parse_args()

    cia_map = load_cia_map()
    ttps = retrieve_ttps(args.query, top_k=args.topk)
    logs = load_json_optional(Path(args.logs) if args.logs else None)
    iocs = load_json_optional(Path(args.iocs) if args.iocs else None)

    prompt = build_prompt(args.query, ttps, logs, iocs, cia_map)
    answer = ollama_generate(prompt)

    # Print nicely with a tiny header
    print("\n=== RAG ANSWER ===\n")
    print(answer)
    print("\n=== CITED TTPs ===")
    for t in ttps:
        print(f"[{t.get('id')}] {t.get('name')} (score={t.get('_score',0):.3f})")

if __name__ == "__main__":
    main()
