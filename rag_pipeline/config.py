# rag_pipeline/config.py
from pathlib import Path

# --- Model / Ollama ---
OLLAMA_URL = "http://localhost:11434/api/generate"  # or set via .env and read here
OLLAMA_MODEL = "llama3"                 # pick the local model you pulled

# --- Data paths ---
MITRE_ATTACK_JSON = Path("data/mitre_cti/processed/attack_patterns.json")
MITRE_CIA_JSON    = Path("data/mitre_cti/processed/attack_patterns_cia_cvss.json")

# vector index built from attack_patterns(+optional CIA-enriched descriptions)
FAISS_INDEX       = Path("vectorstore/index.faiss")
FAISS_METADATA    = Path("vectorstore/index_metadata.json")

# optional evidence (mapped logs / mapped IOCs)
MAPPED_LOGS_JSON  = None  # e.g., Path("data/mapped/ttp_mapped_windows.json")
MAPPED_IOCS_JSON  = None  # e.g., Path("data/mapped/ioc_ttp_mapped.json")

TOP_K = 8

# --- Prompt template ---
SYSTEM_PREAMBLE = """You are a security analyst. Answer strictly with evidence from the provided context.
Map the user question to MITRE ATT&CK techniques (TTPs). Include short IDs (e.g., T1059) and tactics if present.
Cite each claim using the given [TID] markers and ‘Logs’ or ‘IOCs’ references when used.
If context is insufficient, say so briefly and suggest the next artifact to collect."""

USER_TEMPLATE = """Question: {query}

# Retrieved TTPs:
{ttp_block}

# Evidence (Logs/IOCs):
{evidence_block}

Answer:
"""
