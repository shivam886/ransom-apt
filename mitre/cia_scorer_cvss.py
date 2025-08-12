# import json
# import argparse
# from pathlib import Path
# from typing import Dict, List, Tuple

# # ---------------- CVSS v3.1 constants ----------------
# CVSS_WEIGHT = {
#     "N": 0.00,   # None
#     "L": 0.22,   # Low
#     "H": 0.56,   # High
# }
# CVSS_LABELS = ["none", "low", "high"]  # classification targets

# # ---------------- Optional ML (CPU) ----------------
# USE_ZS = True
# try:
#     from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
# except Exception:
#     USE_ZS = False

# # Simple keyword fallback (very conservative)
# KEYWORDS = {
#     "confidentiality": {
#         "high": ["exfiltrat", "leak", "steal", "dump credential", "data theft", "exposure"],
#         "low":  ["access sensitive", "view", "enumerat cred", "discover secrets"]
#     },
#     "integrity": {
#         "high": ["tamper", "modify", "backdoor", "replace", "inject", "sideload"],
#         "low":  ["alter", "manipulate", "change config", "edit"]
#     },
#     "availability": {
#         "high": ["encrypt", "ransom", "destroy", "wipe", "dos", "ddos", "disable service"],
#         "low":  ["degrade", "flood", "resource exhaustion", "lock"]
#     }
# }

# def fallback_label(text: str, dimension: str) -> str:
#     t = text.lower()
#     for kw in KEYWORDS[dimension]["high"]:
#         if kw in t:
#             return "H"
#     for kw in KEYWORDS[dimension]["low"]:
#         if kw in t:
#             return "L"
#     return "N"

# def load_attack_patterns(path: Path) -> List[Dict]:
#     with open(path, "r", encoding="utf-8") as f:
#         return json.load(f)

# def save_output(rows: List[Dict], out_path: Path):
#     out_path.parent.mkdir(parents=True, exist_ok=True)
#     with open(out_path, "w", encoding="utf-8") as f:
#         json.dump(rows, f, indent=2)
#     print(f"✅ Saved {len(rows)} CIA CVSS-scored TTPs → {out_path}")

# def to_ext_id(ap: Dict) -> str:
#     for ref in ap.get("external_references", []):
#         if ref.get("source_name", "").startswith("mitre") and ref.get("external_id"):
#             return ref["external_id"]
#     return ""

# def cvss_isc_base(C: float, I: float, A: float) -> float:
#     # ISC_Base = 1 − (1−C)(1−I)(1−A)
#     return 1.0 - (1.0 - C) * (1.0 - I) * (1.0 - A)

# def cvss_impact_subscore(isc_base: float, scope_changed: bool) -> float:
#     if scope_changed:
#         return max(0.0, 7.52 * (isc_base - 0.029) - 3.25 * pow((isc_base - 0.02), 15))
#     else:
#         return 6.42 * isc_base

# def pick_level_from_probs(probs: Dict[str, float], hi_thr: float, lo_thr: float) -> str:
#     # probs keyed by 'none'/'low'/'high'
#     if probs.get("high", 0.0) >= hi_thr:
#         return "H"
#     if probs.get("low", 0.0) >= lo_thr:
#         return "L"
#     return "N"

# def score_with_zeroshot(text: str, clf, hi_thr: float, lo_thr: float) -> Tuple[str, str, str]:
#     # We ask three tailored prompts to reduce crosstalk across dimensions
#     prompts = {
#         "confidentiality": f"Does this technique harm confidentiality? {text}",
#         "integrity":       f"Does this technique harm integrity? {text}",
#         "availability":    f"Does this technique harm availability? {text}",
#     }
#     levels = {}
#     for dim, prompt in prompts.items():
#         out = clf(prompt, candidate_labels=CVSS_LABELS, multi_label=False)
#         # Normalize label→score dict
#         probs = {lbl.lower(): float(score) for lbl, score in zip(out["labels"], out["scores"])}
#         levels[dim] = pick_level_from_probs(probs, hi_thr, lo_thr)  # 'H'|'L'|'N'
#     return levels["confidentiality"], levels["integrity"], levels["availability"]

# def main():
#     ap = argparse.ArgumentParser(description="Score MITRE ATT&CK techniques with CVSS-style CIA metrics.")
#     ap.add_argument("--input",  default="data/mitre_cti/processed/attack_patterns.json",
#                     help="Path to MITRE attack_patterns.json")
#     ap.add_argument("--output", default="data/mitre_cti/processed/attack_patterns_cia_cvss.json",
#                     help="Output JSON path")
#     ap.add_argument("--scope", choices=["unchanged","changed"], default="unchanged",
#                     help="CVSS Scope for Impact subscore (default: unchanged)")
#     ap.add_argument("--hi-thr", type=float, default=0.55, help="Zero-shot probability threshold for High")
#     ap.add_argument("--lo-thr", type=float, default=0.40, help="Zero-shot probability threshold for Low")
#     ap.add_argument("--no-ml", action="store_true", help="Disable transformers; use keyword fallback only")
#     args = ap.parse_args()

#     scope_changed = (args.scope == "changed")

#     # Load input
#     aps = load_attack_patterns(Path(args.input))
#     print(f"📥 Loaded {len(aps)} attack patterns")

#     # Init zero-shot on CPU (optional)
#     use_ml = (USE_ZS and not args.no_ml)
#     if use_ml:
#         print("🧠 Loading zero-shot model on CPU (facebook/bart-large-mnli)…")
#         tokenizer = AutoTokenizer.from_pretrained("facebook/bart-large-mnli")
#         model = AutoModelForSequenceClassification.from_pretrained("facebook/bart-large-mnli")
#         clf = pipeline("zero-shot-classification", model=model, tokenizer=tokenizer, device=-1)
#         print("✅ Model ready.")
#     else:
#         clf = None
#         print("ℹ️ Using keyword fallback (no transformers).")

#     out_rows: List[Dict] = []
#     for i, ap in enumerate(aps, 1):
#         ext_id = to_ext_id(ap)
#         if not ext_id:
#             continue
#         text = (ap.get("description") or "") + " " + (ap.get("x_mitre_detection") or "")
#         text = text[:2000]  # keep things bounded

#         if use_ml:
#             C_level, I_level, A_level = score_with_zeroshot(text, clf, args.hi_thr, args.lo_thr)
#         else:
#             C_level = fallback_label(text, "confidentiality")
#             I_level = fallback_label(text, "integrity")
#             A_level = fallback_label(text, "availability")

#         Cw = CVSS_WEIGHT[C_level]
#         Iw = CVSS_WEIGHT[I_level]
#         Aw = CVSS_WEIGHT[A_level]

#         isc_base = cvss_isc_base(Cw, Iw, Aw)
#         impact_sub = cvss_impact_subscore(isc_base, scope_changed)

#         out_rows.append({
#             "id": ext_id,
#             "name": ap.get("name", ""),
#             "cia_cvss": {
#                 "C": C_level, "I": I_level, "A": A_level,             # categorical
#                 "C_weight": Cw, "I_weight": Iw, "A_weight": Aw,       # numeric CVSS weights
#                 "ISC_Base": round(isc_base, 4),
#                 "Impact_Subscore": round(impact_sub, 2),
#                 "Scope": "C" if scope_changed else "U"
#             }
#         })

#         if i % 200 == 0:
#             print(f"…scored {i} techniques")

#     save_output(out_rows, Path(args.output))

# if __name__ == "__main__":
#     main()

import json, argparse, math
from pathlib import Path
from typing import Dict, List, Tuple

CVSS_WEIGHT = {"N": 0.00, "L": 0.22, "H": 0.56}
CVSS_LABELS = ["none", "low", "high"]

USE_ZS = True
try:
    from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
except Exception:
    USE_ZS = False

try:
    from tqdm import tqdm
except Exception:
    tqdm = lambda x, **k: x  # fallback no-op

KEYWORDS = {
    "confidentiality": {
        "high": ["exfiltrat", "leak", "steal", "dump credential", "data theft", "exposure"],
        "low":  ["access sensitive", "view", "enumerat cred", "discover secrets"],
    },
    "integrity": {
        "high": ["tamper", "modify", "backdoor", "replace", "inject", "sideload"],
        "low":  ["alter", "manipulate", "change config", "edit"],
    },
    "availability": {
        "high": ["encrypt", "ransom", "destroy", "wipe", "dos", "ddos", "disable service"],
        "low":  ["degrade", "flood", "resource exhaustion", "lock"],
    },
}

def fallback_label(text: str, dimension: str) -> str:
    t = text.lower()
    for kw in KEYWORDS[dimension]["high"]:
        if kw in t: return "H"
    for kw in KEYWORDS[dimension]["low"]:
        if kw in t: return "L"
    return "N"

def load_attack_patterns(path: Path) -> List[Dict]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_output(rows: List[Dict], out_path: Path):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)
    print(f"✅ Saved {len(rows)} CIA CVSS-scored TTPs → {out_path}")

def to_ext_id(ap: Dict) -> str:
    for ref in ap.get("external_references", []):
        if ref.get("source_name", "").startswith("mitre") and ref.get("external_id"):
            return ref["external_id"]
    return ""

def cvss_isc_base(C: float, I: float, A: float) -> float:
    return 1.0 - (1.0 - C) * (1.0 - I) * (1.0 - A)

def cvss_impact_subscore(isc_base: float, scope_changed: bool) -> float:
    if scope_changed:
        return max(0.0, 7.52 * (isc_base - 0.029) - 3.25 * pow((isc_base - 0.02), 15))
    return 6.42 * isc_base

def pick_level_from_probs(probs: Dict[str, float], hi_thr: float, lo_thr: float) -> str:
    if probs.get("high", 0.0) >= hi_thr: return "H"
    if probs.get("low", 0.0)  >= lo_thr: return "L"
    return "N"

def batched_zero_shot(clf, texts: List[str], labels: List[str], batch_size: int = 32) -> List[Dict[str, float]]:
    """Return a list of prob dicts (keys: 'none','low','high') for each text."""
    out: List[Dict[str, float]] = []
    for i in tqdm(range(0, len(texts), batch_size), desc="🔎 Zero-shot (batched)"):
        batch = texts[i:i+batch_size]
        res = clf(batch, candidate_labels=labels, multi_label=False)  # pipeline supports list inputs
        if isinstance(res, dict):  # single item edge case
            res = [res]
        for r in res:
            probs = {lbl.lower(): float(score) for lbl, score in zip(r["labels"], r["scores"])}
            out.append(probs)
    return out

def main():
    ap = argparse.ArgumentParser(description="CVSS-style CIA scorer (batched, CPU-friendly).")
    ap.add_argument("--input",  default="data/mitre_cti/processed/attack_patterns.json")
    ap.add_argument("--output", default="data/mitre_cti/processed/attack_patterns_cia_cvss.json")
    ap.add_argument("--scope", choices=["unchanged","changed"], default="unchanged")
    ap.add_argument("--hi-thr", type=float, default=0.55)
    ap.add_argument("--lo-thr", type=float, default=0.40)
    ap.add_argument("--no-ml", action="store_true")
    ap.add_argument("--model", default="valhalla/distilbart-mnli-12-3", help="Zero-shot model (smaller=faster)")
    ap.add_argument("--batch-size", type=int, default=32)
    ap.add_argument("--limit", type=int, default=0, help="Process only first N techniques (debug)")
    args = ap.parse_args()

    scope_changed = (args.scope == "changed")
    aps = load_attack_patterns(Path(args.input))
    if args.limit and args.limit > 0:
        aps = aps[:args.limit]
    print(f"📥 Loaded {len(aps)} attack patterns")

    use_ml = (USE_ZS and not args.no_ml)
    clf = None
    if use_ml:
        print(f"🧠 Loading zero-shot model on CPU: {args.model}")
        tok = AutoTokenizer.from_pretrained(args.model)
        mdl = AutoModelForSequenceClassification.from_pretrained(args.model)
        clf = pipeline("zero-shot-classification", model=mdl, tokenizer=tok, device=-1)
        print("✅ Model ready.")
    else:
        print("ℹ️ Using keyword fallback (no transformers).")

    # Prepare texts
    texts = []
    ids = []
    names = []
    for ap in aps:
        ext_id = to_ext_id(ap)
        if not ext_id: continue
        txt = ((ap.get("description") or "") + " " + (ap.get("x_mitre_detection") or "")).strip()
        texts.append(txt[:2000])
        ids.append(ext_id)
        names.append(ap.get("name", ""))

    out_rows: List[Dict] = []

    if use_ml and texts:
        # Do three batched passes with targeted prompts to reduce crosstalk
        prompts_C = [f"Does this technique harm confidentiality? {t}" for t in texts]
        prompts_I = [f"Does this technique harm integrity? {t}"       for t in texts]
        prompts_A = [f"Does this technique harm availability? {t}"    for t in texts]

        probs_C = batched_zero_shot(clf, prompts_C, CVSS_LABELS, args.batch_size)
        probs_I = batched_zero_shot(clf, prompts_I, CVSS_LABELS, args.batch_size)
        probs_A = batched_zero_shot(clf, prompts_A, CVSS_LABELS, args.batch_size)

        for ext_id, name, pc, pi, pa in zip(ids, names, probs_C, probs_I, probs_A):
            C_level = pick_level_from_probs(pc, args.hi_thr, args.lo_thr)
            I_level = pick_level_from_probs(pi, args.hi_thr, args.lo_thr)
            A_level = pick_level_from_probs(pa, args.hi_thr, args.lo_thr)

            Cw, Iw, Aw = CVSS_WEIGHT[C_level], CVSS_WEIGHT[I_level], CVSS_WEIGHT[A_level]
            isc = cvss_isc_base(Cw, Iw, Aw)
            impact = cvss_impact_subscore(isc, scope_changed)

            out_rows.append({
                "id": ext_id, "name": name,
                "cia_cvss": {
                    "C": C_level, "I": I_level, "A": A_level,
                    "C_weight": Cw, "I_weight": Iw, "A_weight": Aw,
                    "ISC_Base": round(isc, 4),
                    "Impact_Subscore": round(impact, 2),
                    "Scope": "C" if scope_changed else "U"
                }
            })
    else:
        # keyword fallback
        for ap in aps:
            ext_id = to_ext_id(ap)
            if not ext_id: continue
            text = ((ap.get("description") or "") + " " + (ap.get("x_mitre_detection") or "")).lower()
            C = fallback_label(text, "confidentiality")
            I = fallback_label(text, "integrity")
            A = fallback_label(text, "availability")
            Cw, Iw, Aw = CVSS_WEIGHT[C], CVSS_WEIGHT[I], CVSS_WEIGHT[A]
            isc = cvss_isc_base(Cw, Iw, Aw)
            impact = cvss_impact_subscore(isc, scope_changed)
            out_rows.append({
                "id": ext_id, "name": ap.get("name",""),
                "cia_cvss": {
                    "C": C, "I": I, "A": A,
                    "C_weight": Cw, "I_weight": Iw, "A_weight": Aw,
                    "ISC_Base": round(isc, 4),
                    "Impact_Subscore": round(impact, 2),
                    "Scope": "C" if scope_changed else "U"
                }
            })

    save_output(out_rows, Path(args.output))

if __name__ == "__main__":
    main()
