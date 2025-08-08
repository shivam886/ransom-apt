import json
from pathlib import Path
from typing import Dict, List
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification

# ========== CONFIG ==========

CIA_LABELS = ["confidentiality", "integrity", "availability"]
MODEL_NAME = "facebook/bart-large-mnli"
MAX_TOKENS = 1024
DEVICE = -1  # -1 = CPU

# ========== LOAD CLASSIFIER ==========

print("🚀 Loading model on CPU...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
classifier = pipeline("zero-shot-classification", model=model, tokenizer=tokenizer, device=DEVICE)
print("✅ Model loaded on CPU.")

# ========== FUNCTIONS ==========

def score_cia(description: str) -> Dict[str, int]:
    """Use zero-shot classification to score a TTP description by CIA impact as integers."""
    if not description:
        return {label: 0 for label in CIA_LABELS}

    try:
        print(f"🔍 Scoring: {description[:60]}...")
        result = classifier(description[:MAX_TOKENS], candidate_labels=CIA_LABELS)

        # Scale and convert scores to integer
        scores = {}
        for label, score in zip(result["labels"], result["scores"]):
            # Multiply by 3 and round for 0–3 scale
            scaled = round(score * 3)
            scores[label] = int(min(scaled, 3))  # Cap max score to 3

        return scores
    except Exception as e:
        print(f"❌ Error scoring CIA: {e}")
        return {label: 0 for label in CIA_LABELS}


def map_cia_to_ttps(attack_patterns: List[Dict]) -> List[Dict]:
    """Attach CIA scores to MITRE ATT&CK patterns."""
    scored_ttps = []

    for ap in attack_patterns:
        desc = ap.get("description", "") + " " + ap.get("x_mitre_detection", "")
        cia_score = score_cia(desc)
        scored_ttps.append({
            "id": ap.get("external_references", [{}])[0].get("external_id", ""),
            "name": ap.get("name", ""),
            "description": ap.get("description", ""),
            "cia_score": cia_score
        })

    return scored_ttps

def load_attack_patterns(path: str) -> List[Dict]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_scored_ttps(scored: List[Dict], output_path: str):
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(scored, f, indent=2)
    print(f"✅ Saved CIA-scored TTPs to {output_path}")

# ========== MAIN CLI ==========

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Score MITRE ATT&CK TTPs using CIA triad (zero-shot).")
    parser.add_argument("--input", type=str, default="data/mitre_cti/processed/attack_patterns.json", help="Path to attack_patterns.json")
    parser.add_argument("--output", type=str, default="data/mitre_cti/processed/attack_patterns_cia.json", help="Output path for scored TTPs")
    args = parser.parse_args()

    print("📥 Loading MITRE ATT&CK patterns...")
    attack_patterns = load_attack_patterns(args.input)

    print("🧠 Scoring CIA impact...")
    scored = map_cia_to_ttps(attack_patterns)

    save_scored_ttps(scored, args.output)
