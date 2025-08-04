# mitre/mitre_loader.py

import json
from pathlib import Path
from typing import List, Dict


def load_stix_objects(file_path: str) -> List[Dict]:
    """Load STIX objects from a file, supporting both bundle and raw list formats."""
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, list):
        return data  # raw list of objects
    elif isinstance(data, dict) and "objects" in data:
        return data["objects"]  # STIX bundle
    else:
        raise ValueError(f"Unsupported STIX format in {file_path}")


def extract_attack_patterns(objects: List[Dict]) -> List[Dict]:
    return [obj for obj in objects if obj.get("type") == "attack-pattern"]


def extract_relationships(objects: List[Dict]) -> List[Dict]:
    return [obj for obj in objects if obj.get("type") == "relationship"]


def extract_intrusion_sets(objects: List[Dict]) -> List[Dict]:
    return [obj for obj in objects if obj.get("type") == "intrusion-set"]


def extract_software(objects: List[Dict]) -> List[Dict]:
    return [obj for obj in objects if obj.get("type") in ["tool", "malware"]]


def extract_all_from_folder(folder_path: str) -> Dict[str, List[Dict]]:
    """Load and extract all MITRE objects from a folder of JSON files."""
    all_objects = []

    for path in Path(folder_path).rglob("*.json"):
        print(f"📥 Loading: {path.name}")
        all_objects.extend(load_stix_objects(str(path)))

    return {
        "attack_patterns": extract_attack_patterns(all_objects),
        "relationships": extract_relationships(all_objects),
        "intrusion_sets": extract_intrusion_sets(all_objects),
        "software": extract_software(all_objects),
    }


def save_extracted_data(data: Dict[str, List[Dict]], output_dir: str):
    """Save each extracted category to separate JSON files."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    for category, items in data.items():
        output_path = Path(output_dir) / f"{category}.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(items, f, indent=2)
        print(f"✅ Saved {category} to {output_path}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Load and extract MITRE ATT&CK data.")
    parser.add_argument("--input", type=str, default="data/mitre", help="Folder containing MITRE JSON files")
    parser.add_argument("--output", type=str, default="data/mitre/processed", help="Folder to save extracted files")

    args = parser.parse_args()

    extracted_data = extract_all_from_folder(args.input)
    save_extracted_data(extracted_data, args.output)
