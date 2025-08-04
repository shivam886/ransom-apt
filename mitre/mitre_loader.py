from stix2 import parse
import json

def load_attack_patterns(file_path="data/mitre_cti/enterprise-attack.json"):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return [parse(obj) for obj in data["objects"] if obj["type"] == "attack-pattern"]

def load_relationships(file_path="data/mitre_cti/relationships.json"):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return [parse(obj) for obj in data["objects"] if obj["type"] == "relationship"]
