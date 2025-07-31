import json
from pathlib import Path

# Path to the master MITRE STIX file
SOURCE_FILE = Path("data/mitre_cti/enterprise-attack.json")

# Output files
OUT_DIR = Path("data/mitre_cti")
OUT_FILES = {
    "attack-pattern": OUT_DIR / "attack-patterns.json",
    "relationship": OUT_DIR / "relationships.json",
    "malware": OUT_DIR / "software.json",
    "tool": OUT_DIR / "software.json",
    "intrusion-set": OUT_DIR / "groups.json"
}

# Object type to content map
output_objects = {
    "attack-pattern": [],
    "relationship": [],
    "malware": [],     # software includes malware and tools
    "tool": [],
    "intrusion-set": []
}

# Load enterprise-attack.json
with open(SOURCE_FILE, "r") as f:
    stix_data = json.load(f)

# Collect relevant objects
for obj in stix_data["objects"]:
    obj_type = obj.get("type")
    if obj_type in output_objects:
        output_objects[obj_type].append(obj)

# Save grouped outputs
for obj_type, objs in output_objects.items():
    target_file = OUT_FILES[obj_type]
    if not target_file.exists():
        with open(target_file, "w") as f:
            json.dump(objs, f, indent=2)

print("✅ Extracted attack-patterns, relationships, software, and groups!")
