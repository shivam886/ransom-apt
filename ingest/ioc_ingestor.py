import csv

def parse_custom_ioc_file(file_path):
    iocs = []

    with open(file_path, newline='', encoding='utf-8', errors='replace') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            iocs.append({
                "type": row.get("Type", "").strip().lower(),
                "value": row.get("Hash", "").strip(),
                "family": row.get("Family", "").strip(),
                "name": row.get("Name", "").strip(),
                "date": row.get("First_Seen", "").strip(),
                "source": "uploaded_csv"
            })

    return iocs
