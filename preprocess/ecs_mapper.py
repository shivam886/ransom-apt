# # preprocess/ecs_mapper.py
# import sys
# import os
# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# import json
# import argparse
# from pathlib import Path

# from preprocess.mappers.hdfs_ecs import map_hdfs_to_ecs
# from preprocess.mappers.linux_ecs import map_linux_to_ecs
# from preprocess.mappers.mac_ecs import map_mac_to_ecs
# from preprocess.mappers.android_ecs import map_android_to_ecs
# from preprocess.mappers.healthapp_ecs import map_healthapp_to_ecs

# def map_to_ecs(log_entry: dict, log_type: str) -> dict:
#     mapper_functions = {
#         "hdfs": map_hdfs_to_ecs,
#         "linux": map_linux_to_ecs,
#         "mac": map_mac_to_ecs,
#         "android": map_android_to_ecs,
#         "healthapp": map_healthapp_to_ecs
#     }

#     if log_type not in mapper_functions:
#         raise ValueError(f"Unsupported log type: {log_type}")

#     return mapper_functions[log_type](log_entry)

# def main():
#     parser = argparse.ArgumentParser()
#     parser.add_argument("--type", required=True, help="Log type (hdfs, linux, mac, android, healthapp)")
#     parser.add_argument("--input", required=True, help="Path to parsed log JSON")
#     parser.add_argument("--output", required=True, help="Path to save ECS-mapped log JSON")

#     args = parser.parse_args()

#     input_path = Path(args.input)
#     output_path = Path(args.output)

#     if not input_path.exists():
#         raise FileNotFoundError(f"❌ Input file not found: {input_path}")

#     with open(input_path, "r") as infile:
#         logs = json.load(infile)

#     ecs_mapped_logs = []
#     for entry in logs:
#         try:
#             ecs_entry = map_to_ecs(entry, args.type)
#             ecs_mapped_logs.append(ecs_entry)
#         except Exception as e:
#             print(f"[⚠️ Warning] Failed to map entry: {entry} - {e}")

#     output_path.parent.mkdir(parents=True, exist_ok=True)
#     with open(output_path, "w") as outfile:
#         json.dump(ecs_mapped_logs, outfile, indent=2)

#     print(f"✅ Saved ECS-mapped logs to: {output_path}")

# if __name__ == "__main__":
#     main()

# File: preprocess/ecs_mapper.py
import argparse
import json
import pandas as pd
from pathlib import Path
from typing import List, Dict
import os

from mappers.windows_wazuh_ecs import map_windows_to_ecs, map_wazuh_csv_row_to_ecs

def read_input_file(input_path: str, log_type: str) -> List[Dict]:
    path = Path(input_path)
    if path.suffix == ".json":
        with open(path, "r") as f:
            return [json.loads(line) for line in f if line.strip()]
    elif path.suffix == ".csv":
        df = pd.read_csv(path)
        return df.to_dict(orient="records")
    elif path.suffix == ".txt" and log_type == "windows":
        with open(path, "r") as f:
            return [json.loads(line) for line in f if line.strip()]
    else:
        raise ValueError(f"Unsupported file format: {path.suffix}")

def map_logs(logs: List[Dict], log_type: str) -> List[Dict]:
    if log_type == "windows":
        return [map_windows_to_ecs(log) for log in logs]
    elif log_type == "wazuh":
        return [map_wazuh_csv_row_to_ecs(log) for log in logs]
    else:
        raise ValueError(f"Unsupported log type: {log_type}")
    

def save_output(mapped_logs, output_path):
    with open(output_path, "w") as f:
        json.dump(mapped_logs, f, indent=2)


def run_ecs_mapper(log_type: str, input_path: str, output_path: str):
    logs = read_input_file(input_path, log_type)
    mapped = map_logs(logs, log_type)
    save_output(mapped, output_path)
    print(f"[+] ECS mapping complete. {len(mapped)} records written to {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--type", required=True, choices=["windows", "wazuh"], help="Log type")
    parser.add_argument("--input", required=True, help="Input file path (.json, .csv, .txt)")
    parser.add_argument("--output", required=True, help="Output file path (.json)")
    args = parser.parse_args()

    run_ecs_mapper(args.type, args.input, args.output)

