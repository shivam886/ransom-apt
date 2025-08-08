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

