# parsers/healthapp_parser.py

import re
from datetime import datetime

def parse_healthapp_log(line):
    parts = line.strip().split('|')
    if len(parts) < 4:
        return None

    # Extract timestamp and reformat
    try:
        timestamp_raw = parts[0]
        timestamp = datetime.strptime(timestamp_raw, "%Y%m%d-%H:%M:%S:%f").isoformat() + "Z"
    except ValueError:
        return None  # skip malformed timestamps

    return {
        "timestamp": timestamp,
        "module": parts[1],
        "device_id": parts[2],
        "message": parts[3]
    }
