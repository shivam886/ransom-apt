# parsers/hdfs_parser.py

import re
from datetime import datetime

def parse_hdfs_log(line):
    try:
        parts = line.split()
        if len(parts) < 6:
            return None

        # Timestamp handling
        date_str = parts[0] + parts[1]
        timestamp = datetime.strptime(date_str, "%y%m%d%H%M%S").isoformat() + "Z"

        component = parts[5].rstrip(":")
        message = " ".join(parts[6:])

        # Extract IPs (if any)
        src_match = re.search(r'src: /([\d\.]+):(\d+)', line)
        dst_match = re.search(r'dest: /([\d\.]+):(\d+)', line)
        served_match = re.search(r'Served block .* to /([\d\.]+)', line)
        transmit_match = re.search(r'Transmitted block .* to /([\d\.]+):(\d+)', line)

        result = {
            "timestamp": timestamp,
            "component": component,
            "message": message
        }

        if src_match:
            result["source_ip"] = src_match.group(1)
        if dst_match:
            result["destination_ip"] = dst_match.group(1)
        if served_match:
            result["served_to_ip"] = served_match.group(1)
        if transmit_match:
            result["transmitted_to_ip"] = transmit_match.group(1)

        return result

    except Exception:
        return None
