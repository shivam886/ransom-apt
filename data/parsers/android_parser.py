# parsers/android_parser.py

import re
from datetime import datetime

def parse_android_log(line):
    pattern = (
        r'(?P<date>\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}\.\d{3})\s+'
        r'(?P<pid>\d+)\s+(?P<tid>\d+)\s+(?P<level>[VDIWEF]) (?P<tag>[^:]+): (?P<message>.+)'
    )

    match = re.match(pattern, line)
    if not match:
        return None

    g = match.groupdict()
    now = datetime.utcnow()
    full_date_str = f"{now.year}-{g['date']} {g['time']}"
    timestamp = datetime.strptime(full_date_str, "%Y-%m-%d %H:%M:%S.%f").isoformat() + "Z"

    return {
        "timestamp": timestamp,
        "pid": g["pid"],
        "tid": g["tid"],
        "level": g["level"],
        "tag": g["tag"].strip(),
        "message": g["message"].strip()
    }
