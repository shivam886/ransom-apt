# parsers/hadoop_parser.py

import re
from datetime import datetime

def parse_hadoop_log(line):
    pattern = (
        r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) '
        r'(?P<level>[A-Z]+) \[(?P<thread>[^\]]+)\] '
        r'(?P<source>[^\s]+) ?: (?P<message>.*)'
    )

    match = re.match(pattern, line)
    if not match:
        return None

    g = match.groupdict()

    return {
        "timestamp": datetime.strptime(g["timestamp"], "%Y-%m-%d %H:%M:%S,%f").isoformat() + "Z",
        "level": g["level"],
        "thread": g["thread"],
        "source": g["source"],
        "message": g["message"].strip()
    }
