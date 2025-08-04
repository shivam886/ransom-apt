# parsers/linux_parser.py

import re
from datetime import datetime

def parse_unix_syslog(line):
    pattern = (
        r'(?P<month>\w{3})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) '
        r'(?P<host>\S+) (?P<component>\S+?)(?:\[(?P<pid>\d+)\])?: (?P<message>.+)'
    )

    match = re.match(pattern, line)
    if not match:
        return None

    g = match.groupdict()
    now = datetime.utcnow()
    date_str = f"{g['month']} {g['day']} {now.year} {g['time']}"
    timestamp = datetime.strptime(date_str, "%b %d %Y %H:%M:%S").isoformat() + "Z"

    return {
        "timestamp": timestamp,
        "host": g["host"],
        "component": g["component"].strip(),
        "pid": g.get("pid"),
        "message": g["message"].strip()
    }
