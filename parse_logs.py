import argparse
import json
from data.parsers.hdfs_parser import parse_hdfs_log
from data.parsers.linux_parser import parse_unix_syslog
from data.parsers.hadoop_parser import parse_hadoop_log
from data.parsers.android_parser import parse_android_log
from data.parsers.healthapp_parser import parse_healthapp_log
from data.parsers.mac_parser import parse_mac_log

PARSERS = {
    "hdfs": parse_hdfs_log,
    "linux": parse_unix_syslog,
    "mac": parse_mac_log,
    "hadoop": parse_hadoop_log,
    "android": parse_android_log,
    "healthapp": parse_healthapp_log,
}

def main():
    parser = argparse.ArgumentParser(description="Log parser CLI")
    parser.add_argument("--type", required=True, help="Type of log (hdfs, linux, mac, hadoop, android, healthapp)")
    parser.add_argument("--input", required=True, help="Path to input raw log file")
    parser.add_argument("--output", required=True, help="Path to save parsed output JSON")

    args = parser.parse_args()

    log_type = args.type.lower()
    if log_type not in PARSERS:
        print(f"❌ Unsupported log type: {log_type}")
        return

    parser_fn = PARSERS[log_type]
    results = []

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parsed = parser_fn(line.strip())
            if parsed:
                results.append(parsed)

    with open(args.output, "w", encoding="utf-8") as out:
        json.dump(results, out, indent=2)
    print(f"✅ Parsed {len(results)} logs and saved to {args.output}")

if __name__ == "__main__":
    main()
