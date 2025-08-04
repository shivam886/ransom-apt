def map_hdfs_to_ecs(entry):
    return {
        "@timestamp": entry.get("timestamp"),
        "source.ip": entry.get("source_ip"),
        "destination.ip": entry.get("destination_ip"),
        "event.category": "file",
        "event.action": entry.get("action"),
        "message": entry.get("message")
    }