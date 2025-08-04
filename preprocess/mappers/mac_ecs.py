def map_mac_to_ecs(entry):
    return {
        "@timestamp": entry.get("timestamp"),
        "host.name": entry.get("hostname"),
        "process.name": entry.get("process_name"),
        "log.level": entry.get("level"),
        "event.module": "macos",
        "message": entry.get("message")
    }