def map_linux_to_ecs(entry):
    return {
        "@timestamp": entry.get("timestamp"),
        "host.name": entry.get("hostname"),
        "process.name": entry.get("process_name"),
        "log.level": entry.get("level"),
        "message": entry.get("message")
    }