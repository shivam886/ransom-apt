def map_android_to_ecs(entry):
    return {
        "@timestamp": entry.get("timestamp"),
        "process.name": entry.get("process_name"),
        "event.module": "android",
        "event.action": entry.get("event"),
        "log.level": entry.get("level"),
        "message": entry.get("message")
    }