def map_healthapp_to_ecs(entry):
    return {
        "@timestamp": entry.get("timestamp"),
        "event.category": "health",
        "event.action": entry.get("event"),
        "user.id": entry.get("user_id"),
        "message": entry.get("message")
    }