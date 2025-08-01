import re

def detect_type_from_value(value):
    value = value.strip().lower()
    if re.fullmatch(r"[a-f0-9]{32}", value):
        return "md5"
    elif re.fullmatch(r"[a-f0-9]{40}", value):
        return "sha1"
    elif re.fullmatch(r"[a-f0-9]{64}", value):
        return "sha256"
    else:
        return "unknown"

def normalize_ioc(ioc):
    value = ioc.get("value", "").strip().lower()
    ioc_type = ioc.get("type") or detect_type_from_value(value)

    return {
        "type": ioc_type,
        "value": value,
        "family": ioc.get("family", "unknown"),
        "name": ioc.get("name", "unknown"),
        "source": ioc.get("source", "unknown"),
        "date": ioc.get("date"),
        "normalized": True,
        "valid": bool(value)
    }

def normalize_ioc_list(ioc_list):
    return [normalize_ioc(ioc) for ioc in ioc_list]
