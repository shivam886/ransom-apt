# File: preprocess/mappers/windows_wazuh_ecs.py
from typing import Dict

def map_windows_to_ecs(log: Dict) -> Dict:
    ecs = {
        "@timestamp": log.get("Time"),
        "event.code": log.get("EventID"),
        "host.name": log.get("LogHost"),
        "user.name": log.get("UserName"),
        "user.domain": log.get("DomainName"),
        "user.id": log.get("LogonID"),
        "process.name": log.get("ProcessName"),
        "process.pid": log.get("ProcessID"),
        "process.parent.name": log.get("ParentProcessName"),
        "process.parent.pid": log.get("ParentProcessID"),
        "winlog.logon.type_description": log.get("LogonTypeDescription"),
        "winlog.logon.auth_package": log.get("AuthenticationPackage")
    }
    return {k: v for k, v in ecs.items() if v is not None}


def map_wazuh_csv_row_to_ecs(row: Dict) -> Dict:
    ecs = {
        "@timestamp": row.get("_source.@timestamp") or row.get("_source.timestamp"),
        "event.provider": "wazuh",
        "event.category": "intrusion_detection",
        "host.name": row.get("_source.agent.name"),
        "host.id": row.get("_source.agent.id"),
        "orchestrator.name": row.get("_source.manager.name"),
        "event.module": row.get("_source.decoder.name"),
        "rule.id": row.get("_source.rule.id"),
        "rule.description": row.get("_source.rule.description"),
        "source.ip": row.get("_source.data.srcip"),
        "destination.ip": row.get("_source.data.dstip"),
        "source.port": row.get("_source.data.srcport"),
        "destination.port": row.get("_source.data.dstport"),
        "user.name": row.get("_source.data.user"),
        "process.command_line": row.get("_source.data.command"),
        "file.name": row.get("_source.data.file"),
        "log.level": row.get("_source.rule.level"),
    }
    return {k: v for k, v in ecs.items() if v is not None}
