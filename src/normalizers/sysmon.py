"""Sysmon operational telemetry normalizer (Process, Network, File, DNS)."""

from typing import Any, Dict
from src.normalizers.base import BaseNormalizer


class SysmonNormalizer(BaseNormalizer):
    def normalize(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        event = self.base_schema(raw_event, category="Sysmon")
        eid = raw_event.get("EventID")
        data = raw_event.get("EventData", {})

        event["user"] = data.get("User")
        event["process_name"] = data.get("Image")
        event["process_guid"] = data.get("ProcessGuid")

        if eid == 1:
            event["parent_process"] = data.get("ParentImage")
            event["parent_process_guid"] = data.get("ParentProcessGuid")
            event["command_line"] = data.get("CommandLine")
            event["logon_id"] = data.get("LogonId")
            event["logon_guid"] = data.get("LogonGuid")
            event["summary"] = f"Sysmon Process Create: {event['process_name']} | Cmd: {event['command_line']}"
        elif eid == 3:
            event["source_ip"] = data.get("SourceIp")
            event["destination_ip"] = data.get("DestinationIp")
            dst_port = data.get("DestinationPort")
            event["summary"] = f"Network Connect: {event['process_name']} -> {event['destination_ip']}:{dst_port}"
        elif eid == 11:
            target_file = data.get("TargetFilename")
            event["summary"] = f"File Created: {target_file} by {event['process_name']}"
        elif eid == 22:
            query = data.get("QueryName")
            result = data.get("QueryResults")
            event["summary"] = f"DNS Query: {query} -> {result} (Process: {event['process_name']})"
        else:
            event["summary"] = f"Sysmon Event {eid}"

        return event
