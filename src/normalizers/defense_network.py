"""Windows Defender, Firewall, DNS, and Bits-Client log normalizer."""

from typing import Any, Dict
from src.normalizers.base import BaseNormalizer


class DefenseNetworkNormalizer(BaseNormalizer):
    def normalize(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        event = self.base_schema(raw_event, category="Defense/Network")
        eid = raw_event.get("EventID")
        data = raw_event.get("EventData", {})

        url = data.get("url") or data.get("RemoteName") or data.get("Path")
        threat = data.get("Threat Name") or data.get("ThreatName")
        if url:
            event["command_line"] = url
        event["summary"] = f"Defense/Network Event {eid}: Threat={threat} URL/Path={url}"
        return event
