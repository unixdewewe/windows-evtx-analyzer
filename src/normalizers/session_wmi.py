"""TerminalServices (RDP), Winlogon, and WMI-Activity log normalizer."""

from typing import Any, Dict
from src.normalizers.base import BaseNormalizer


class SessionWmiNormalizer(BaseNormalizer):
    def normalize(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        event = self.base_schema(raw_event, category="Session/WMI")
        eid = raw_event.get("EventID")
        data = raw_event.get("EventData", {})
        user_data = raw_event.get("UserData", {})

        event["user"] = data.get("User") or user_data.get("User")
        event["source_ip"] = data.get("Address") or user_data.get("Address")
        operation = user_data.get("Operation") or data.get("Operation")
        event["summary"] = (
            f"Session/WMI Event {eid}: User={event['user']} IP={event['source_ip']} Op={operation}"
        )
        return event
