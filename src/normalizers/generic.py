"""Universal fallback normalizer for all unmapped .evtx channels."""

from typing import Any, Dict
from src.normalizers.base import BaseNormalizer


class GenericNormalizer(BaseNormalizer):
    """Fallback normalizer ensuring zero data loss across auxiliary .evtx files."""

    def normalize(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        event = self.base_schema(raw_event, category="General/Operational")
        data = raw_event.get("EventData", {})
        user_data = raw_event.get("UserData", {})
        combined = {**data, **user_data}
        preview = ", ".join(f"{k}={v}" for k, v in list(combined.items())[:4] if v)
        event["summary"] = f"Event {event['event_id']} ({event['provider']}): {preview}"
        return event
