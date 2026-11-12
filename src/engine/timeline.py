"""Unified UTC timeline sorting & filtering."""

from typing import Any, Dict, List, Optional


class TimelineBuilder:
    """Aggregates, filters, and chronologically sorts normalized forensic events."""

    def __init__(self):
        self.events: List[Dict[str, Any]] = []

    def add_events(self, events: List[Dict[str, Any]]) -> None:
        self.events.extend(events)

    def build(
        self,
        event_ids: Optional[List[int]] = None,
        keyword: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Returns sorted timeline events optionally filtered by EventID or keyword."""
        filtered = self.events

        if event_ids:
            id_set = set(event_ids)
            filtered = [e for e in filtered if e.get("event_id") in id_set]

        if keyword:
            kw = keyword.lower()
            filtered = [
                e for e in filtered
                if kw in str(e.get("summary", "")).lower()
                or kw in str(e.get("command_line", "")).lower()
                or kw in str(e.get("raw_data", "")).lower()
            ]

        return sorted(filtered, key=lambda x: x.get("timestamp") or "")
