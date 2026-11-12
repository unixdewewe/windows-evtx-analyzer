"""Abstract base normalizer interface."""

from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseNormalizer(ABC):
    """Base contract for all Windows Event Log channel normalizers."""

    def base_schema(self, raw_event: Dict[str, Any], category: str) -> Dict[str, Any]:
        """Creates the baseline unified forensic event schema."""
        return {
            "timestamp": raw_event.get("TimeCreated"),
            "computer": raw_event.get("Computer"),
            "channel": raw_event.get("Channel"),
            "provider": raw_event.get("Provider"),
            "source_file": raw_event.get("source_file"),
            "event_id": raw_event.get("EventID"),
            "record_id": raw_event.get("EventRecordID"),
            "category": category,
            "summary": "",
            "user": None,
            "target_user": None,
            "logon_id": None,
            "logon_guid": None,
            "source_ip": None,
            "destination_ip": None,
            "process_name": None,
            "parent_process": None,
            "command_line": None,
            "process_guid": None,
            "parent_process_guid": None,
            "raw_data": raw_event.get("EventData", {}),
            "user_data": raw_event.get("UserData", {}),
        }

    @abstractmethod
    def normalize(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Normalizes a raw parsed event dictionary into the unified schema."""
        raise NotImplementedError
