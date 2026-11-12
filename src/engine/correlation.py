"""State machine for process trees & session pivoting."""

from typing import Any, Dict, List


class CorrelationEngine:
    """Links events by ProcessGuid, LogonId, and LogonGuid across log channels."""

    def __init__(self):
        self.process_tree: Dict[str, Dict[str, Any]] = {}
        self.logon_sessions: Dict[str, List[Dict[str, Any]]] = {}

    def correlate(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Builds process lineage and attaches session context to events."""
        for ev in events:
            p_guid = ev.get("process_guid")
            if p_guid and ev.get("event_id") == 1:
                self.process_tree[p_guid] = {
                    "image": ev.get("process_name"),
                    "parent_image": ev.get("parent_process"),
                    "parent_guid": ev.get("parent_process_guid"),
                    "command_line": ev.get("command_line"),
                    "timestamp": ev.get("timestamp"),
                }

            logon_id = ev.get("logon_id")
            if logon_id:
                self.logon_sessions.setdefault(logon_id, []).append(ev)

        return events
