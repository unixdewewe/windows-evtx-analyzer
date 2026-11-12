"""PowerShell operational and legacy log normalizer."""

from typing import Any, Dict
from src.normalizers.base import BaseNormalizer


class PowerShellNormalizer(BaseNormalizer):
    def normalize(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        event = self.base_schema(raw_event, category="PowerShell")
        eid = raw_event.get("EventID")
        data = raw_event.get("EventData", {})

        if eid == 4104:
            script_text = data.get("ScriptBlockText", "")
            path = data.get("Path", "Interactive/Memory")
            event["command_line"] = script_text
            event["summary"] = f"PowerShell ScriptBlock ({path}): {script_text[:120]}"
        elif eid == 4103:
            payload = data.get("Payload", "")
            event["command_line"] = payload
            event["summary"] = f"PowerShell Pipeline Execution: {payload[:120]}"
        else:
            event["summary"] = f"PowerShell Event {eid}"

        return event
