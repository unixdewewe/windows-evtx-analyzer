"""Security.evtx normalizer (Logon, PrivEsc, Account Management, Process Creation)."""

from typing import Any, Dict
from src.normalizers.base import BaseNormalizer


class SecurityNormalizer(BaseNormalizer):
    LOGON_TYPES = {
        "2": "Interactive",
        "3": "Network",
        "4": "Batch",
        "5": "Service",
        "7": "Unlock",
        "8": "NetworkCleartext",
        "9": "NewCredentials",
        "10": "RemoteInteractive (RDP)",
        "11": "CachedInteractive",
    }

    def normalize(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        event = self.base_schema(raw_event, category="Security")
        eid = raw_event.get("EventID")
        data = raw_event.get("EventData", {})

        if eid in (4624, 4625):
            status = "Success" if eid == 4624 else "Failed"
            ltype = str(data.get("LogonType", ""))
            ltype_desc = self.LOGON_TYPES.get(ltype, ltype)
            event["target_user"] = data.get("TargetUserName")
            event["user"] = data.get("SubjectUserName")
            event["source_ip"] = data.get("IpAddress")
            event["logon_id"] = data.get("TargetLogonId")
            event["logon_guid"] = data.get("LogonGuid")
            event["summary"] = (
                f"Logon {status} ({ltype_desc}) for {event['target_user']} from {event['source_ip']}"
            )
        elif eid == 4648:
            event["user"] = data.get("SubjectUserName")
            event["target_user"] = data.get("TargetUserName")
            event["source_ip"] = data.get("IpAddress")
            event["process_name"] = data.get("ProcessName")
            event["summary"] = f"Explicit Credential Logon by {event['user']} as {event['target_user']}"
        elif eid == 4672:
            event["user"] = data.get("SubjectUserName")
            event["logon_id"] = data.get("SubjectLogonId")
            event["summary"] = f"Special Privileges Assigned to {event['user']}: {data.get('PrivilegeList')}"
        elif eid == 4688:
            event["user"] = data.get("SubjectUserName")
            event["logon_id"] = data.get("SubjectLogonId")
            event["process_name"] = data.get("NewProcessName")
            event["parent_process"] = data.get("ParentProcessName")
            event["command_line"] = data.get("CommandLine")
            event["summary"] = f"Process Created: {event['process_name']} | Cmd: {event['command_line']}"
        elif eid in (4720, 4728, 4732, 4756):
            event["user"] = data.get("SubjectUserName")
            event["target_user"] = data.get("TargetUserName") or data.get("MemberName")
            event["summary"] = f"Account/Group Change (ID {eid}) affecting {event['target_user']}"
        elif eid == 1102:
            event["user"] = data.get("SubjectUserName")
            event["summary"] = f"ALERT: Security Audit Log Cleared by {event['user']}"
        else:
            event["summary"] = f"Security Event {eid}"

        return event
