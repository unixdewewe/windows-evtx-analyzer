"""Active Directory & Domain Controller normalizer (Kerberos, DCSync, AD Objects)."""

from typing import Any, Dict
from src.normalizers.base import BaseNormalizer


class DomainNormalizer(BaseNormalizer):
    def normalize(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        event = self.base_schema(raw_event, category="ActiveDirectory")
        eid = raw_event.get("EventID")
        data = raw_event.get("EventData", {})

        if eid == 4662:
            event["user"] = data.get("SubjectUserName")
            event["logon_id"] = data.get("SubjectLogonId")
            obj_name = data.get("ObjectName")
            props = data.get("Properties", "")
            event["summary"] = f"DS Object Access by {event['user']} on {obj_name} | Props: {props}"
        elif eid in (4768, 4769, 4771):
            event["target_user"] = data.get("TargetUserName")
            event["source_ip"] = data.get("IpAddress")
            service = data.get("ServiceName", "")
            enc = data.get("TicketEncryptionType", "")
            event["summary"] = (
                f"Kerberos Event {eid} for {event['target_user']} (Service: {service}, Enc: {enc}) from {event['source_ip']}"
            )
        elif eid in (5136, 5137, 5139):
            event["user"] = data.get("SubjectUserName")
            obj_dn = data.get("ObjectDN")
            attr = data.get("AttributeLDAPDisplayName", "")
            val = data.get("AttributeValue", "")
            event["summary"] = f"AD Object Change ({eid}) by {event['user']} on {obj_dn} [{attr}={val}]"
        else:
            event["summary"] = f"Domain/AD Event {eid}"

        return event
