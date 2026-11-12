"""BinXML extraction & XML-to-dict mapping."""

import xml.etree.ElementTree as ET
from typing import Any, Dict


class EventParser:
    """Parses raw Windows Event XML strings into standardized Python dictionaries."""

    NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

    @classmethod
    def parse_record(cls, xml_string: str, source_file: str = "") -> Dict[str, Any]:
        """Converts raw XML record into a structured dictionary."""
        root = ET.fromstring(xml_string)
        system = root.find(f"{cls.NS}System")

        parsed: Dict[str, Any] = {
            "source_file": source_file,
            "Provider": None,
            "EventID": None,
            "Version": None,
            "Level": None,
            "Task": None,
            "Opcode": None,
            "Keywords": None,
            "TimeCreated": None,
            "EventRecordID": None,
            "ProcessID": None,
            "ThreadID": None,
            "Channel": None,
            "Computer": None,
            "SecurityUserID": None,
            "EventData": {},
            "UserData": {},
        }

        if system is not None:
            provider = system.find(f"{cls.NS}Provider")
            if provider is not None:
                parsed["Provider"] = provider.attrib.get("Name")

            event_id = system.find(f"{cls.NS}EventID")
            if event_id is not None and event_id.text:
                parsed["EventID"] = int(event_id.text)

            time_created = system.find(f"{cls.NS}TimeCreated")
            if time_created is not None:
                parsed["TimeCreated"] = time_created.attrib.get("SystemTime")

            record_id = system.find(f"{cls.NS}EventRecordID")
            if record_id is not None and record_id.text:
                parsed["EventRecordID"] = int(record_id.text)

            execution = system.find(f"{cls.NS}Execution")
            if execution is not None:
                parsed["ProcessID"] = execution.attrib.get("ProcessID")
                parsed["ThreadID"] = execution.attrib.get("ThreadID")

            channel = system.find(f"{cls.NS}Channel")
            if channel is not None:
                parsed["Channel"] = channel.text

            computer = system.find(f"{cls.NS}Computer")
            if computer is not None:
                parsed["Computer"] = computer.text

            security = system.find(f"{cls.NS}Security")
            if security is not None:
                parsed["SecurityUserID"] = security.attrib.get("UserID")

        event_data = root.find(f"{cls.NS}EventData")
        if event_data is not None:
            unnamed_idx = 0
            for data in event_data:
                name = data.attrib.get("Name")
                if name:
                    parsed["EventData"][name] = data.text
                else:
                    parsed["EventData"][f"Data_{unnamed_idx}"] = data.text
                    unnamed_idx += 1

        user_data = root.find(f"{cls.NS}UserData")
        if user_data is not None:
            for elem in user_data.iter():
                tag = elem.tag.replace(cls.NS, "")
                if elem.text and elem.text.strip():
                    parsed["UserData"][tag] = elem.text.strip()

        return parsed
