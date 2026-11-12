"""Unit tests for EventParser."""

from src.core.parser import EventParser


def test_parse_sample_xml():
    sample_xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <Provider Name="Microsoft-Windows-Security-Auditing" />
            <EventID>4624</EventID>
            <TimeCreated SystemTime="2026-03-10T00:09:00.000000Z" />
            <Computer>SQLSVR01</Computer>
        </System>
        <EventData>
            <Data Name="TargetUserName">Administrator</Data>
            <Data Name="LogonType">10</Data>
        </EventData>
    </Event>"""
    parsed = EventParser.parse_record(sample_xml, source_file="Security.evtx")
    assert parsed["EventID"] == 4624
    assert parsed["Computer"] == "SQLSVR01"
    assert parsed["EventData"]["TargetUserName"] == "Administrator"
