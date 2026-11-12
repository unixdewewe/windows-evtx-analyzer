"""Unit tests for NormalizerRegistry, ForensicStorage, and SigmaEngine."""

import os
import tempfile
from src.normalizers.registry import NormalizerRegistry
from src.core.storage import ForensicStorage
from src.hunting.sigma_engine import SigmaEngine


def test_registry_routing():
    reg = NormalizerRegistry()
    assert reg.get_normalizer("Security.evtx").__class__.__name__ == "SecurityNormalizer"
    assert reg.get_normalizer("HardwareEvents.evtx").__class__.__name__ == "GenericNormalizer"


def test_sqlite_fts5_storage():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name
    try:
        storage = ForensicStorage(db_path)
        storage.insert_batch([
            {
                "timestamp": "2026-03-10T00:10:00Z",
                "computer": "SQLSVR01",
                "channel": "Security",
                "provider": "Microsoft-Windows-Security-Auditing",
                "source_file": "Security.evtx",
                "event_id": 4688,
                "record_id": 101,
                "category": "Security",
                "summary": "Process Created: cmd.exe",
                "command_line": "powershell.exe -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwA=",
                "raw_data": {"CommandLine": "powershell.exe -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwA="},
            }
        ])
        hits = storage.search_fts("powershell")
        assert len(hits) == 1
        assert hits[0]["event_id"] == 4688
        storage.close()
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_sigma_engine_dcsync():
    engine = SigmaEngine("windows_evtx_analyzer/rules")
    sample_event = {
        "timestamp": "2026-03-10T01:00:00Z",
        "computer": "DC01",
        "channel": "Security",
        "source_file": "Security.evtx",
        "event_id": 4662,
        "user": "attacker_svc",
        "summary": "DS Object Access",
        "raw_data": {
            "SubjectUserName": "attacker_svc",
            "Properties": "%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}",
        },
    }
    alerts = engine.scan_event(sample_event)
    assert len(alerts) == 1
    assert "DCSync" in alerts[0]["rule_title"]
