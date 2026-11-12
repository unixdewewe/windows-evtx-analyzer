"""Flat CSV export for spreadsheet analysis."""

import csv
from typing import Any, Dict, List


class CSVExporter:
    FIELDNAMES = [
        "timestamp",
        "computer",
        "channel",
        "event_id",
        "category",
        "user",
        "target_user",
        "source_ip",
        "destination_ip",
        "logon_id",
        "logon_guid",
        "process_name",
        "parent_process",
        "command_line",
        "summary",
        "source_file",
    ]

    @classmethod
    def export(cls, events: List[Dict[str, Any]], output_path: str) -> None:
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=cls.FIELDNAMES, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(events)
