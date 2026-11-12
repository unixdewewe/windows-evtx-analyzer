"""Structured JSON timeline export."""

import json
from typing import Any, Dict, List


class JSONExporter:
    @staticmethod
    def export(events: List[Dict[str, Any]], output_path: str) -> None:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2, default=str)
