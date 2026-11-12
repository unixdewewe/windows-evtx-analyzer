"""Low-level .evtx chunk & record iteration."""

import os
from typing import Iterator
from Evtx.Evtx import Evtx


class EvtxIngester:
    """Safely opens .evtx files and yields raw XML event records."""

    def __init__(self, file_path: str):
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"EVTX file not found: {file_path}")
        self.file_path = file_path
        self.filename = os.path.basename(file_path)

    def iter_records(self) -> Iterator[str]:
        """Yields raw XML strings from the .evtx file chunks."""
        with Evtx(self.file_path) as evtx:
            for record in evtx.records():
                try:
                    yield record.xml()
                except Exception:
                    continue
