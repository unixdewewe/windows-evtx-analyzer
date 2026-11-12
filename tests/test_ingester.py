"""Unit tests for EvtxIngester."""

import pytest
from src.core.ingester import EvtxIngester


def test_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        EvtxIngester("nonexistent.evtx")
