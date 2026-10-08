"""Tests for the CAN frame parser and DBC decoding."""

import os

import cantools

from can_sniffer.parser import CanParser

DBC_PATH = os.path.join(os.path.dirname(__file__), "..", "dbc", "sample.dbc")


def test_parse_without_dbc():
    parser = CanParser()
    frame = parser.parse(1.0, 0x100, b"\x01\x02\x03\x04")
    assert frame.arbitration_id == 0x100
    assert frame.dlc == 4
    assert frame.name is None
    assert frame.signals == {}


def test_arbitration_id_hex():
    parser = CanParser()
    frame = parser.parse(0.0, 0x100, b"")
    assert frame.arbitration_id_hex == "0x100"


def test_parse_with_dbc_roundtrip():
    database = cantools.database.load_file(DBC_PATH)
    data = database.encode_message(
        "EngineData", {"EngineRPM": 2000, "EngineTemp": 90, "ThrottlePos": 20}
    )
    parser = CanParser(DBC_PATH)
    frame = parser.parse(1.0, 0x100, data)
    assert frame.name == "EngineData"
    assert round(frame.signals["EngineRPM"]) == 2000
    assert round(frame.signals["EngineTemp"]) == 90
    assert round(frame.signals["ThrottlePos"]) == 20


def test_unknown_id_with_dbc_has_no_signals():
    parser = CanParser(DBC_PATH)
    frame = parser.parse(1.0, 0x666, b"\xff\xff\xff\xff\xff\xff\xff\xff")
    assert frame.name is None
    assert frame.signals == {}
