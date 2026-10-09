"""Tests for the intrusion-detection rules."""

from can_sniffer.ids import IntrusionDetector
from can_sniffer.parser import ParsedFrame


def make_frame(frame_id, ts=0.0, signals=None):
    return ParsedFrame(
        timestamp=ts,
        arbitration_id=frame_id,
        dlc=8,
        data=b"\x00" * 8,
        signals=signals or {},
    )


def test_unknown_id_triggers_alert():
    detector = IntrusionDetector(allowed_ids=[0x100])
    alerts = detector.inspect(make_frame(0x200))
    assert any(a.rule == "UNKNOWN_ID" for a in alerts)


def test_known_id_produces_no_alert():
    detector = IntrusionDetector(allowed_ids=[0x100])
    assert detector.inspect(make_frame(0x100)) == []


def test_signal_out_of_range():
    detector = IntrusionDetector(signal_ranges={"EngineRPM": (0, 8000)})
    alerts = detector.inspect(make_frame(0x100, signals={"EngineRPM": 9000}))
    assert any(a.rule == "SIGNAL_RANGE" for a in alerts)


def test_signal_in_range_is_ok():
    detector = IntrusionDetector(signal_ranges={"EngineRPM": (0, 8000)})
    alerts = detector.inspect(make_frame(0x100, signals={"EngineRPM": 2000}))
    assert alerts == []


def test_flood_detection():
    detector = IntrusionDetector(flood_window=1.0, flood_threshold=5)
    alerts = []
    for i in range(10):
        alerts = detector.inspect(make_frame(0x100, ts=i * 0.01))
    assert any(a.rule == "FLOOD" for a in alerts)


def test_old_frames_leave_flood_window():
    detector = IntrusionDetector(flood_window=1.0, flood_threshold=3)
    # Spread frames more than one second apart: window never fills up.
    for i in range(10):
        alerts = detector.inspect(make_frame(0x100, ts=i * 2.0))
    assert all(a.rule != "FLOOD" for a in alerts)
