"""Tests for the live sniffer using python-can's virtual bus."""

import can

from can_sniffer.ids import IntrusionDetector
from can_sniffer.parser import CanParser
from can_sniffer.sniffer import CanSniffer


def test_process_message_on_virtual_bus():
    sniffer = CanSniffer(
        CanParser(),
        IntrusionDetector(allowed_ids=[0x100]),
        interface="virtual",
        channel="test-sniffer",
    )
    bus = sniffer.open()
    sender = can.Bus(interface="virtual", channel="test-sniffer")
    try:
        sender.send(
            can.Message(arbitration_id=0x100, data=b"\x01\x02", is_extended_id=False)
        )
        msg = bus.recv(timeout=2.0)
        assert msg is not None
        frame, alerts = sniffer.process_message(msg)
        assert frame.arbitration_id == 0x100
        assert frame.dlc == 2
        assert alerts == []
    finally:
        sender.shutdown()
        sniffer.close()


def test_stream_stops_on_limit():
    sniffer = CanSniffer(CanParser(), interface="virtual", channel="test-limit")
    bus = sniffer.open()  # noqa: F841 - opens the channel for the sender below
    sender = can.Bus(interface="virtual", channel="test-limit")
    try:
        for _ in range(3):
            sender.send(
                can.Message(arbitration_id=0x100, data=b"\x00", is_extended_id=False)
            )
        received = list(sniffer.stream(limit=2, timeout=2.0))
        assert len(received) == 2
    finally:
        sender.shutdown()
        sniffer.close()


def test_unknown_id_detected_on_virtual_bus():
    sniffer = CanSniffer(
        CanParser(),
        IntrusionDetector(allowed_ids=[0x100]),
        interface="virtual",
        channel="test-attack",
    )
    bus = sniffer.open()
    sender = can.Bus(interface="virtual", channel="test-attack")
    try:
        sender.send(
            can.Message(arbitration_id=0x666, data=b"\xff", is_extended_id=False)
        )
        msg = bus.recv(timeout=2.0)
        _, alerts = sniffer.process_message(msg)
        assert any(a.rule == "UNKNOWN_ID" for a in alerts)
    finally:
        sender.shutdown()
        sniffer.close()
