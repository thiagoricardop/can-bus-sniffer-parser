"""Generate CAN traffic (normal + attack) on a bus, for hardware-free demos."""

from __future__ import annotations

import time
from typing import Optional

import can


class TrafficSimulator:
    """Publishes frames onto a (usually virtual) CAN bus.

    If a ``cantools`` database is supplied, normal frames are encoded from
    physical signal values; otherwise fixed raw payloads are sent.
    """

    def __init__(
        self,
        channel: str = "vcan0",
        interface: str = "virtual",
        database=None,
    ) -> None:
        self.bus = can.Bus(interface=interface, channel=channel)
        self.db = database

    def _message(self, name, frame_id, signals, raw) -> can.Message:
        if self.db is not None:
            message = self.db.get_message_by_name(name)
            data = message.encode(signals)
            return can.Message(
                arbitration_id=message.frame_id, data=data, is_extended_id=False
            )
        return can.Message(arbitration_id=frame_id, data=raw, is_extended_id=False)

    def send_normal(self, count: int = 20, delay: float = 0.02) -> None:
        for i in range(count):
            self.bus.send(
                self._message(
                    "EngineData",
                    0x100,
                    {"EngineRPM": 800 + i, "EngineTemp": 90, "ThrottlePos": 20},
                    b"\x20\x0c\x32\x00\x00\x00\x00\x00",
                )
            )
            self.bus.send(
                self._message(
                    "VehicleSpeed",
                    0x200,
                    {"Speed": 50.0},
                    b"\x88\x13\x00\x00\x00\x00\x00\x00",
                )
            )
            time.sleep(delay)

    def inject_attack(self, count: int = 100, delay: float = 0.001) -> None:
        """Flood the bus with a spoofed, unknown arbitration ID."""
        for _ in range(count):
            self.bus.send(
                can.Message(
                    arbitration_id=0x666,
                    data=b"\xff\xff\xff\xff\xff\xff\xff\xff",
                    is_extended_id=False,
                )
            )
            time.sleep(delay)

    def shutdown(self) -> None:
        self.bus.shutdown()
