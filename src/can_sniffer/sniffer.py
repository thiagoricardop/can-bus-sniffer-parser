"""Read CAN frames from a bus and run them through the parser and IDS."""

from __future__ import annotations

from typing import Iterator, Optional

import can

from .ids import Alert, IntrusionDetector
from .parser import CanParser, ParsedFrame


class CanSniffer:
    """Opens a CAN bus and yields parsed frames with any IDS alerts."""

    def __init__(
        self,
        parser: CanParser,
        detector: Optional[IntrusionDetector] = None,
        interface: str = "virtual",
        channel: str = "vcan0",
        bitrate: int = 500000,
    ) -> None:
        self.parser = parser
        self.detector = detector
        self.interface = interface
        self.channel = channel
        self.bitrate = bitrate
        self._bus: Optional[can.BusABC] = None

    def open(self) -> can.BusABC:
        kwargs = {"interface": self.interface, "channel": self.channel}
        if self.interface != "virtual":
            kwargs["bitrate"] = self.bitrate
        self._bus = can.Bus(**kwargs)
        return self._bus

    def close(self) -> None:
        if self._bus is not None:
            self._bus.shutdown()
            self._bus = None

    def process_message(self, msg: can.Message) -> tuple[ParsedFrame, list[Alert]]:
        frame = self.parser.parse(msg.timestamp, msg.arbitration_id, msg.data)
        alerts = self.detector.inspect(frame) if self.detector else []
        return frame, alerts

    def stream(
        self,
        limit: Optional[int] = None,
        timeout: float = 1.0,
        stop_on_idle: bool = False,
    ) -> Iterator[tuple[ParsedFrame, list[Alert]]]:
        if self._bus is None:
            raise RuntimeError("Bus not open. Call open() first.")
        count = 0
        while True:
            msg = self._bus.recv(timeout=timeout)
            if msg is None:
                if stop_on_idle:
                    break
                continue
            yield self.process_message(msg)
            count += 1
            if limit is not None and count >= limit:
                break
