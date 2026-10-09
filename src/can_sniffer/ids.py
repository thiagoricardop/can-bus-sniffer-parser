"""Intrusion-detection rules for CAN traffic."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Iterable, Optional

from .parser import ParsedFrame


@dataclass
class Alert:
    """A single IDS finding for one frame."""

    timestamp: float
    arbitration_id: int
    rule: str
    detail: str

    @property
    def arbitration_id_hex(self) -> str:
        return f"0x{self.arbitration_id:X}"


class IntrusionDetector:
    """Stateful detector that inspects frames one at a time.

    Rules:
        * ``UNKNOWN_ID``   - arbitration ID not in the allowlist.
        * ``SIGNAL_RANGE`` - a decoded signal is outside its valid range.
        * ``FLOOD``        - too many frames for one ID within a time window.
    """

    def __init__(
        self,
        allowed_ids: Optional[Iterable[int]] = None,
        signal_ranges: Optional[dict[str, tuple[float, float]]] = None,
        flood_window: float = 1.0,
        flood_threshold: int = 50,
    ) -> None:
        self.allowed_ids = set(allowed_ids) if allowed_ids is not None else None
        self.signal_ranges = signal_ranges or {}
        self.flood_window = flood_window
        self.flood_threshold = flood_threshold
        self._timestamps: dict[int, deque] = defaultdict(deque)

    def inspect(self, frame: ParsedFrame) -> list[Alert]:
        alerts: list[Alert] = []

        if self.allowed_ids is not None and frame.arbitration_id not in self.allowed_ids:
            alerts.append(
                Alert(
                    frame.timestamp,
                    frame.arbitration_id,
                    "UNKNOWN_ID",
                    f"Arbitration ID {frame.arbitration_id_hex} not in allowlist",
                )
            )

        for signal, value in frame.signals.items():
            if signal not in self.signal_ranges:
                continue
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                continue
            low, high = self.signal_ranges[signal]
            if numeric < low or numeric > high:
                alerts.append(
                    Alert(
                        frame.timestamp,
                        frame.arbitration_id,
                        "SIGNAL_RANGE",
                        f"{signal}={numeric} outside [{low}, {high}]",
                    )
                )

        window = self._timestamps[frame.arbitration_id]
        window.append(frame.timestamp)
        while window and frame.timestamp - window[0] > self.flood_window:
            window.popleft()
        if len(window) > self.flood_threshold:
            alerts.append(
                Alert(
                    frame.timestamp,
                    frame.arbitration_id,
                    "FLOOD",
                    f"{len(window)} frames in {self.flood_window}s window",
                )
            )

        return alerts
