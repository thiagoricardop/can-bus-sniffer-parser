"""Parse raw CAN frames and decode their signals using a DBC database."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import cantools


@dataclass
class ParsedFrame:
    """A single CAN frame, optionally decoded into named signals."""

    timestamp: float
    arbitration_id: int
    dlc: int
    data: bytes
    name: Optional[str] = None
    signals: dict[str, Any] = field(default_factory=dict)

    @property
    def arbitration_id_hex(self) -> str:
        return f"0x{self.arbitration_id:X}"


class CanParser:
    """Turns raw CAN frames into :class:`ParsedFrame` objects.

    When a DBC file is provided, known frames are decoded into physical
    signal values; unknown frames are returned without signals.
    """

    def __init__(self, dbc_path: Optional[str] = None) -> None:
        self._db = None
        if dbc_path:
            self.load_dbc(dbc_path)

    def load_dbc(self, dbc_path: str) -> None:
        self._db = cantools.database.load_file(dbc_path)

    def parse(self, timestamp: float, arbitration_id: int, data: bytes) -> ParsedFrame:
        data = bytes(data)
        frame = ParsedFrame(
            timestamp=timestamp,
            arbitration_id=arbitration_id,
            dlc=len(data),
            data=data,
        )
        if self._db is not None:
            try:
                message = self._db.get_message_by_frame_id(arbitration_id)
                frame.name = message.name
                frame.signals = dict(self._db.decode_message(arbitration_id, data))
            except KeyError:
                # Unknown arbitration ID: leave name/signals empty.
                pass
            except Exception:
                # Malformed payload for a known message: keep the raw frame.
                pass
        return frame
