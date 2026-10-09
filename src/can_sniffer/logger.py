"""Structured logging for frames and IDS alerts (console / CSV / JSON Lines)."""

from __future__ import annotations

import csv
import json
import sys
from typing import Any, Optional, TextIO

from .ids import Alert
from .parser import ParsedFrame


def _to_jsonable(value: Any) -> Any:
    try:
        return float(value)
    except (TypeError, ValueError):
        return str(value)


class EventLogger:
    """Writes parsed frames and alerts to the console and, optionally, files."""

    def __init__(
        self,
        stream: Optional[TextIO] = None,
        csv_path: Optional[str] = None,
        json_path: Optional[str] = None,
    ) -> None:
        self.stream = stream if stream is not None else sys.stdout
        self._csv_file = None
        self._csv_writer = None
        self._json_file = None

        if csv_path:
            self._csv_file = open(csv_path, "w", newline="", encoding="utf-8")
            self._csv_writer = csv.writer(self._csv_file)
            self._csv_writer.writerow(
                ["timestamp", "id", "dlc", "name", "signals", "data"]
            )
        if json_path:
            self._json_file = open(json_path, "w", encoding="utf-8")

    def log_frame(self, frame: ParsedFrame) -> None:
        signals = {k: _to_jsonable(v) for k, v in frame.signals.items()}
        print(
            f"[{frame.timestamp:.3f}] {frame.arbitration_id_hex} "
            f"({frame.dlc}) {frame.name or 'UNKNOWN'} {signals}",
            file=self.stream,
        )
        if self._csv_writer:
            self._csv_writer.writerow(
                [
                    frame.timestamp,
                    frame.arbitration_id_hex,
                    frame.dlc,
                    frame.name or "",
                    json.dumps(signals),
                    frame.data.hex(),
                ]
            )
        if self._json_file:
            self._json_file.write(
                json.dumps(
                    {
                        "type": "frame",
                        "timestamp": frame.timestamp,
                        "id": frame.arbitration_id_hex,
                        "dlc": frame.dlc,
                        "name": frame.name,
                        "signals": signals,
                        "data": frame.data.hex(),
                    }
                )
                + "\n"
            )

    def log_alert(self, alert: Alert) -> None:
        print(
            f"[{alert.timestamp:.3f}] ALERT {alert.rule} "
            f"{alert.arbitration_id_hex}: {alert.detail}",
            file=self.stream,
        )
        if self._json_file:
            self._json_file.write(
                json.dumps(
                    {
                        "type": "alert",
                        "timestamp": alert.timestamp,
                        "id": alert.arbitration_id_hex,
                        "rule": alert.rule,
                        "detail": alert.detail,
                    }
                )
                + "\n"
            )

    def close(self) -> None:
        if self._csv_file:
            self._csv_file.close()
        if self._json_file:
            self._json_file.close()
