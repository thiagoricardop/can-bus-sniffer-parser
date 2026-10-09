"""Command-line interface for the CAN bus sniffer."""

from __future__ import annotations

import argparse
import threading
from typing import Optional

from .ids import IntrusionDetector
from .logger import EventLogger
from .parser import CanParser
from .simulator import TrafficSimulator
from .sniffer import CanSniffer

DEFAULT_ALLOWED_IDS = [0x100, 0x200]
DEFAULT_SIGNAL_RANGES = {
    "EngineRPM": (0, 8000),
    "EngineTemp": (-40, 150),
    "ThrottlePos": (0, 100),
    "Speed": (0, 300),
}


def _build_detector() -> IntrusionDetector:
    return IntrusionDetector(
        allowed_ids=DEFAULT_ALLOWED_IDS,
        signal_ranges=DEFAULT_SIGNAL_RANGES,
        flood_window=1.0,
        flood_threshold=40,
    )


def run_sniff(args: argparse.Namespace) -> None:
    sniffer = CanSniffer(
        CanParser(args.dbc),
        _build_detector(),
        interface=args.interface,
        channel=args.channel,
    )
    logger = EventLogger(csv_path=args.csv, json_path=args.json)
    sniffer.open()
    try:
        for frame, alerts in sniffer.stream(limit=args.limit, timeout=args.timeout):
            logger.log_frame(frame)
            for alert in alerts:
                logger.log_alert(alert)
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.close()
        logger.close()


def run_demo(args: argparse.Namespace) -> None:
    database = None
    if args.dbc:
        import cantools

        database = cantools.database.load_file(args.dbc)

    sniffer = CanSniffer(
        CanParser(args.dbc),
        _build_detector(),
        interface="virtual",
        channel=args.channel,
    )
    logger = EventLogger()
    sniffer.open()

    def producer() -> None:
        sim = TrafficSimulator(channel=args.channel, interface="virtual", database=database)
        sim.send_normal(count=10, delay=0.02)
        if args.attack:
            sim.inject_attack(count=80, delay=0.001)
        sim.shutdown()

    thread = threading.Thread(target=producer)
    thread.start()
    try:
        for frame, alerts in sniffer.stream(timeout=1.0, stop_on_idle=True):
            logger.log_frame(frame)
            for alert in alerts:
                logger.log_alert(alert)
    finally:
        thread.join()
        sniffer.close()
        logger.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="can-sniffer",
        description="CAN bus sniffer, DBC parser, and intrusion-detection demo.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sniff = sub.add_parser("sniff", help="Read and analyze frames from a CAN interface.")
    sniff.add_argument("--interface", default="virtual", help="python-can interface (e.g. socketcan).")
    sniff.add_argument("--channel", default="vcan0", help="Channel name (e.g. vcan0).")
    sniff.add_argument("--dbc", default=None, help="Path to a .dbc database for decoding.")
    sniff.add_argument("--limit", type=int, default=None, help="Stop after N frames.")
    sniff.add_argument("--timeout", type=float, default=1.0, help="recv() timeout in seconds.")
    sniff.add_argument("--csv", default=None, help="Write frames to this CSV file.")
    sniff.add_argument("--json", default=None, help="Write frames/alerts to this JSON Lines file.")
    sniff.set_defaults(func=run_sniff)

    demo = sub.add_parser("demo", help="Run a hardware-free demo on a virtual bus.")
    demo.add_argument("--channel", default="demo", help="Virtual channel name.")
    demo.add_argument("--dbc", default=None, help="Path to a .dbc database for decoding.")
    demo.add_argument("--attack", action="store_true", help="Inject a flooding/spoofing attack.")
    demo.set_defaults(func=run_demo)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
