"""
main.py - Real-Time Covert Channel Detector (Main Entry Point)

Starts the packet sniffer and detection engine.
Run this first before launching the sender scripts.

Usage:
    sudo python3 main.py          (from the project root directory)

Or with an explicit interface:
    sudo python3 main.py --iface eth0

Press Ctrl+C to stop detection and view statistics.
"""

import sys
import os
import time
import argparse
import signal

# ── Ensure we can import the detector package from project root ──────────────
# Add the project root to Python's path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# ── Import checker ────────────────────────────────────────────────────────────
try:
    from scapy.all import conf as scapy_conf
except ImportError:
    print("[ERROR] Scapy is not installed.")
    print("        Fix: pip install scapy")
    sys.exit(1)

try:
    import yaml
except ImportError:
    print("[WARN]  PyYAML not installed. Using default config.")
    print("        Optional fix: pip install pyyaml")

# ── Local imports ─────────────────────────────────────────────────────────────
from detector.utils           import load_config, get_timestamp
from detector.logger          import AlertLogger
from detector.detection_engine import DetectionEngine
from detector.packet_sniffer  import PacketSniffer


# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────

BANNER = r"""
╔══════════════════════════════════════════════════════════╗
║     REAL-TIME COVERT CHANNEL DETECTION SYSTEM            ║
║     Network Traffic Analysis | Minor Project             ║
╠══════════════════════════════════════════════════════════╣
║  Detects: ICMP Covert Channels | DNS Tunneling           ║
║  Author : Minor Project Team                             ║
╚══════════════════════════════════════════════════════════╝
"""


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Real-Time Covert Channel Detector"
    )
    parser.add_argument(
        "--iface", "-i",
        type=str,
        default=None,
        help="Network interface to sniff on (e.g. eth0, wlan0, lo)"
    )
    parser.add_argument(
        "--config", "-c",
        type=str,
        default=None,
        help="Path to config.yaml (default: detector/config.yaml)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show all captured packets, not just alerts"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Print the banner
    print(BANNER)

    # ── Load configuration ────────────────────────────────────────────────
    config_path = args.config or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "config.yaml"
    )
    config = load_config(config_path)

    # Command-line overrides
    if args.iface:
        config["interface"] = args.iface
    if args.verbose:
        config["show_all_packets"] = True

    # ── Set up the log file path relative to project root ─────────────────
    log_file = os.path.join(project_root, config.get("log_file", "logs/alerts.log"))
    config["log_file"] = log_file

    # ── Initialize components ─────────────────────────────────────────────
    print(f"[INIT] Starting detector at {get_timestamp()}")
    print(f"[INIT] Log file: {log_file}\n")

    logger   = AlertLogger(log_file=log_file)
    engine   = DetectionEngine(config=config, logger=logger)
    sniffer  = PacketSniffer(engine=engine, config=config)

    # ── Graceful shutdown on Ctrl+C ───────────────────────────────────────
    def shutdown(signum, frame):
        print("\n\n[STOP] Ctrl+C received. Shutting down detector...")
        sniffer.stop()
        engine.print_stats()
        logger.close()
        print(f"\n[DONE] Alerts saved to: {log_file}")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # ── Start sniffing ────────────────────────────────────────────────────
    sniffer.start()

    print("[INFO] Detection engine is ACTIVE.")
    print("[INFO] Waiting for packets... (Press Ctrl+C to stop)\n")
    print(f"{'─' * 65}")
    print(f"{'TIMESTAMP':<22} {'SEV':<10} {'PROTO':<6} {'SOURCE':<18} DETAILS")
    print(f"{'─' * 65}\n")

    # ── Keep main thread alive ────────────────────────────────────────────
    while sniffer.is_running():
        time.sleep(0.5)

    # If sniffer stopped unexpectedly
    print("\n[WARN] Sniffer stopped unexpectedly.")
    engine.print_stats()
    logger.close()


if __name__ == "__main__":
    main()
