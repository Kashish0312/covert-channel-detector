"""
packet_sniffer.py - Live Packet Sniffer using Scapy

Captures packets in real time from the network interface and
passes each packet to the DetectionEngine for analysis.

Key points:
  - Uses Scapy's sniff() function with a BPF filter for efficiency
  - Runs sniffing in a background thread so the main program stays responsive
  - Captures on the best available interface (auto-detected or user-specified)
"""

import sys
import time
import threading

try:
    from scapy.all import sniff, conf, get_if_list
except ImportError:
    print("[ERROR] Scapy not installed. Run: pip install scapy")
    sys.exit(1)

from detector.detection_engine import DetectionEngine
from detector.utils import get_timestamp


class PacketSniffer:
    """
    Wraps Scapy's sniff() in a threaded, stoppable sniffer.
    Delegates each captured packet to DetectionEngine.analyze().
    """

    def __init__(self, engine: DetectionEngine, config: dict):
        self.engine    = engine
        self.config    = config
        self.running   = False
        self._thread   = None
        self.packet_count = 0

    def _get_interface(self) -> str:
        """
        Determine which interface to sniff on.
        Uses config value if set, otherwise auto-selects.
        """
        configured = self.config.get("interface")
        if configured:
            return configured

        # Try to auto-detect a usable interface
        try:
            # Scapy's default interface (usually the main uplink)
            default_iface = conf.iface
            if default_iface:
                return str(default_iface)
        except Exception:
            pass

        # Fallback: pick first available interface
        available = get_if_list()
        if available:
            return available[0]

        return None  # Let Scapy use its default

    def _packet_callback(self, packet):
        """
        Called by Scapy for every captured packet.
        Increments counter and forwards to detection engine.
        """
        self.packet_count += 1
        self.engine.analyze(packet)

    def _sniff_loop(self, interface: str, bpf_filter: str):
        """
        The actual sniffing loop, runs in a background thread.
        Uses store=False to avoid keeping packets in memory (important for long runs).
        """
        try:
            kwargs = {
                "prn":    self._packet_callback,
                "store":  False,
                "filter": bpf_filter,
                # stop_filter lets us stop sniffing cleanly when self.running = False
                "stop_filter": lambda _: not self.running,
            }
            if interface:
                kwargs["iface"] = interface

            sniff(**kwargs)
        except PermissionError:
            print("\n[ERROR] Permission denied. Scapy requires root/sudo privileges.")
            print("       Run: sudo python3 main.py")
            self.running = False
        except OSError as e:
            print(f"\n[ERROR] Interface error: {e}")
            print(f"       Check that interface '{interface}' exists.")
            print(f"       Available interfaces: {get_if_list()}")
            self.running = False
        except Exception as e:
            print(f"\n[ERROR] Sniffer error: {e}")
            self.running = False

    def start(self):
        """Start the packet sniffer in a background thread."""
        interface  = self._get_interface()
        bpf_filter = self.config.get("bpf_filter", "icmp or udp port 53")

        self.running = True

        print(f"\n[SNIFFER] Starting live capture...")
        print(f"[SNIFFER] Interface  : {interface or 'auto'}")
        print(f"[SNIFFER] BPF Filter : {bpf_filter}")
        print(f"[SNIFFER] Listening for ICMP and DNS packets...\n")

        self._thread = threading.Thread(
            target=self._sniff_loop,
            args=(interface, bpf_filter),
            daemon=True  # Dies when main program exits
        )
        self._thread.start()

    def stop(self):
        """Signal the sniffer to stop."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=3)
        print(f"\n[SNIFFER] Stopped. Total packets captured: {self.packet_count}")

    def is_running(self) -> bool:
        return self.running and (self._thread is not None) and self._thread.is_alive()
