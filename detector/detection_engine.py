"""
detection_engine.py - Core Detection Logic for Covert Channel Detector

This module analyzes individual packets and determines whether they
carry covert channel characteristics.

Detection methods implemented:
  1. ICMP payload size analysis   → Large ICMP payloads are suspicious
  2. ICMP entropy analysis        → High-entropy payloads suggest encoding
  3. ICMP ID fingerprinting       → Specific ICMP IDs (e.g. 0xBEEF) used by our sender
  4. DNS subdomain entropy        → Encoded data in subdomains has high entropy
  5. DNS suspicious domain check  → Queries to known covert-channel domain names
  6. DNS query frequency tracking → Same domain queried many times = tunneling
"""

import time
from collections import defaultdict

try:
    from scapy.all import IP, ICMP, UDP, DNS, DNSQR, Raw
except ImportError:
    pass  # Handled in main.py

from detector.utils import shannon_entropy, base64_ratio, looks_encoded, try_base64_decode, load_config


class DetectionEngine:
    """
    Stateful detection engine that analyzes packets for covert channel indicators.

    It tracks state (e.g. DNS query history) across packets to detect
    patterns that only become visible over multiple packets.
    """

    def __init__(self, config: dict, logger):
        self.config = config
        self.logger = logger

        # DNS query tracking: domain → list of timestamps
        # Used to detect high-frequency queries (DNS tunneling)
        self.dns_query_history = defaultdict(list)

        # Statistics counters
        self.stats = {
            "packets_analyzed":  0,
            "icmp_alerts":       0,
            "dns_alerts":        0,
            "total_alerts":      0,
        }

    def analyze(self, packet):
        """
        Main entry point. Analyze a single packet and emit alerts if needed.
        Called once per captured packet from the sniffer.
        """
        self.stats["packets_analyzed"] += 1

        if not packet.haslayer(IP):
            return  # Skip non-IP packets

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # ── Route to protocol-specific analyzer ──────────────────────────
        if packet.haslayer(ICMP):
            self._analyze_icmp(packet, src_ip, dst_ip)

        elif packet.haslayer(UDP) and packet.haslayer(DNS):
            self._analyze_dns(packet, src_ip, dst_ip)

        # Optional: show all packets if configured
        if self.config.get("show_all_packets"):
            self.logger.info(
                "PKT", src_ip, dst_ip,
                f"Packet captured",
                f"Proto={packet[IP].proto}"
            )

    # ─────────────────────────────────────────────────────────────────────
    # ICMP Detection
    # ─────────────────────────────────────────────────────────────────────

    def _analyze_icmp(self, packet, src_ip: str, dst_ip: str):
        """
        Analyze ICMP packets for covert channel indicators.

        Checks:
          a) Unusual ICMP ID value (our sender uses 0xBEEF = 48879)
          b) Payload size larger than normal ping size
          c) Payload Shannon entropy above threshold (encoded data)
        """
        icmp_layer = packet[ICMP]
        icmp_type  = icmp_layer.type   # 8 = echo request, 0 = echo reply
        icmp_id    = icmp_layer.id
        icmp_seq   = icmp_layer.seq

        # Extract the raw payload after the ICMP header
        payload = bytes(icmp_layer.payload) if icmp_layer.payload else b""
        payload_len = len(payload)

        # Thresholds from config
        size_threshold = self.config.get("icmp_payload_threshold", 20)

        # ── Check 1: Suspicious ICMP ID (0xBEEF = our sender's signature) ──
        if icmp_id == 0xBEEF:
            decoded = self._try_decode_payload(payload) if payload else ""
            entropy = shannon_entropy(payload) if payload else 0.0
            details = (
                f"ICMP_ID=0xBEEF (attacker signature) | "
                f"Seq={icmp_seq} | "
                f"PayloadLen={payload_len}B | "
                f"Entropy={entropy:.2f}bits"
            )
            self.logger.alert(
                "ICMP", src_ip, dst_ip,
                "ICMP Covert Channel — Attacker Signature Detected",
                details,
                decoded=decoded
            )
            self.stats["icmp_alerts"] += 1
            self.stats["total_alerts"] += 1
            return  # Already alerted, no need for further checks

        # ── Check 2: Oversized ICMP payload ────────────────────────────────
        if payload_len > size_threshold:
            entropy   = shannon_entropy(payload)
            is_enc    = looks_encoded(payload)
            decoded   = self._try_decode_payload(payload) if is_enc else ""
            b64ratio  = base64_ratio(payload)

            severity = "ALERT" if is_enc else "WARNING"
            reason = (
                "ICMP Covert Channel — Large Encoded Payload Detected"
                if is_enc
                else "ICMP — Unusually Large Payload (Possible Covert Channel)"
            )
            details = (
                f"PayloadLen={payload_len}B | "
                f"Entropy={entropy:.2f}bits | "
                f"B64ratio={b64ratio:.2f} | "
                f"ICMP_ID={hex(icmp_id)} | "
                f"Seq={icmp_seq} | "
                f"Preview={payload[:20]!r}"
            )

            if severity == "ALERT":
                self.logger.alert("ICMP", src_ip, dst_ip, reason, details, decoded=decoded)
                self.stats["icmp_alerts"] += 1
                self.stats["total_alerts"] += 1
            else:
                self.logger.warning("ICMP", src_ip, dst_ip, reason, details)

        # ── Check 3: looks encoded even for normal-sized payload ─────────────
        elif payload_len > 0:
            if looks_encoded(payload):
                decoded  = self._try_decode_payload(payload)
                entropy  = shannon_entropy(payload)
                b64ratio = base64_ratio(payload)
                details  = (
                    f"Entropy={entropy:.2f}bits | "
                    f"B64ratio={b64ratio:.2f} | "
                    f"PayloadLen={payload_len}B | "
                    f"ICMP_ID={hex(icmp_id)}"
                )
                self.logger.alert(
                    "ICMP", src_ip, dst_ip,
                    "ICMP — Encoded Payload Detected (Possible Covert Channel)",
                    details,
                    decoded=decoded
                )
                self.stats["icmp_alerts"] += 1
                self.stats["total_alerts"] += 1

    # ─────────────────────────────────────────────────────────────────────
    # DNS Detection
    # ─────────────────────────────────────────────────────────────────────

    def _analyze_dns(self, packet, src_ip: str, dst_ip: str):
        """
        Analyze DNS packets for covert channel / DNS tunneling indicators.

        Checks:
          a) Suspicious keywords in the queried domain name
          b) High entropy in the subdomain label (encoded data)
          c) Same domain queried too frequently (tunneling pattern)
        """
        dns_layer = packet[DNS]

        # Only analyze DNS questions (qr=0), not responses (qr=1)
        if dns_layer.qr != 0:
            return

        if not dns_layer.qd:
            return  # No question record

        # Decode the queried domain name
        try:
            qname = dns_layer.qd.qname.decode('utf-8', errors='replace').rstrip('.')
        except Exception:
            qname = str(dns_layer.qd.qname)

        entropy_threshold  = self.config.get("entropy_threshold", 3.5)   # raw bits
        suspicious_labels  = self.config.get("dns_suspicious_labels", [])
        count_threshold    = self.config.get("dns_query_count_threshold", 3)
        time_window        = self.config.get("dns_time_window", 30)

        labels = qname.split('.')

        # ── Check 1: Suspicious keyword in domain ──────────────────────────
        for label in labels:
            for keyword in suspicious_labels:
                if keyword.lower() in label.lower():
                    details = (
                        f"Domain={qname} | "
                        f"MatchedKeyword='{keyword}' | "
                        f"Label='{label}'"
                    )
                    self.logger.alert(
                        "DNS", src_ip, dst_ip,
                        f"DNS Tunneling — Suspicious Domain Keyword '{keyword}'",
                        details
                    )
                    self.stats["dns_alerts"] += 1
                    self.stats["total_alerts"] += 1

        # ── Check 2: Encoded subdomain label ────────────────────────────────
        # Check only the first label (the data-carrying subdomain)
        if labels:
            first_label = labels[0]
            label_bytes = first_label.encode()
            is_enc      = looks_encoded(label_bytes, min_length=4)
            b64r        = base64_ratio(label_bytes)
            ent         = shannon_entropy(label_bytes)

            if is_enc:
                # Reverse our sender's padding substitution ('-' → '=') before decoding
                decoded_label = first_label.replace('-', '=')
                decoded_msg   = try_base64_decode(decoded_label.encode())

                details = (
                    f"Domain={qname} | "
                    f"Label='{first_label}' | "
                    f"B64ratio={b64r:.2f} | "
                    f"Entropy={ent:.2f}bits"
                )
                self.logger.alert(
                    "DNS", src_ip, dst_ip,
                    "DNS Tunneling — Encoded Subdomain Detected",
                    details,
                    decoded=decoded_msg or ""
                )
                self.stats["dns_alerts"] += 1
                self.stats["total_alerts"] += 1

        # ── Check 3: Repeated queries to same domain (frequency analysis) ──
        base_domain = '.'.join(labels[-2:]) if len(labels) >= 2 else qname
        now = time.time()

        # Record this query timestamp
        self.dns_query_history[base_domain].append(now)

        # Keep only queries within the time window
        self.dns_query_history[base_domain] = [
            t for t in self.dns_query_history[base_domain]
            if now - t <= time_window
        ]

        query_count = len(self.dns_query_history[base_domain])

        if query_count >= count_threshold:
            details = (
                f"Domain={base_domain} | "
                f"Queries={query_count} in {time_window}s | "
                f"LastQuery={qname}"
            )
            self.logger.alert(
                "DNS", src_ip, dst_ip,
                f"DNS Tunneling — High Query Frequency ({query_count} queries/{time_window}s)",
                details
            )
            self.stats["dns_alerts"] += 1
            self.stats["total_alerts"] += 1
            # Clear history after alerting to prevent repeated same-alert spam
            self.dns_query_history[base_domain] = []

    # ─────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────

    def _try_decode_payload(self, payload: bytes) -> str:
        """Try to decode payload as base64 and return readable string."""
        if not payload:
            return ""
        result = try_base64_decode(payload)
        if result:
            return result
        # Fallback: show safe ASCII representation
        return payload.decode('ascii', errors='replace').strip()

    def print_stats(self):
        """Print a summary of detection statistics to console."""
        print("\n" + "=" * 55)
        print("  DETECTION STATISTICS")
        print("=" * 55)
        print(f"  Packets Analyzed : {self.stats['packets_analyzed']}")
        print(f"  ICMP Alerts      : {self.stats['icmp_alerts']}")
        print(f"  DNS Alerts       : {self.stats['dns_alerts']}")
        print(f"  Total Alerts     : {self.stats['total_alerts']}")
        print("=" * 55)
