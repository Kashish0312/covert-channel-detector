"""
logger.py - Alert Logger for the Covert Channel Detector

Handles:
  - Writing alerts to logs/alerts.log in real time
  - Console output with colored severity labels
  - Structured log format for easy analysis

Log entry format:
  [TIMESTAMP] [SEVERITY] PROTOCOL | SRC -> DST | Reason | Details
"""

import os
import sys
from detector.utils import get_timestamp, ensure_log_dir


# ANSI color codes for console output (works on Linux/macOS terminals)
class Colors:
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"


# Severity levels and their console colors
SEVERITY_COLORS = {
    "INFO":     Colors.CYAN,
    "WARNING":  Colors.YELLOW,
    "ALERT":    Colors.RED + Colors.BOLD,
    "CRITICAL": Colors.MAGENTA + Colors.BOLD,
    "DEBUG":    Colors.GREEN,
}


class AlertLogger:
    """
    Handles all logging for the covert channel detector.
    Writes structured alerts to both console and log file simultaneously.
    """

    def __init__(self, log_file: str = "logs/alerts.log"):
        self.log_file = log_file
        ensure_log_dir(log_file)

        # Open log file in append mode so previous runs are preserved
        try:
            self.log_fh = open(log_file, "a", buffering=1)  # Line-buffered for real-time writes
            self._write_separator()
        except Exception as e:
            print(f"[ERROR] Cannot open log file {log_file}: {e}")
            self.log_fh = None

    def _write_separator(self):
        """Write a session start marker to the log file."""
        ts = get_timestamp()
        line = f"\n{'=' * 70}\n[SESSION START] {ts}\n{'=' * 70}\n"
        if self.log_fh:
            self.log_fh.write(line)
            self.log_fh.flush()

    def log(self, severity: str, protocol: str, src_ip: str, dst_ip: str,
            reason: str, details: str = "", decoded: str = ""):
        """
        Log a detection alert to both console and file.

        Args:
            severity : "INFO" | "WARNING" | "ALERT" | "CRITICAL"
            protocol : "ICMP" | "DNS" | "TCP" | etc.
            src_ip   : Source IP address
            dst_ip   : Destination IP address
            reason   : Why this packet was flagged
            details  : Additional technical details (entropy score, payload preview, etc.)
            decoded  : Decoded hidden message (if recovered)
        """
        ts = get_timestamp()

        # Build the log message
        log_line = (
            f"[{ts}] [{severity:8s}] {protocol:4s} | "
            f"{src_ip:15s} -> {dst_ip:15s} | "
            f"{reason}"
        )

        if details:
            log_line += f" | {details}"

        if decoded:
            log_line += f" | DECODED: \"{decoded}\""

        # ── Console output (colored) ──────────────────────────────────────
        color = SEVERITY_COLORS.get(severity, "")
        reset = Colors.RESET

        # Print a prominent alert banner for ALERT/CRITICAL
        if severity in ("ALERT", "CRITICAL"):
            print(f"\n{color}{'─' * 65}{reset}")
            print(f"{color}{log_line}{reset}")
            print(f"{color}{'─' * 65}{reset}\n")
        else:
            print(f"{color}{log_line}{reset}")

        # ── File output (plain text) ──────────────────────────────────────
        if self.log_fh:
            try:
                self.log_fh.write(log_line + "\n")
                self.log_fh.flush()
            except Exception as e:
                print(f"[WARN] Could not write to log: {e}")

    def info(self, protocol, src, dst, reason, details=""):
        self.log("INFO", protocol, src, dst, reason, details)

    def warning(self, protocol, src, dst, reason, details=""):
        self.log("WARNING", protocol, src, dst, reason, details)

    def alert(self, protocol, src, dst, reason, details="", decoded=""):
        self.log("ALERT", protocol, src, dst, reason, details, decoded)

    def critical(self, protocol, src, dst, reason, details="", decoded=""):
        self.log("CRITICAL", protocol, src, dst, reason, details, decoded)

    def close(self):
        """Close the log file handle cleanly on exit."""
        if self.log_fh:
            ts = get_timestamp()
            self.log_fh.write(f"[SESSION END] {ts}\n")
            self.log_fh.close()
