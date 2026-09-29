"""
utils.py - Shared Utility Functions for the Detector

Contains:
  - Shannon entropy calculator (used to detect encoded/compressed payloads)
  - Base64 decode helper (used to reveal hidden messages)
  - Config loader (reads config.yaml)
  - Timestamp formatter
"""

import math
import base64
import os
from datetime import datetime

try:
    import yaml
except ImportError:
    yaml = None  # Handled gracefully in load_config()


def shannon_entropy(data: bytes) -> float:
    """
    Calculate the Shannon entropy of a byte sequence in bits.

    Entropy measures randomness/unpredictability:
      - Low entropy  (< 2.0) → repetitive or structured data (normal short strings)
      - High entropy (> 3.5) → encoded, encrypted, or compressed data (suspicious)

    Returns raw entropy in bits (not normalized).
    For a 256-symbol alphabet, max = 8.0 bits.
    For base64 (64-symbol), typical range is 4.0 - 6.0 bits for long payloads.
    """
    if not data or len(data) == 0:
        return 0.0

    # Count frequency of each byte value
    frequency = {}
    for byte in data:
        frequency[byte] = frequency.get(byte, 0) + 1

    total = len(data)
    entropy = 0.0

    for count in frequency.values():
        probability = count / total
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy  # raw bits


def base64_ratio(data: bytes) -> float:
    """
    Calculate the fraction of bytes that belong to the base64 alphabet
    (A-Z, a-z, 0-9, +, /, =, -).  Values close to 1.0 suggest base64 encoding.

    This is more reliable than entropy for SHORT strings (< 20 chars)
    because short strings don't have enough statistical mass for entropy to work well.
    """
    if not data:
        return 0.0
    b64_chars = set(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-')
    count = sum(1 for b in data if b in b64_chars)
    return count / len(data)


def looks_encoded(data: bytes, min_length: int = 6) -> bool:
    """
    Combined heuristic: returns True if data looks like base64-encoded content.
    Uses both entropy (for longer payloads) and base64 alphabet ratio (for short ones).
    """
    if not data or len(data) < min_length:
        return False

    ratio = base64_ratio(data)
    entropy = shannon_entropy(data)

    if len(data) >= 20:
        # For longer payloads: high entropy AND mostly base64 chars
        return ratio > 0.90 and entropy > 3.5
    else:
        # For short labels (DNS chunks): rely mainly on b64 ratio + mixed case
        has_upper  = any(c in data for c in b'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        has_lower  = any(c in data for c in b'abcdefghijklmnopqrstuvwxyz')
        has_digits = any(c in data for c in b'0123456789')
        mixed = (has_upper and has_lower) or (has_upper and has_digits) or (has_lower and has_digits)
        return ratio > 0.95 and mixed


def try_base64_decode(data: bytes) -> str:
    """
    Attempt to decode bytes as base64.
    Returns the decoded string if successful, otherwise returns None.
    """
    try:
        # Try to decode directly
        decoded = base64.b64decode(data).decode('utf-8')
        return decoded
    except Exception:
        pass

    # Try stripping whitespace and padding
    try:
        padded = data.strip()
        # Add padding if needed
        padding_needed = len(padded) % 4
        if padding_needed:
            padded += b'=' * (4 - padding_needed)
        decoded = base64.b64decode(padded).decode('utf-8')
        return decoded
    except Exception:
        return None


def get_timestamp() -> str:
    """Return a formatted timestamp string for logging."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def load_config(config_path: str = None) -> dict:
    """
    Load configuration from config.yaml.
    Falls back to sensible defaults if the file is missing or yaml is not installed.
    """
    defaults = {
        "interface": None,
        "bpf_filter": "icmp or udp port 53",
        "icmp_payload_threshold": 20,
        "entropy_threshold": 0.82,
        "dns_query_count_threshold": 3,
        "dns_time_window": 30,
        "dns_suspicious_labels": ["covertchannel", "tunnel", "exfil", "c2", "cmd"],
        "log_file": "logs/alerts.log",
        "show_all_packets": False,
        "show_decoded_payload": True,
    }

    if config_path is None:
        # Determine path relative to THIS file's location
        base_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(base_dir, "config.yaml")

    if yaml is None:
        print("[WARN] PyYAML not installed. Using default configuration.")
        return defaults

    if not os.path.exists(config_path):
        print(f"[WARN] config.yaml not found at {config_path}. Using defaults.")
        return defaults

    try:
        with open(config_path, "r") as f:
            loaded = yaml.safe_load(f)
            if loaded:
                defaults.update(loaded)
    except Exception as e:
        print(f"[WARN] Could not read config.yaml: {e}. Using defaults.")

    return defaults


def ensure_log_dir(log_file: str):
    """Create the logs directory if it does not exist."""
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
