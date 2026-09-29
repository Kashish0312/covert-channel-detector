"""
icmp_sender.py - ICMP Covert Channel Sender (Attacker Module)

This module hides a secret message inside the ICMP ping payload.
Normal ping packets have an 8-byte payload; we embed encoded text instead.

Usage:
    sudo python3 icmp_sender.py

Requires: scapy (pip install scapy)
Must be run as root/sudo to send raw packets.
"""

import sys
import time

try:
    from scapy.all import IP, ICMP, send, conf
except ImportError:
    print("[ERROR] Scapy not installed. Run: pip install scapy")
    sys.exit(1)

# Suppress Scapy's verbose output
conf.verb = 0

# Add parent directory to path so we can import our utils
sys.path.insert(0, '.')
from utils import encode_message, get_target_ip


def send_icmp_covert(message: str, target_ip: str, delay: float = 0.5):
    """
    Encode a message and send it inside ICMP echo request packets.

    How it works:
    - A normal ICMP ping has a small fixed payload.
    - We replace that payload with our base64-encoded secret message.
    - The detector will flag ICMP packets with non-standard payloads.

    Args:
        message   : The secret string to hide in ICMP packets
        target_ip : Destination IP address
        delay     : Seconds to wait between packets
    """
    # Encode the message to base64 bytes
    encoded = encode_message(message)

    print(f"\n[ICMP SENDER] Target     : {target_ip}")
    print(f"[ICMP SENDER] Message    : {message}")
    print(f"[ICMP SENDER] Encoded    : {encoded.decode()}")
    print(f"[ICMP SENDER] Payload Len: {len(encoded)} bytes")
    print(f"[ICMP SENDER] Sending packets...\n")

    # Split encoded message into chunks to simulate multi-packet transmission
    chunk_size = 32
    chunks = [encoded[i:i + chunk_size] for i in range(0, len(encoded), chunk_size)]

    for idx, chunk in enumerate(chunks):
        # Build ICMP packet: IP header / ICMP header / custom payload
        packet = IP(dst=target_ip) / ICMP(id=0xBEEF, seq=idx) / chunk

        try:
            send(packet)
            print(f"  [PKT {idx + 1:02d}] Sent ICMP to {target_ip} | "
                  f"Payload: {chunk.decode(errors='replace')} | "
                  f"Seq: {idx}")
            time.sleep(delay)
        except PermissionError:
            print("[ERROR] Permission denied. Run with sudo: sudo python3 icmp_sender.py")
            sys.exit(1)
        except Exception as e:
            print(f"[ERROR] Failed to send packet: {e}")
            sys.exit(1)

    print(f"\n[ICMP SENDER] Done. Sent {len(chunks)} packet(s).")


def main():
    print("=" * 55)
    print("   ICMP COVERT CHANNEL SENDER  (Attacker Module)")
    print("=" * 55)

    # Get the secret message from user
    message = input("Enter the secret message to hide: ").strip()
    if not message:
        message = "HELLO_COVERT"
        print(f"[INFO] Using default message: {message}")

    # Get target IP
    target_ip = get_target_ip()

    # Send covert ICMP packets
    send_icmp_covert(message, target_ip)


if __name__ == "__main__":
    main()
