"""
utils.py - Shared encoding/decoding utilities for the covert channel sender.
Used by both icmp_sender.py and dns_sender.py.
"""

import base64


def encode_message(message: str) -> bytes:
    """
    Encode a plaintext message to base64 bytes.
    This simulates what an attacker would do to hide data in packets.
    """
    return base64.b64encode(message.encode('utf-8'))


def decode_message(data: bytes) -> str:
    """
    Decode base64 bytes back to a plaintext string.
    Used on the receiver side to reveal the hidden message.
    """
    try:
        return base64.b64decode(data).decode('utf-8')
    except Exception:
        return "[Could not decode message]"


def chunk_message(message: str, chunk_size: int = 8) -> list:
    """
    Split a message into fixed-size chunks for DNS subdomain encoding.
    Each chunk becomes one DNS query subdomain label.
    """
    encoded = encode_message(message).decode('utf-8')
    # Replace base64 padding '=' with '-' for valid DNS label use
    encoded = encoded.replace('=', '-')
    return [encoded[i:i + chunk_size] for i in range(0, len(encoded), chunk_size)]


def get_target_ip() -> str:
    """
    Prompt user for target IP address with a default fallback to localhost.
    """
    ip = input("Enter target IP address (press Enter for localhost 127.0.0.1): ").strip()
    if not ip:
        return "127.0.0.1"
    return ip
