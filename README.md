# Real-Time Covert Channel Detection System
### Minor Project — Network Security | B.Tech Semester VI

---

## 📌 Project Overview

This project demonstrates and detects **covert channel attacks** over a network using:
- **ICMP Covert Channel** — Hiding secret data inside ICMP (ping) packet payloads
- **DNS Covert Channel / DNS Tunneling** — Encoding data in DNS query subdomain labels

The system consists of:
1. **Sender (Attacker)** — Crafts and sends malicious packets (`sender/`)
2. **Detector (Defender)** — Sniffs traffic and raises alerts in real time (`detector/`)

---

## 📁 Project Structure

```
covert_channel_detector/
│
├── sender/
│   ├── icmp_sender.py      ← Sends ICMP packets with hidden payload
│   ├── dns_sender.py       ← Sends DNS queries with encoded subdomains
│   └── utils.py            ← Shared encode/decode and helper functions
│
├── detector/
│   ├── main.py             ← ENTRY POINT — run this to start the detector
│   ├── packet_sniffer.py   ← Live Scapy-based packet capture (threaded)
│   ├── detection_engine.py ← Core logic: ICMP + DNS analysis
│   ├── logger.py           ← Real-time alert logger (console + file)
│   ├── utils.py            ← Entropy calculator, base64 decoder, config loader
│   └── config.yaml         ← Tunable detection thresholds and settings
│
├── logs/
│   └── alerts.log          ← Auto-updated alert log file
│
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

### Step 1 — Install Python dependencies

```bash
pip install -r requirements.txt
```

This installs:
- `scapy` — packet crafting and live capture
- `pyyaml` — config file parsing

### Step 2 — Verify Scapy installation

```bash
python3 -c "from scapy.all import IP, ICMP, DNS; print('Scapy OK')"
```

---

## ▶️ Running on Localhost (Same System)

Open **two terminals** in the project root directory.

### Terminal 1 — Start the Detector (run first)

```bash
sudo python3 -m detector.main
```

Or with an explicit interface:
```bash
sudo python3 -m detector.main --iface lo
```

You should see:
```
[SNIFFER] Starting live capture...
[SNIFFER] Interface  : lo
[SNIFFER] BPF Filter : icmp or udp port 53
[INFO] Detection engine is ACTIVE.
[INFO] Waiting for packets...
```

### Terminal 2 — Run the ICMP Sender (Attacker)

```bash
cd sender
sudo python3 icmp_sender.py
```

Enter your message when prompted. Example:
```
Enter the secret message to hide: HELLO_WORLD
Enter target IP (press Enter for 127.0.0.1): [Enter]
```

Expected detector output:
```
─────────────────────────────────────────────────────────────
[ALERT] ICMP | 127.0.0.1 -> 127.0.0.1 | ICMP Covert Channel — Attacker Signature Detected | ICMP_ID=0xBEEF | DECODED: "HELLO_WORLD"
─────────────────────────────────────────────────────────────
```

### Terminal 2 (Alternative) — Run the DNS Sender (Attacker)

```bash
cd sender
sudo python3 dns_sender.py
```

---

## 🌐 Running on Two Systems (LAN/Wi-Fi)

### System A — Detector Machine

```bash
# Find your IP address first
ip a                # Linux
ipconfig           # Windows

# Start the detector (on the machine you want to protect)
sudo python3 -m detector.main --iface eth0   # or wlan0 for WiFi
```

### System B — Attacker Machine

```bash
cd sender
sudo python3 icmp_sender.py
# When asked for target IP, enter System A's IP address
# Example: 192.168.1.105
```

---

## 📋 Detection Methods Explained

| Method | Protocol | What it checks | Why it's suspicious |
|--------|----------|----------------|---------------------|
| ICMP ID Fingerprint | ICMP | ICMP ID = 0xBEEF | Our sender uses this signature |
| ICMP Payload Size | ICMP | Payload > 20 bytes | Normal pings have small payloads |
| ICMP Entropy | ICMP | Entropy > 0.82 | Base64 data has high entropy |
| DNS Keyword | DNS | Domain contains "covertchannel" etc. | Attacker-controlled domain |
| DNS Label Entropy | DNS | Subdomain entropy > 0.82 | Encoded data in subdomains |
| DNS Frequency | DNS | Same domain queried 3+ times / 30s | Tunneling pattern |

---

## 🔬 Wireshark Verification

1. Open Wireshark
2. Select your active interface (e.g. `eth0`, `wlan0`, or `lo` for loopback)
3. Apply these display filters:

**For ICMP covert channel:**
```
icmp
```
Click on a packet → expand "Data" section → you will see the base64-encoded payload.

**For DNS tunneling:**
```
dns
```
Look for queries to `covertchannel.xyz` with random-looking subdomains like:
```
SEVMTE8t.covertchannel.xyz
```

**Combined filter:**
```
icmp or (dns and udp.port == 53)
```

---

## 📝 Log File

Alerts are automatically saved to `logs/alerts.log`.

View in real time:
```bash
tail -f logs/alerts.log
```

Sample log entry:
```
[2025-01-15 14:32:07] [ALERT   ] ICMP | 127.0.0.1        -> 127.0.0.1        | ICMP Covert Channel — Attacker Signature Detected | ICMP_ID=0xBEEF | Seq=0 | PayloadLen=24B | DECODED: "HELLO_WORLD"
```

---

## 🎓 Viva Talking Points

1. **What is a covert channel?**
   A communication path that hides data within legitimate-looking protocol traffic to evade detection.

2. **Why ICMP?**
   ICMP (ping) is often allowed through firewalls. Attackers exploit the payload field to carry hidden data.

3. **What is DNS tunneling?**
   Encoding data as subdomain labels in DNS queries. The data reaches an attacker-controlled DNS server even through strict firewalls, because DNS is almost never blocked.

4. **What is Shannon entropy?**
   A measure of randomness in data. Encoded/encrypted data has high entropy (close to 1.0). Normal English text has low entropy (~0.6). We use this to flag suspicious payloads.

5. **How does the detector avoid false positives?**
   Multiple checks are combined — size, entropy, ICMP ID, and DNS frequency. A single check alone would cause too many false alerts.

---

## ⚠️ Ethical Notice

This project is for educational purposes only. Only run on systems and networks you own or have explicit written permission to test.
