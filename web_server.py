"""
web_server.py - Flask Dashboard Server for Covert Channel Detector
==================================================================
Drop this file into your project ROOT (alongside detector/ and logs/).

Run:
    pip install flask
    python3 web_server.py

Then open:  http://localhost:5000

What this does:
  - Parses your real logs/alerts.log using the EXACT format from logger.py
  - Serves /api/logs      → all parsed log entries as JSON
  - Serves /api/stream    → Server-Sent Events for live push (no refresh needed)
  - Serves /              → the dashboard HTML
  - Watches alerts.log with a tail thread — new alerts appear on dashboard instantly
"""

import os
import re
import time
import json
import queue
import threading
from datetime import datetime
from flask import Flask, jsonify, request, Response, render_template_string, send_file, make_response

try:
    import yaml
except ImportError:
    yaml = None

app = Flask(__name__)


# ── CORS middleware ───────────────────────────────────────────────────────
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response

# ── Paths (relative to this file's location = project root) ──────────────
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(PROJECT_ROOT, "logs", "alerts.log")
CONFIG_FILE = os.path.join(PROJECT_ROOT, "detector", "config.yaml")
STANDALONE_HTML = os.path.join(os.path.dirname(PROJECT_ROOT), "covert_channel_ids_dashboard.html")

# ── Global state ──────────────────────────────────────────────────────────
_log_entries = []          # All parsed entries, newest first
_lock = threading.Lock()
_sse_clients = []          # Active SSE connections


# ═══════════════════════════════════════════════════════════════════════════
# LOG PARSER — matches logger.py format EXACTLY
# Format: [TIMESTAMP] [SEVERITY] PROTO | SRC -> DST | Reason | Details | DECODED: "msg"
# ═══════════════════════════════════════════════════════════════════════════

LOG_RE = re.compile(
    r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]'   # [timestamp]
    r'\s+\[(\w+)\s*\]'                                  # [SEVERITY]
    r'\s+(\w+)\s+\|'                                    # PROTO |
    r'\s+([\d\.]+)\s+->\s+([\d\.]+)\s+\|'             # SRC -> DST |
    r'\s+(.*)$'                                         # rest
)

def parse_line(line: str) -> dict | None:
    """Parse one log line from logger.py output into a dict."""
    line = line.strip()
    if not line or line.startswith('[SESSION') or line.startswith('='):
        return None

    m = LOG_RE.match(line)
    if not m:
        return None

    ts_str, sev, proto, src, dst, rest = m.groups()
    sev = sev.strip()

    # Extract DECODED: "message" if present
    decoded = ''
    decoded_m = re.search(r'DECODED:\s+"([^"]*)"', rest)
    if decoded_m:
        decoded = decoded_m.group(1)
        rest = rest[:decoded_m.start()].strip().rstrip('|').strip()

    # Split remaining into reason | details
    parts = [p.strip() for p in rest.split('|')]
    reason  = parts[0] if parts else ''
    details = ' | '.join(parts[1:]) if len(parts) > 1 else ''

    # Extract entropy from details
    entropy = None
    ent_m = re.search(r'Entropy=([\d.]+)bits', details)
    if ent_m:
        entropy = float(ent_m.group(1))

    # Extract payload length
    payload_len = None
    pl_m = re.search(r'PayloadLen=(\d+)B', details)
    if pl_m:
        payload_len = int(pl_m.group(1))

    # Extract ICMP_ID
    icmp_id = None
    id_m = re.search(r'ICMP_ID=(0x[0-9a-fA-F]+|\d+)', details)
    if id_m:
        icmp_id = id_m.group(1)

    # Extract domain
    domain = None
    dom_m = re.search(r'Domain=([\w.\-]+)', details)
    if dom_m:
        domain = dom_m.group(1)

    # Extract b64 ratio
    b64ratio = None
    b64_m = re.search(r'B64ratio=([\d.]+)', details)
    if b64_m:
        b64ratio = float(b64_m.group(1))

    # Determine check type (matches your detection_engine.py checks)
    check = _classify_check(reason, proto)

    return {
        'ts':         ts_str,
        'ts_epoch':   int(datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S').timestamp() * 1000),
        'sev':        sev,
        'proto':      proto,
        'src':        src.strip(),
        'dst':        dst.strip(),
        'reason':     reason,
        'details':    details,
        'decoded':    decoded,
        'entropy':    entropy,
        'payload_len': payload_len,
        'icmp_id':    icmp_id,
        'domain':     domain,
        'b64ratio':   b64ratio,
        'check':      check,
        'raw':        line,
    }


def _classify_check(reason: str, proto: str) -> str:
    """Map reason string → detection check name (mirrors detection_engine.py)."""
    r = reason.lower()
    if 'signature' in r or '0xbeef' in r:
        return 'ICMP_ID_Fingerprint'
    if 'large encoded' in r:
        return 'ICMP_Payload_Encoded'
    if 'large payload' in r or 'unusually large' in r:
        return 'ICMP_Payload_Size'
    if 'encoded payload' in r:
        return 'ICMP_Entropy'
    if 'keyword' in r:
        return 'DNS_Keyword'
    if 'subdomain' in r:
        return 'DNS_Label_Entropy'
    if 'frequency' in r:
        return 'DNS_Frequency'
    return 'Unknown'


def load_all_logs() -> list:
    """Read and parse the entire alerts.log file."""
    if not os.path.exists(LOG_FILE):
        return []
    entries = []
    try:
        with open(LOG_FILE, 'r', errors='replace') as f:
            for line in f:
                entry = parse_line(line)
                if entry:
                    entries.append(entry)
    except Exception as e:
        print(f"[WARN] Could not read log file: {e}")
    # Newest first
    entries.sort(key=lambda x: x['ts_epoch'], reverse=True)
    return entries


def compute_stats(entries: list) -> dict:
    """Compute summary statistics matching your detection_engine.stats dict."""
    return {
        'total_entries':     len(entries),
        'icmp_alerts':       sum(1 for e in entries if e['proto'] == 'ICMP' and e['sev'] == 'ALERT'),
        'dns_alerts':        sum(1 for e in entries if e['proto'] == 'DNS'  and e['sev'] == 'ALERT'),
        'total_alerts':      sum(1 for e in entries if e['sev'] in ('ALERT', 'CRITICAL')),
        'warnings':          sum(1 for e in entries if e['sev'] == 'WARNING'),
        'high_entropy':      sum(1 for e in entries if e['entropy'] and e['entropy'] > 3.5),
        'decoded_count':     sum(1 for e in entries if e['decoded']),
        'beef_detected':     sum(1 for e in entries if e['icmp_id'] == '0xBEEF' or e['check'] == 'ICMP_ID_Fingerprint'),
        'checks': {
            'ICMP_ID_Fingerprint':  sum(1 for e in entries if e['check'] == 'ICMP_ID_Fingerprint'),
            'ICMP_Payload_Size':    sum(1 for e in entries if e['check'] == 'ICMP_Payload_Size'),
            'ICMP_Payload_Encoded': sum(1 for e in entries if e['check'] == 'ICMP_Payload_Encoded'),
            'ICMP_Entropy':         sum(1 for e in entries if e['check'] == 'ICMP_Entropy'),
            'DNS_Keyword':          sum(1 for e in entries if e['check'] == 'DNS_Keyword'),
            'DNS_Label_Entropy':    sum(1 for e in entries if e['check'] == 'DNS_Label_Entropy'),
            'DNS_Frequency':        sum(1 for e in entries if e['check'] == 'DNS_Frequency'),
        },
        'unique_src_ips':    len(set(e['src'] for e in entries)),
        'unique_domains':    len(set(e['domain'] for e in entries if e['domain'])),
        'top_src_ips':       _top_n([e['src'] for e in entries], 5),
        'top_domains':       _top_n([e['domain'] for e in entries if e['domain']], 5),
    }


def _top_n(items: list, n: int) -> list:
    from collections import Counter
    return [{'value': v, 'count': c} for v, c in Counter(items).most_common(n)]


# ═══════════════════════════════════════════════════════════════════════════
# LOG FILE WATCHER — tail -f equivalent
# Pushes new lines to SSE clients in real time
# ═══════════════════════════════════════════════════════════════════════════

def _tail_log():
    """Background thread: watch alerts.log for new lines and push via SSE."""
    global _log_entries
    last_size = 0

    while True:
        try:
            if not os.path.exists(LOG_FILE):
                time.sleep(1)
                continue

            size = os.path.getsize(LOG_FILE)
            if size > last_size:
                with open(LOG_FILE, 'r', errors='replace') as f:
                    f.seek(last_size)
                    new_lines = f.readlines()

                last_size = size

                new_entries = []
                for line in new_lines:
                    entry = parse_line(line)
                    if entry:
                        new_entries.append(entry)

                if new_entries:
                    with _lock:
                        _log_entries = new_entries + _log_entries

                    # Push to all SSE clients
                    payload = json.dumps({'type': 'new_entries', 'entries': new_entries})
                    dead = []
                    for q in _sse_clients:
                        try:
                            q.put_nowait(payload)
                        except Exception:
                            dead.append(q)
                    for q in dead:
                        _sse_clients.remove(q)

            elif size < last_size:
                # File was rotated/cleared — reload everything
                last_size = 0

        except Exception as e:
            print(f"[WATCHER] Error: {e}")

        time.sleep(0.5)


# ═══════════════════════════════════════════════════════════════════════════
# FLASK ROUTES
# ═══════════════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route('/api/logs')
def api_logs():
    """
    GET /api/logs
    Query params:
      ?proto=ICMP|DNS
      ?sev=ALERT|WARNING|INFO|CRITICAL
      ?check=ICMP_ID_Fingerprint|DNS_Keyword|...
      ?q=search_string
      ?limit=100  (default 500)
      ?offset=0
    """
    with _lock:
        entries = list(_log_entries)

    proto  = request.args.get('proto', '').upper()
    sev    = request.args.get('sev', '').upper()
    check  = request.args.get('check', '')
    q      = request.args.get('q', '').lower()
    limit  = min(int(request.args.get('limit', 500)), 2000)
    offset = int(request.args.get('offset', 0))

    if proto:
        entries = [e for e in entries if e['proto'] == proto]
    if sev:
        entries = [e for e in entries if e['sev'] == sev]
    if check:
        entries = [e for e in entries if e['check'] == check]
    if q:
        entries = [e for e in entries if
                   q in e['src'] or q in e['dst'] or
                   q in e['reason'].lower() or
                   q in (e['decoded'] or '').lower() or
                   q in (e['domain'] or '').lower()]

    total = len(entries)
    page_entries = entries[offset:offset + limit]

    return jsonify({
        'total':   total,
        'offset':  offset,
        'limit':   limit,
        'entries': page_entries,
        'stats':   compute_stats(list(_log_entries)),
    })


@app.route('/api/stats')
def api_stats():
    """GET /api/stats — summary statistics only (fast)."""
    with _lock:
        entries = list(_log_entries)
    return jsonify(compute_stats(entries))


@app.route('/api/stream')
def api_stream():
    """
    GET /api/stream — Server-Sent Events endpoint.
    The dashboard JS listens here. New alerts are pushed instantly
    when your detector writes to alerts.log — no polling needed.
    """
    def event_stream(q):
        # Send current stats on connect
        with _lock:
            entries = list(_log_entries)
        yield f"data: {json.dumps({'type': 'init', 'stats': compute_stats(entries)})}\n\n"

        while True:
            try:
                msg = q.get(timeout=25)
                yield f"data: {msg}\n\n"
            except Exception:
                # Heartbeat to keep connection alive
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"

    client_q = queue.Queue(maxsize=50)
    _sse_clients.append(client_q)

    return Response(
        event_stream(client_q),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
        }
    )


@app.route('/api/log_path')
def api_log_path():
    return jsonify({'path': LOG_FILE, 'exists': os.path.exists(LOG_FILE)})


@app.route('/api/config')
def api_config():
    """GET /api/config — return active detector config.yaml as JSON."""
    defaults = {
        'interface': None,
        'bpf_filter': 'icmp or udp port 53',
        'icmp_payload_threshold': 20,
        'entropy_threshold': 0.82,
        'dns_query_count_threshold': 3,
        'dns_time_window': 30,
        'dns_suspicious_labels': ['covertchannel', 'tunnel', 'exfil', 'c2', 'cmd'],
        'log_file': 'logs/alerts.log',
        'show_all_packets': False,
        'show_decoded_payload': True,
    }
    if yaml and os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                loaded = yaml.safe_load(f)
                if loaded:
                    defaults.update(loaded)
        except Exception:
            pass
    return jsonify(defaults)


@app.route('/dashboard')
def dashboard_standalone():
    """Serve the standalone HTML dashboard file if it exists."""
    if os.path.exists(STANDALONE_HTML):
        return send_file(STANDALONE_HTML)
    return 'Standalone dashboard not found', 404


# ═══════════════════════════════════════════════════════════════════════════
# DASHBOARD HTML — served at /
# Fetches real data from /api/logs and streams from /api/stream
# ═══════════════════════════════════════════════════════════════════════════

DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Covert Channel Detector — Dashboard</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap');
:root{--bg:#0a0c10;--surface:#0f1218;--card:#13171f;--border:#1e2530;--border2:#252d3a;--text:#c8d4e0;--muted:#556070;--hint:#33404d;--green:#00e5a0;--red:#ff4655;--amber:#f5a623;--blue:#4da8ff;--purple:#b06cff;--teal:#00d4cc;--mono:'Share Tech Mono',monospace;--sans:'Rajdhani',sans-serif;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:14px;overflow-x:hidden;}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:9999;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.03) 2px,rgba(0,0,0,0.03) 4px);}
#app{padding:16px 18px 40px;max-width:1400px;margin:0 auto;}
.header{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;border-bottom:1px solid var(--border);padding-bottom:14px;}
.header-left{display:flex;align-items:center;gap:14px;}
.shield-icon{width:36px;height:36px;}
.title{font-size:20px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#e8f0f8;}
.subtitle{font-size:11px;font-family:var(--mono);color:var(--muted);margin-top:2px;}
.header-right{display:flex;align-items:center;gap:12px;}
.live-badge{display:flex;align-items:center;gap:6px;font-family:var(--mono);font-size:11px;color:var(--green);border:1px solid rgba(0,229,160,0.25);border-radius:4px;padding:4px 10px;}
.live-dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green);animation:pulse 1.5s ease-in-out infinite;}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(.8)}}
.clock{font-family:var(--mono);font-size:12px;color:var(--muted);}
.logpath{font-family:var(--mono);font-size:10px;color:var(--hint);border:1px solid var(--border);border-radius:3px;padding:3px 8px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.logpath.ok{color:var(--green);border-color:rgba(0,229,160,0.2);}
.logpath.missing{color:var(--red);border-color:rgba(255,70,85,0.2);}
.metrics{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:14px;}
.metric{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:13px 15px;position:relative;overflow:hidden;}
.metric::before{content:'';position:absolute;inset:0;pointer-events:none;}
.m-icmp::before{background:linear-gradient(135deg,rgba(77,168,255,.07),transparent 60%);}
.m-dns::before{background:linear-gradient(135deg,rgba(0,212,204,.07),transparent 60%);}
.m-alert::before{background:linear-gradient(135deg,rgba(255,70,85,.09),transparent 60%);}
.m-ent::before{background:linear-gradient(135deg,rgba(176,108,255,.07),transparent 60%);}
.m-dec::before{background:linear-gradient(135deg,rgba(0,229,160,.07),transparent 60%);}
.metric-label{font-size:10px;font-family:var(--mono);color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;}
.metric-val{font-size:28px;font-weight:700;line-height:1;}
.metric-sub{font-size:10px;color:var(--muted);margin-top:5px;font-family:var(--mono);}
.c-blue{color:var(--blue)}.c-teal{color:var(--teal)}.c-red{color:var(--red)}.c-purple{color:var(--purple)}.c-green{color:var(--green)}
.main-grid{display:grid;grid-template-columns:1fr 330px;gap:12px;margin-bottom:12px;}
.panel{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:15px;}
.panel-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:13px;}
.panel-title{font-size:11px;font-family:var(--mono);color:var(--muted);text-transform:uppercase;letter-spacing:.08em;}
.panel-tag{font-size:10px;font-family:var(--mono);color:var(--hint);}
.search-row{display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap;}
.search-row input,.search-row select{font-family:var(--mono);font-size:12px;padding:7px 11px;background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--text);outline:none;transition:border-color .15s;}
.search-row input{flex:1;min-width:160px;}
.search-row input::placeholder{color:var(--hint);}
.search-row input:focus,.search-row select:focus{border-color:var(--blue);}
.search-row select option{background:#1a2030;}
.btn{font-family:var(--mono);font-size:11px;padding:7px 14px;border-radius:4px;border:1px solid var(--border);background:var(--surface);color:var(--text);cursor:pointer;transition:all .15s;}
.btn:hover{background:var(--border);}
.btn-go{background:rgba(77,168,255,.12);border-color:rgba(77,168,255,.35);color:var(--blue);}
.btn-go:hover{background:rgba(77,168,255,.2);}
.table-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:4px;}
table{width:100%;border-collapse:collapse;font-size:12px;table-layout:fixed;}
thead th{background:var(--surface);color:var(--muted);font-family:var(--mono);font-size:10px;font-weight:400;padding:8px 10px;text-align:left;border-bottom:1px solid var(--border);text-transform:uppercase;letter-spacing:.06em;cursor:pointer;white-space:nowrap;user-select:none;}
thead th:hover{color:var(--text);}
tbody tr{border-bottom:1px solid var(--border);transition:background .1s;}
tbody tr:last-child{border:none;}
tbody tr:hover{background:rgba(255,255,255,.025);}
tbody td{padding:7px 10px;font-family:var(--mono);font-size:11px;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;vertical-align:middle;}
.sev-tag{display:inline-block;font-size:9px;font-weight:600;padding:2px 7px;border-radius:3px;text-transform:uppercase;letter-spacing:.05em;}
.sev-alert{background:rgba(255,70,85,.12);color:var(--red);border:1px solid rgba(255,70,85,.25);}
.sev-warning{background:rgba(245,166,35,.12);color:var(--amber);border:1px solid rgba(245,166,35,.25);}
.sev-info{background:rgba(77,168,255,.1);color:var(--blue);border:1px solid rgba(77,168,255,.2);}
.sev-critical{background:rgba(255,70,85,.2);color:#ff8899;border:1px solid rgba(255,70,85,.4);}
.proto-tag{display:inline-block;font-size:9px;padding:2px 6px;border-radius:3px;font-weight:600;}
.proto-icmp{background:rgba(77,168,255,.1);color:var(--blue);}
.proto-dns{background:rgba(0,212,204,.1);color:var(--teal);}
.decoded-col{color:var(--green);}
.pag{display:flex;align-items:center;justify-content:space-between;margin-top:10px;}
.pag-info{font-family:var(--mono);font-size:10px;color:var(--muted);}
.pag-btns{display:flex;gap:4px;}
.pag-btn{font-family:var(--mono);font-size:11px;padding:3px 9px;border-radius:3px;border:1px solid var(--border);background:var(--surface);color:var(--muted);cursor:pointer;}
.pag-btn.active{background:rgba(77,168,255,.15);border-color:rgba(77,168,255,.4);color:var(--blue);}
.pag-btn:hover:not(.active){background:var(--border);}
.alert-feed{display:flex;flex-direction:column;gap:7px;max-height:430px;overflow-y:auto;}
.alert-feed::-webkit-scrollbar{width:3px;}
.alert-feed::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px;}
.alert-item{background:var(--surface);border:1px solid var(--border);border-radius:5px;padding:10px 12px;border-left:3px solid var(--border);animation:slideIn .3s ease;}
@keyframes slideIn{from{opacity:0;transform:translateX(8px)}to{opacity:1;transform:none}}
.alert-item.sev-alert{border-left-color:var(--red);}
.alert-item.sev-warning{border-left-color:var(--amber);}
.alert-item.sev-info{border-left-color:var(--blue);}
.alert-item.sev-critical{border-left-color:#ff8899;}
.ai-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:5px;}
.ai-time{font-size:10px;font-family:var(--mono);color:var(--hint);}
.ai-reason{font-size:11px;font-family:var(--mono);color:var(--text);margin-bottom:4px;line-height:1.4;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.ai-route{font-size:10px;color:var(--muted);}
.ai-decoded{font-size:10px;font-family:var(--mono);color:var(--green);margin-top:4px;}
.bottom-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;}
.checks-grid{display:grid;grid-template-columns:1fr 1fr;gap:7px;}
.check-item{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:9px 11px;}
.check-name{font-size:10px;font-family:var(--mono);color:var(--muted);margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em;}
.check-val{font-size:18px;font-weight:700;}
.check-sub{font-size:9px;color:var(--hint);font-family:var(--mono);margin-top:2px;}
.ent-list{display:flex;flex-direction:column;gap:8px;}
.ent-row{display:flex;align-items:center;gap:8px;}
.ent-label{font-family:var(--mono);font-size:10px;color:var(--muted);width:95px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.ent-bar-bg{flex:1;height:6px;background:var(--surface);border-radius:3px;overflow:hidden;}
.ent-bar-fill{height:100%;border-radius:3px;transition:width .8s cubic-bezier(.4,0,.2,1);}
.ent-val{font-family:var(--mono);font-size:10px;color:var(--muted);width:36px;text-align:right;}
.cfg-list{display:flex;flex-direction:column;gap:0;}
.cfg-row{display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border);}
.cfg-row:last-child{border:none;}
.cfg-key{font-family:var(--mono);font-size:10px;color:var(--muted);}
.cfg-val{font-family:var(--mono);font-size:11px;color:var(--blue);}
#no-results{text-align:center;padding:28px;color:var(--muted);font-family:var(--mono);font-size:12px;display:none;}
.empty-feed{font-family:var(--mono);font-size:11px;color:var(--hint);text-align:center;padding:24px;line-height:1.7;}
.status-bar{font-family:var(--mono);font-size:10px;color:var(--hint);text-align:center;padding:8px;margin-top:4px;}
</style>
</head>
<body>
<div id="app">

<div class="header">
  <div class="header-left">
    <svg class="shield-icon" viewBox="0 0 38 44" fill="none">
      <path d="M19 2L3 9v14c0 10.5 6.8 18.5 16 21 9.2-2.5 16-10.5 16-21V9L19 2z" fill="rgba(77,168,255,0.12)" stroke="rgba(77,168,255,0.5)" stroke-width="1.5"/>
      <circle cx="19" cy="22" r="4" fill="none" stroke="#4da8ff" stroke-width="1.5"/>
      <line x1="19" y1="16" x2="19" y2="19" stroke="#4da8ff" stroke-width="1.5"/>
      <line x1="19" y1="25" x2="19" y2="28" stroke="#4da8ff" stroke-width="1.5"/>
      <line x1="13" y1="22" x2="16" y2="22" stroke="#4da8ff" stroke-width="1.5"/>
      <line x1="22" y1="22" x2="25" y2="22" stroke="#4da8ff" stroke-width="1.5"/>
    </svg>
    <div>
      <div class="title">Covert Channel Detector</div>
      <div class="subtitle">ICMP Payload Analysis · DNS Tunneling · Shannon Entropy · Real-Time</div>
    </div>
  </div>
  <div class="header-right">
    <span class="logpath" id="logPathTag">checking log file...</span>
    <div class="live-badge"><div class="live-dot"></div>LIVE</div>
    <div class="clock" id="clock">--:--:--</div>
  </div>
</div>

<div class="metrics">
  <div class="metric m-icmp"><div class="metric-label">ICMP Alerts</div><div class="metric-val c-blue" id="m-icmp">—</div><div class="metric-sub">0xBEEF + payload checks</div></div>
  <div class="metric m-dns"><div class="metric-label">DNS Alerts</div><div class="metric-val c-teal" id="m-dns">—</div><div class="metric-sub">tunneling / encoded labels</div></div>
  <div class="metric m-alert"><div class="metric-label">Total Alerts</div><div class="metric-val c-red" id="m-total">—</div><div class="metric-sub">ALERT + CRITICAL</div></div>
  <div class="metric m-ent"><div class="metric-label">High Entropy</div><div class="metric-val c-purple" id="m-entropy">—</div><div class="metric-sub">&gt; 3.5 bits raw</div></div>
  <div class="metric m-dec"><div class="metric-label">Decoded Msgs</div><div class="metric-val c-green" id="m-decoded">—</div><div class="metric-sub">base64 recovered</div></div>
</div>

<div class="main-grid">
  <div class="panel">
    <div class="panel-header">
      <span class="panel-title">alerts.log — Live Search</span>
      <span class="panel-tag" id="log-count">loading...</span>
    </div>
    <div class="search-row">
      <input type="text" id="searchInput" placeholder="Search src IP, dst IP, reason, decoded message, domain..." />
      <select id="filtSev"><option value="">All severity</option><option>ALERT</option><option>WARNING</option><option>INFO</option><option>CRITICAL</option></select>
      <select id="filtProto"><option value="">All proto</option><option>ICMP</option><option>DNS</option></select>
      <select id="filtCheck">
        <option value="">All checks</option>
        <option value="ICMP_ID_Fingerprint">0xBEEF Signature</option>
        <option value="ICMP_Payload_Size">Large Payload</option>
        <option value="ICMP_Payload_Encoded">Encoded Payload</option>
        <option value="ICMP_Entropy">ICMP Entropy</option>
        <option value="DNS_Keyword">DNS Keyword</option>
        <option value="DNS_Label_Entropy">DNS Subdomain Entropy</option>
        <option value="DNS_Frequency">DNS Frequency</option>
      </select>
      <button class="btn btn-go" onclick="applyFilters()">Search</button>
      <button class="btn" onclick="clearFilters()">Clear</button>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th style="width:100px" onclick="sortBy('ts')">Timestamp</th>
          <th style="width:60px" onclick="sortBy('sev')">Sev</th>
          <th style="width:46px" onclick="sortBy('proto')">Proto</th>
          <th style="width:105px" onclick="sortBy('src')">Src IP</th>
          <th style="width:105px" onclick="sortBy('dst')">Dst IP</th>
          <th onclick="sortBy('reason')">Check / Reason</th>
          <th style="width:110px" class="decoded-col">Decoded</th>
          <th style="width:60px">Entropy</th>
        </tr></thead>
        <tbody id="logBody"></tbody>
      </table>
      <div id="no-results">No log entries match — <a href="#" onclick="clearFilters();return false;" style="color:var(--blue)">clear filters</a></div>
    </div>
    <div class="pag">
      <span class="pag-info" id="pag-info">—</span>
      <div class="pag-btns" id="pagBtns"></div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-header">
      <span class="panel-title">Live Alert Feed</span>
      <span class="panel-tag" id="feed-tag">0 alerts</span>
    </div>
    <div class="alert-feed" id="alertFeed">
      <div class="empty-feed">Waiting for real alerts...<br>Run your detector:<br><br>sudo python3 -m detector.main</div>
    </div>
  </div>
</div>

<div class="bottom-grid">
  <div class="panel">
    <div class="panel-header"><span class="panel-title">Entropy Analysis</span><span class="panel-tag">threshold 3.5 bits</span></div>
    <div class="ent-list" id="entList"></div>
  </div>
  <div class="panel">
    <div class="panel-header"><span class="panel-title">Detection Checks Fired</span><span class="panel-tag">6 methods</span></div>
    <div class="checks-grid" id="checksGrid"></div>
  </div>
  <div class="panel">
    <div class="panel-header"><span class="panel-title">config.yaml Active</span><span class="panel-tag">live settings</span></div>
    <div class="cfg-list">
      <div class="cfg-row"><span class="cfg-key">icmp_payload_threshold</span><span class="cfg-val">20 bytes</span></div>
      <div class="cfg-row"><span class="cfg-key">entropy_threshold</span><span class="cfg-val">3.5 bits (raw)</span></div>
      <div class="cfg-row"><span class="cfg-key">dns_query_count_threshold</span><span class="cfg-val">3 queries</span></div>
      <div class="cfg-row"><span class="cfg-key">dns_time_window</span><span class="cfg-val">30 seconds</span></div>
      <div class="cfg-row"><span class="cfg-key">bpf_filter</span><span class="cfg-val">icmp or udp port 53</span></div>
      <div class="cfg-row"><span class="cfg-key">suspicious_labels</span><span class="cfg-val">covertchannel, tunnel…</span></div>
      <div class="cfg-row"><span class="cfg-key">show_decoded_payload</span><span class="cfg-val c-green">true</span></div>
    </div>
  </div>
</div>
<div class="status-bar" id="statusBar">Connecting to /api/stream...</div>
</div>

<script>
let allEntries = [], filtered = [], sortKey = 'ts_epoch', sortAsc = false, page = 0;
const PER = 12;

// ── Fetch initial logs from Flask API ────────────────────────────────────
async function loadLogs() {
  try {
    const r = await fetch('/api/logs');
    const d = await r.json();
    allEntries = d.entries;
    filtered = [...allEntries];
    renderAll(d.stats);
    document.getElementById('log-count').textContent = d.total + ' entries';
  } catch(e) {
    document.getElementById('statusBar').textContent = 'Error connecting to Flask server: ' + e.message;
  }
}

// ── Check log file path ──────────────────────────────────────────────────
async function checkLogPath() {
  try {
    const r = await fetch('/api/log_path');
    const d = await r.json();
    const el = document.getElementById('logPathTag');
    el.textContent = d.path;
    el.className = 'logpath ' + (d.exists ? 'ok' : 'missing');
    if (!d.exists) el.title = 'Log file not found — run the detector first';
  } catch(e) {}
}

// ── Server-Sent Events — real-time push from alerts.log watcher ──────────
function connectSSE() {
  const es = new EventSource('/api/stream');
  es.onmessage = (e) => {
    const d = JSON.parse(e.data);
    if (d.type === 'new_entries') {
      // Prepend new real entries
      allEntries = [...d.entries, ...allEntries];
      filtered = applyCurrentFilters(allEntries);
      page = 0;
      renderAll(null);
      // Flash new alerts in feed
      d.entries.forEach(entry => prependToFeed(entry));
      document.getElementById('log-count').textContent = allEntries.length + ' entries';
      document.getElementById('statusBar').textContent = `Last update: ${new Date().toLocaleTimeString()} — ${d.entries.length} new entry(s)`;
    } else if (d.type === 'init') {
      updateStats(d.stats);
      document.getElementById('statusBar').textContent = 'Connected to live stream ✓';
    } else if (d.type === 'heartbeat') {
      document.getElementById('statusBar').textContent = `Watching alerts.log... ${new Date().toLocaleTimeString()}`;
    }
  };
  es.onerror = () => {
    document.getElementById('statusBar').textContent = 'SSE disconnected — retrying...';
    setTimeout(connectSSE, 3000);
  };
}

// ── Render everything ────────────────────────────────────────────────────
function renderAll(stats) {
  renderTable();
  if (stats) updateStats(stats);
  else {
    // Compute stats locally from allEntries
    fetch('/api/stats').then(r=>r.json()).then(updateStats).catch(()=>{});
  }
  buildEntropyList();
  buildChecks();
  buildFeed();
}

function updateStats(s) {
  if (!s) return;
  setMetric('m-icmp', s.icmp_alerts);
  setMetric('m-dns', s.dns_alerts);
  setMetric('m-total', s.total_alerts);
  setMetric('m-entropy', s.high_entropy);
  setMetric('m-decoded', s.decoded_count);
  document.getElementById('feed-tag').textContent = s.total_alerts + ' alerts';
}
function setMetric(id, val) {
  const el = document.getElementById(id);
  el.textContent = val !== undefined ? val : '—';
}

// ── Table ────────────────────────────────────────────────────────────────
function renderTable() {
  const body = document.getElementById('logBody');
  const start = page * PER, end = Math.min(start + PER, filtered.length);
  body.innerHTML = '';
  document.getElementById('no-results').style.display = filtered.length ? 'none' : 'block';
  filtered.slice(start, end).forEach(e => {
    const sc = 'sev-' + e.sev.toLowerCase();
    const pc = 'proto-' + e.proto.toLowerCase();
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${(e.ts||'').split(' ')[1] || e.ts}</td>
      <td><span class="sev-tag ${sc}">${e.sev}</span></td>
      <td><span class="proto-tag ${pc}">${e.proto}</span></td>
      <td>${e.src}</td>
      <td>${e.dst}</td>
      <td title="${e.reason}">${e.reason}</td>
      <td class="decoded-col" title="${e.decoded||''}">${e.decoded || '—'}</td>
      <td style="color:${entropyColor(e.entropy)}">${e.entropy != null ? e.entropy.toFixed(2) : '—'}</td>
    `;
    body.appendChild(tr);
  });
  document.getElementById('pag-info').textContent = filtered.length ? `${start+1}–${end} of ${filtered.length}` : '0 results';
  renderPag();
}

function entropyColor(v) {
  if (v == null) return 'var(--hint)';
  if (v > 5) return 'var(--red)';
  if (v > 3.5) return 'var(--amber)';
  return 'var(--blue)';
}

function renderPag() {
  const total = Math.ceil(filtered.length / PER);
  const el = document.getElementById('pagBtns'); el.innerHTML = '';
  const add = (lbl, pg, active) => {
    const b = document.createElement('button');
    b.className = 'pag-btn' + (active ? ' active' : '');
    b.textContent = lbl; b.onclick = () => { page = pg; renderTable(); }; el.appendChild(b);
  };
  add('‹', Math.max(0, page-1));
  const s = Math.max(0, page-2), e2 = Math.min(total, s+5);
  for (let i = s; i < e2; i++) add(i+1, i, i===page);
  add('›', Math.min(total-1, page+1));
}

// ── Filters ──────────────────────────────────────────────────────────────
function applyCurrentFilters(entries) {
  const q   = document.getElementById('searchInput').value.toLowerCase().trim();
  const sev = document.getElementById('filtSev').value;
  const proto = document.getElementById('filtProto').value;
  const check = document.getElementById('filtCheck').value;
  return entries.filter(e => {
    if (sev   && e.sev   !== sev)   return false;
    if (proto && e.proto !== proto) return false;
    if (check && e.check !== check) return false;
    if (q && !(
      e.src.includes(q) || e.dst.includes(q) ||
      (e.reason||'').toLowerCase().includes(q) ||
      (e.decoded||'').toLowerCase().includes(q) ||
      (e.domain||'').toLowerCase().includes(q)
    )) return false;
    return true;
  });
}
function applyFilters() { filtered = applyCurrentFilters(allEntries); page = 0; renderTable(); }
function clearFilters() {
  ['searchInput','filtSev','filtProto','filtCheck'].forEach(id => { const el=document.getElementById(id); if(el.tagName==='INPUT') el.value=''; else el.value=''; });
  filtered = [...allEntries]; page = 0; renderTable();
}
function sortBy(k) {
  if (sortKey===k) sortAsc=!sortAsc; else { sortKey=k; sortAsc=false; }
  const d = sortAsc ? 1 : -1;
  filtered.sort((a,b) => { const av=a[k]||'', bv=b[k]||''; return av<bv?-d:av>bv?d:0; });
  renderTable();
}
document.getElementById('searchInput').addEventListener('keydown', e => { if (e.key==='Enter') applyFilters(); });

// ── Alert feed ───────────────────────────────────────────────────────────
function buildFeed() {
  const alerts = allEntries.filter(e => e.sev==='ALERT'||e.sev==='CRITICAL'||e.sev==='WARNING').slice(0,10);
  const feed = document.getElementById('alertFeed');
  if (!alerts.length) return;
  feed.innerHTML = '';
  alerts.forEach(a => feed.appendChild(makeFeedItem(a)));
}
function prependToFeed(a) {
  const feed = document.getElementById('alertFeed');
  // Remove empty state div if present
  const empty = feed.querySelector('.empty-feed');
  if (empty) empty.remove();
  feed.prepend(makeFeedItem(a));
  if (feed.children.length > 12) feed.lastChild.remove();
}
function makeFeedItem(a) {
  const sc = 'sev-' + a.sev.toLowerCase();
  const pc = 'proto-' + a.proto.toLowerCase();
  const el = document.createElement('div');
  el.className = 'alert-item ' + sc;
  el.innerHTML = `
    <div class="ai-header">
      <span><span class="sev-tag ${sc}">${a.sev}</span>&nbsp;<span class="proto-tag ${pc}">${a.proto}</span></span>
      <span class="ai-time">${(a.ts||'').split(' ')[1]||a.ts}</span>
    </div>
    <div class="ai-reason" title="${a.reason}">${a.reason}</div>
    <div class="ai-route">${a.src} → ${a.dst}</div>
    ${a.decoded ? `<div class="ai-decoded">▶ DECODED: "${a.decoded}"</div>` : ''}
  `;
  return el;
}

// ── Entropy list ─────────────────────────────────────────────────────────
function buildEntropyList() {
  const el = document.getElementById('entList'); el.innerHTML = '';
  const withEnt = allEntries.filter(e=>e.entropy!=null).sort((a,b)=>b.entropy-a.entropy).slice(0,8);
  if (!withEnt.length) { el.innerHTML='<div style="font-family:var(--mono);font-size:11px;color:var(--hint);text-align:center;padding:16px">No entropy data yet</div>'; return; }
  withEnt.forEach(e => {
    const pct = Math.min(100, (e.entropy/8)*100);
    const col = e.entropy>5?'var(--red)':e.entropy>3.5?'var(--amber)':'var(--blue)';
    el.innerHTML += `<div class="ent-row">
      <span class="ent-label" title="${e.src}">${e.src}</span>
      <div class="ent-bar-bg"><div class="ent-bar-fill" style="width:${pct}%;background:${col}"></div></div>
      <span class="ent-val">${e.entropy.toFixed(2)}</span>
    </div>`;
  });
}

// ── Detection checks ─────────────────────────────────────────────────────
function buildChecks() {
  const el = document.getElementById('checksGrid'); el.innerHTML = '';
  const checks = [
    {name:'0xBEEF ID',key:'ICMP_ID_Fingerprint',col:'var(--red)',sub:'ICMP fingerprint'},
    {name:'Large Payload',key:'ICMP_Payload_Size',col:'var(--amber)',sub:'> 20 bytes'},
    {name:'High Entropy',key:'ICMP_Entropy',col:'var(--purple)',sub:'> 3.5 bits'},
    {name:'DNS Keyword',key:'DNS_Keyword',col:'var(--teal)',sub:'covertchannel etc'},
    {name:'Enc.Subdomain',key:'DNS_Label_Entropy',col:'var(--blue)',sub:'base64 label'},
    {name:'DNS Frequency',key:'DNS_Frequency',col:'var(--amber)',sub:'≥3/30s'},
  ];
  checks.forEach(c => {
    const count = allEntries.filter(e=>e.check===c.key).length;
    el.innerHTML += `<div class="check-item">
      <div class="check-name">${c.name}</div>
      <div class="check-val" style="color:${c.col}">${count}</div>
      <div class="check-sub">${c.sub}</div>
    </div>`;
  });
}

// ── Clock ────────────────────────────────────────────────────────────────
function tick(){const n=new Date();document.getElementById('clock').textContent=`${String(n.getHours()).padStart(2,'0')}:${String(n.getMinutes()).padStart(2,'0')}:${String(n.getSeconds()).padStart(2,'0')}`;}
tick(); setInterval(tick,1000);

// ── Boot ─────────────────────────────────────────────────────────────────
checkLogPath();
loadLogs().then(() => connectSSE());
</script>
</body>
</html>
"""

# ═══════════════════════════════════════════════════════════════════════════
# STARTUP
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("=" * 60)
    print("  COVERT CHANNEL DETECTOR — Web Dashboard")
    print("=" * 60)
    print(f"  Log file : {LOG_FILE}")
    print(f"  Exists   : {os.path.exists(LOG_FILE)}")
    print(f"  Dashboard: http://localhost:5000")
    print("=" * 60)

    if not os.path.exists(LOG_FILE):
        print(f"\n[WARN] Log file not found at: {LOG_FILE}")
        print("  Start the detector first:")
        print("    sudo python3 -m detector.main")
        print("  Then open http://localhost:5000\n")

    # Load initial logs
    _log_entries = load_all_logs()
    print(f"[INFO] Loaded {len(_log_entries)} existing log entries")

    # Start file watcher thread
    watcher = threading.Thread(target=_tail_log, daemon=True)
    watcher.start()
    print("[INFO] Log file watcher started\n")

    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
