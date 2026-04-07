#!/usr/bin/env python3
"""
RaspyJackProbe — Boot Mode Selector
Displays a mode menu on the Waveshare 1.44" LCD HAT.

KEY1 (BCM 21)      →  Mode 1: Anomaly Detector
KEY2 (BCM 20)      →  Mode 2: RaspyJack
KEY3 (BCM 16)      →  Mode 3: Bettercap Monitor (passive LAN/Wi-Fi + MITM toggle)
JOY UP (BCM 6)     →  Mode 4: Quick Scan (one-shot ARP → LCD → return)
JOY LEFT (BCM 5)   →  Mode 5: Wi-Fi Scanner (airodump-ng AP list)
JOY DOWN (BCM 19)  →  Mode 6: Port Scanner
JOY RIGHT (BCM 26) →  Mode 7: YouTube Stream (live RTMP via USB microscope cam)
JOY PRESS (BCM 13) →  Settings Portal
"""
import re
import sys, os, time, subprocess, threading, socket, json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, unquote_plus
import urllib.request, base64

sys.path.insert(0, '/root/Raspyjack')

import RPi.GPIO as GPIO
from PIL import Image, ImageDraw, ImageFont
import LCD_1in44
import LCD_Config

# ── Button pins (active LOW, internal pull-up) ──────────────────────────────
KEY1_PIN       = 21   # Anomaly Detector
KEY2_PIN       = 20   # RaspyJack
KEY3_PIN       = 16   # Bettercap Monitor
JOYSTICK_UP    = 6    # Quick Scan
JOYSTICK_DOWN  = 19   # Port Scanner
JOYSTICK_PRESS = 13   # Settings portal
JOYSTICK_LEFT  = 5    # Wi-Fi scanner in menu, MITM toggle inside Bettercap mode
JOYSTICK_RIGHT = 26   # YouTube Stream

_PROJECT_DIR  = '/root/RaspyJackProbe'
_CONFIG_PATH  = os.path.join(_PROJECT_DIR, 'config.json')
_EVENT_SERVER_PORT = 9090

# ── Event broadcaster ────────────────────────────────────────────────────────
# Shared in-memory ring buffer. Written by any thread, read by the HTTP server.
import collections
_event_lock   = threading.Lock()
_event_buffer = collections.deque(maxlen=50)
_current_mode = 'idle'


def _push_event(level: str, msg: str):
    """level: INFO | ALERT | BC | MODE"""
    ts = time.strftime('%H:%M:%S')
    entry = {'ts': ts, 'level': level, 'msg': msg}
    with _event_lock:
        _event_buffer.append(entry)


def _set_mode(name: str):
    global _current_mode
    _current_mode = name
    _push_event('MODE', f'Mode → {name}')

# ── Font helper ──────────────────────────────────────────────────────────────
_FONT_PATH_BOLD = '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'
_FONT_PATH      = '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'

def _font(path, size):
    try:
        return ImageFont.truetype(path, size)
    except Exception:
        return ImageFont.load_default()


# ── Display ──────────────────────────────────────────────────────────────────
def draw_menu(lcd, selected=None):
    img  = Image.new('RGB', (128, 128), color=(0, 0, 0))
    draw = ImageDraw.Draw(img)
    f8   = _font(_FONT_PATH, 8)
    f7   = _font(_FONT_PATH, 7)

    draw.rectangle([(0, 0), (128, 12)], fill=(0, 50, 120))
    draw.text((4, 2), 'RASPYJACKPROBE  v1.0', font=f7, fill=(255, 255, 255))

    modes = [
        (1, 'KEY1  Anomaly Det.',   'Standalone Watcher',   (0, 100, 50)),
        (2, 'KEY2  RaspyJack',      'Security Toolkit',     (180, 0, 60)),
        (3, 'KEY3  Bettercap Mon.', 'Passive Recon+MITM',   (0, 110, 140)),
        (4, 'JOY\u2191  Quick Scan', 'One-shot ARP Sweep',  (100, 60, 0)),
        (5, 'JOY\u2193  Port Scan',  'nmap All Hosts',      (60, 0, 120)),
        (6, 'JOY\u2190  WiFi Scan',  '2.4/5 GHz AP List',   (0, 90, 120)),
        (7, 'JOY\u2192  YT Stream',  'Live to YouTube',      (180, 20, 20)),
    ]
    for i, (num, title, sub, color) in enumerate(modes):
        y0 = 14 + i * 14
        y1 = y0 + 12
        bg = color if selected == num else (30, 30, 30)
        draw.rectangle([(3, y0), (124, y1)], fill=bg, outline=(60, 60, 60))
        draw.text((7, y0 + 1), title, font=f8, fill=(255, 255, 255))
        draw.text((7, y0 + 7), sub, font=f7, fill=(180, 180, 180))

    draw.line([(0, 112), (128, 112)], fill=(50, 50, 50))
    draw.text((4, 115), 'JOY\u25cf  \u2699 Settings Portal', font=f7, fill=(180, 140, 0))

    lcd.LCD_ShowImage(img, 0, 0)


def draw_selected(lcd, label, color):
    img  = Image.new('RGB', (128, 128), color=(0, 0, 0))
    draw = ImageDraw.Draw(img)
    f12b = _font(_FONT_PATH_BOLD, 12)
    f9   = _font(_FONT_PATH, 9)
    draw.rectangle([(0, 0), (128, 128)], fill=color)
    draw.text((10, 45), 'LAUNCHING', font=f12b, fill=(255, 255, 255))
    draw.text((10, 65), label, font=f9, fill=(220, 220, 220))
    lcd.LCD_ShowImage(img, 0, 0)


# ── Helpers ──────────────────────────────────────────────────────────────────
def _get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '?.?.?.?'


def _best_iface():
    """Return best interface for scanning: prefer wired (eth/en) over wireless."""
    try:
        out = subprocess.check_output(['ip', '-o', 'addr', 'show'], text=True)
        eth, wlan = [], []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4 or parts[2] != 'inet':
                continue
            name = parts[1]
            if name == 'lo':
                continue
            if name.startswith(('eth', 'en')):
                eth.append(name)
            elif name.startswith(('wlan', 'wl')):
                wlan.append(name)
        return eth[0] if eth else (wlan[0] if wlan else None)
    except Exception:
        return None


def _set_ip_forward(enable: bool):
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1\n' if enable else '0\n')
    except Exception as e:
        print(f'[ipforward] {e}')


_SYSCTL_IPFWD = '/etc/sysctl.d/99-probe-ipforward.conf'

def _apply_ip_forward_persistent(cfg):
    enabled = cfg.get('ip_forward_persistent', False)
    try:
        if enabled:
            with open(_SYSCTL_IPFWD, 'w') as f:
                f.write('# Managed by RaspyJackProbe settings portal\nnet.ipv4.ip_forward = 1\n')
        else:
            if os.path.exists(_SYSCTL_IPFWD):
                os.remove(_SYSCTL_IPFWD)
    except Exception as e:
        print(f'[ipforward] sysctl persistence: {e}')
    _set_ip_forward(enabled)


def _restore_ip_forward():
    try:
        cfg = json.load(open(_CONFIG_PATH))
    except Exception:
        cfg = {}
    _set_ip_forward(cfg.get('ip_forward_persistent', False))


# ── Reboot confirm ───────────────────────────────────────────────────────────
def _draw_reboot_confirm(lcd, yes_lit=False):
    img  = Image.new('RGB', (128, 128), (0, 0, 0))
    draw = ImageDraw.Draw(img)
    f8   = _font(_FONT_PATH, 8)
    f7   = _font(_FONT_PATH, 7)
    draw.rectangle([(0, 0), (128, 18)], fill=(180, 30, 0))
    draw.text((4, 4), '! REBOOT DEVICE ?', font=f8, fill=(255, 255, 0))
    draw.text((4, 30), f'JOY \u2191 = YES, REBOOT', font=f8,
              fill=(80, 255, 80) if yes_lit else (200, 255, 200))
    draw.line([(4, 50), (124, 50)], fill=(60, 60, 60))
    draw.text((4, 55), 'ANY KEY = NO, CANCEL', font=f8, fill=(200, 100, 100))
    draw.text((4, 90), 'Waiting 10s...', font=f7, fill=(80, 80, 80))
    lcd.LCD_ShowImage(img, 0, 0)


def _check_reboot_hold(lcd, joy_hold_count):
    if joy_hold_count < 15:
        return joy_hold_count
    print('[REBOOT] Hold detected — showing confirmation')
    _draw_reboot_confirm(lcd)
    deadline = time.monotonic() + 10
    ju_was = False
    while time.monotonic() < deadline:
        time.sleep(0.1)
        try:
            ju = GPIO.input(JOYSTICK_UP) == GPIO.LOW
            k1 = GPIO.input(KEY1_PIN)    == GPIO.LOW
            k2 = GPIO.input(KEY2_PIN)    == GPIO.LOW
            k3 = GPIO.input(KEY3_PIN)    == GPIO.LOW
        except Exception:
            return 0
        if ju and not ju_was:
            _draw_reboot_confirm(lcd, yes_lit=True)
            time.sleep(0.5)
            subprocess.run(['sudo', '/sbin/reboot'])
            return 0
        if k1 or k2 or k3:
            print('[REBOOT] Cancelled')
            break
        ju_was = ju
    return 0


# ── CYD Event / Command Server ───────────────────────────────────────────────
# Runs on port 9090 in a daemon thread. Never blocks the main loop.
#
#  GET  /status    → {"mode": "...", "device_count": N, "wifi_ap_count": N, "bettercap": bool}
#  GET  /events    → {"events": [{ts,level,msg}, ...]}  (newest last)
#  GET  /bettercap → {"interface": "...", "hosts": [...], "wifi_aps": [...], ...}
#  POST /cmd       → {"cmd": "anomaly_detector"|"raspyjack"|"bettercap"|"quick_scan"|"wifi_scan"|"stop"}

_cmd_queue       = []                # pending commands for main loop to consume
_cmd_lock        = threading.Lock()
_stop_event      = threading.Event() # set by CYD 'stop'/'rj_stop' to interrupt running modes
_bc_device_count = 0                 # updated by bettercap polling
_bc_wifi_ap_count = 0                # updated by bettercap polling
_bc_snapshot_lock = threading.Lock()
_cpu_snapshot    = None              # (idle_ticks, total_ticks) for delta CPU%
_loot_seen       = {}                # path → mtime, tracks RaspyJack loot changes
_align_cam       = None              # set while alignment mode is active; used by /snap HTTP handler


def _empty_bc_snapshot():
    return {
        'interface': '?',
        'wifi_interface': '',
        'modules': [],
        'hosts': [],
        'wifi_aps': [],
    }


_bc_snapshot = _empty_bc_snapshot()


def _set_bc_snapshot(snapshot=None):
    global _bc_snapshot, _bc_device_count, _bc_wifi_ap_count
    snap = snapshot or _empty_bc_snapshot()
    with _bc_snapshot_lock:
        _bc_snapshot = snap
    _bc_device_count = len(snap.get('hosts', []))
    _bc_wifi_ap_count = len(snap.get('wifi_aps', []))


class _CYDHandler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _cors(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Type', 'application/json')

    def do_GET(self):
        if self.path == '/status':
            with _event_lock:
                payload = json.dumps({
                    'mode': _current_mode,
                    'device_count': _bc_device_count,
                    'wifi_ap_count': _bc_wifi_ap_count,
                    'bettercap': _current_mode in ('bettercap', 'mitm'),
                }).encode()
            self.send_response(200); self._cors(); self.send_header('Content-Length', len(payload)); self.end_headers()
            self.wfile.write(payload)

        elif self.path == '/events':
            with _event_lock:
                events = list(_event_buffer)
            payload = json.dumps({'events': events}).encode()
            self.send_response(200); self._cors(); self.send_header('Content-Length', len(payload)); self.end_headers()
            self.wfile.write(payload)

        elif self.path == '/bettercap':
            with _bc_snapshot_lock:
                payload = json.dumps(_bc_snapshot).encode()
            self.send_response(200); self._cors(); self.send_header('Content-Length', len(payload)); self.end_headers()
            self.wfile.write(payload)

        elif self.path.startswith('/snap.jpg'):
            # Serve the snapshot with a rule-of-thirds overlay drawn on top
            if not os.path.exists(_YT_SNAP_PATH):
                self.send_response(404); self.end_headers(); return
            try:
                img  = Image.open(_YT_SNAP_PATH).convert('RGB')
                draw = ImageDraw.Draw(img)
                w, h = img.size
                for x in (w // 3, 2 * w // 3):
                    draw.line([(x, 0), (x, h)], fill=(255, 255, 80), width=2)
                for y in (h // 3, 2 * h // 3):
                    draw.line([(0, y), (w, y)], fill=(255, 255, 80), width=2)
                import io
                buf = io.BytesIO()
                img.save(buf, format='JPEG', quality=85)
                data = buf.getvalue()
                self.send_response(200)
                self.send_header('Content-Type', 'image/jpeg')
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Cache-Control', 'no-cache')
                self.end_headers()
                self.wfile.write(data)
            except Exception:
                self.send_response(500); self.end_headers()

        elif self.path == '/align':
            cam   = _align_cam
            cname = cam['name'] if cam else 'No camera selected'
            cmode = 'Press K1 on Pi or click Refresh Snapshot to update.'
            html  = f"""<!DOCTYPE html><html><head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Camera Alignment \u2014 RaspyJackProbe</title>
<style>
body{{background:#111;color:#eee;font-family:monospace;text-align:center;padding:14px;margin:0}}
h2{{color:#0af;margin:0 0 6px 0}}
.info{{color:#888;font-size:12px;margin-bottom:10px}}
img{{max-width:100%;width:640px;border:2px solid #333;display:block;margin:0 auto 10px auto;border-radius:4px}}
button{{padding:11px 22px;background:#0a6;color:#fff;border:none;border-radius:6px;font-size:14px;cursor:pointer;margin:4px}}
.status{{font-size:12px;color:#0af;min-height:16px;margin:6px 0}}
.hint{{font-size:11px;color:#555;margin-top:10px;line-height:1.5}}
</style></head><body>
<h2>\u25ce Camera Alignment</h2>
<div class="info">Camera: <b style="color:#fff">{cname}</b> &nbsp;|&nbsp; {cmode}</div>
<img id="snap" src="/snap.jpg?t=0" alt="Camera preview">
<div class="status" id="status">Auto-refreshing every 3 s</div>
<button onclick="refreshSnap()">&#128247; Refresh Snapshot</button>
<div class="hint">
  Yellow lines = rule-of-thirds guide.<br>
  Press <b>JOY \u25cf</b> on the Pi to go live once framing looks good.<br>
  Press <b>K2/K3</b> on the Pi to cancel back to the camera menu.
</div>
<script>
let autoTimer = setInterval(autoRefresh, 3000);
function stamp(){{ return '?t=' + Date.now(); }}
function autoRefresh(){{ document.getElementById('snap').src = '/snap.jpg' + stamp(); }}
function refreshSnap() {{
  const st = document.getElementById('status');
  st.textContent = 'Taking snapshot\u2026';
  clearInterval(autoTimer);
  fetch('/snap', {{method:'POST'}}).then(() => {{
    setTimeout(() => {{
      document.getElementById('snap').src = '/snap.jpg' + stamp();
      st.textContent = 'Auto-refreshing every 3 s';
      autoTimer = setInterval(autoRefresh, 3000);
    }}, 1500);
  }}).catch(() => {{
    st.textContent = 'Snap failed \u2014 check Pi connection';
    autoTimer = setInterval(autoRefresh, 3000);
  }});
}}
</script></body></html>""".encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(html)))
            self.end_headers()
            self.wfile.write(html)

        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        if self.path == '/snap':
            # Retake snapshot from the current alignment camera
            cam = _align_cam
            if cam:
                _take_snapshot(cam)
                resp = json.dumps({'ok': True}).encode()
                self.send_response(200)
            else:
                resp = json.dumps({'ok': False, 'error': 'not in alignment mode'}).encode()
                self.send_response(409)
            self._cors()
            self.send_header('Content-Length', len(resp))
            self.end_headers()
            self.wfile.write(resp)

        elif self.path == '/cmd':
            length = int(self.headers.get('Content-Length', 0))
            body   = self.rfile.read(length)
            try:
                data = json.loads(body)
                cmd  = data.get('cmd', '').strip()
                _valid = {
                    'anomaly_detector', 'raspyjack', 'bettercap', 'quick_scan', 'port_scan', 'wifi_scan',
                    'stop', 'rj_net_scan', 'rj_arp_scan', 'rj_loot', 'rj_stop', 'rj_port_scan',
                    'youtube_stream', 'youtube_stop',
                }
                if cmd in _valid:
                    with _cmd_lock:
                        _cmd_queue.append(cmd)
                    if cmd in ('stop', 'rj_stop'):
                        _stop_event.set()
                    resp = json.dumps({'ok': True, 'cmd': cmd}).encode()
                    self.send_response(200)
                else:
                    resp = json.dumps({'ok': False, 'error': 'unknown cmd'}).encode()
                    self.send_response(400)
            except Exception as e:
                resp = json.dumps({'ok': False, 'error': str(e)}).encode()
                self.send_response(400)
            self._cors(); self.send_header('Content-Length', len(resp)); self.end_headers()
            self.wfile.write(resp)
        else:
            self.send_response(404); self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200); self._cors(); self.end_headers()


def _start_cyd_server():
    try:
        srv = HTTPServer(('0.0.0.0', _EVENT_SERVER_PORT), _CYDHandler)
        t   = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        print(f'[CYD] event server on :{_EVENT_SERVER_PORT}')
    except Exception as e:
        print(f'[CYD] server failed: {e}')

    # Start background telemetry threads
    threading.Thread(target=_sysmon_ticker,  daemon=True).start()
    threading.Thread(target=_loot_watcher,   daemon=True).start()


def _sysmon_ticker():
    """Push system metrics (CPU/mem/temp/uptime) every 60 seconds."""
    global _cpu_snapshot
    time.sleep(15)   # give the system a moment to settle after boot
    while True:
        try:
            # CPU delta from /proc/stat
            with open('/proc/stat') as f:
                parts = [int(x) for x in f.readline().split()[1:]]
            idle  = parts[3] + (parts[4] if len(parts) > 4 else 0)
            total = sum(parts)
            if _cpu_snapshot:
                p_idle, p_total = _cpu_snapshot
                td = total - p_total
                cpu_pct = round(100.0 * (1.0 - (idle - p_idle) / td), 1) if td > 0 else 0.0
            else:
                cpu_pct = 0.0
            _cpu_snapshot = (idle, total)

            # Memory from /proc/meminfo
            mem = {}
            with open('/proc/meminfo') as f:
                for line in f:
                    k, v = line.split(':')
                    mem[k.strip()] = int(v.strip().split()[0]) * 1024
            mem_used  = (mem.get('MemTotal', 0) - mem.get('MemAvailable', mem.get('MemFree', 0))) // (1024 * 1024)
            mem_total = mem.get('MemTotal', 0) // (1024 * 1024)

            # Temperature
            try:
                raw  = open('/sys/class/thermal/thermal_zone0/temp').read().strip()
                temp = float(raw) / 1000.0 if float(raw) > 1000 else float(raw)
                temp_str = f'{temp:.0f}C'
            except Exception:
                temp_str = '?'

            # Uptime
            uptime_s = int(float(open('/proc/uptime').read().split()[0]))
            h, r = divmod(uptime_s, 3600)
            m    = r // 60

            _push_event('INFO', f'SYS cpu:{cpu_pct}% mem:{mem_used}/{mem_total}MB temp:{temp_str} up:{h}h{m}m')
        except Exception as e:
            print(f'[sysmon] {e}')
        time.sleep(60)


def _loot_watcher():
    """Watch /root/Raspyjack/loot/ for new or modified text files, push to CYD."""
    global _loot_seen
    _LOOT_DIR    = '/root/Raspyjack/loot'
    _SKIP_EXT    = {'.pcap', '.pyc', '.gitkeep'}
    _TEXT_LIMIT  = 10   # max lines to push per change

    time.sleep(20)  # let boot settle
    while True:
        try:
            for root, _, files in os.walk(_LOOT_DIR):
                for fname in files:
                    if fname.startswith('.'):
                        continue
                    ext = os.path.splitext(fname)[1].lower()
                    if ext in _SKIP_EXT:
                        continue
                    path = os.path.join(root, fname)
                    try:
                        mtime = os.path.getmtime(path)
                    except Exception:
                        continue
                    prev = _loot_seen.get(path)
                    if prev is None:
                        _loot_seen[path] = mtime   # first run: mark seen, don't push
                    elif prev != mtime:
                        _loot_seen[path] = mtime
                        try:
                            rel = os.path.relpath(path, _LOOT_DIR)
                            with open(path, errors='replace') as f:
                                lines = [l.rstrip() for l in f.readlines() if l.strip()]
                            _push_event('LOOT', f'[LOOT] {rel} ({len(lines)} lines)')
                            for ln in lines[-_TEXT_LIMIT:]:
                                _push_event('LOOT', f'  {ln[:58]}')
                        except Exception as e:
                            _push_event('LOOT', f'[LOOT] {fname}: {e}')
        except Exception as e:
            print(f'[loot_watcher] {e}')
        time.sleep(5)


# ── Settings portal ───────────────────────────────────────────────────────────
def _settings_html(cfg):
    def v(k, default=''):
        val = cfg.get(k, default)
        if isinstance(val, list):
            val = ', '.join(val)
        return str(val).replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')

    ip_fwd_checked = 'checked' if cfg.get('ip_forward_persistent', False) else ''

    current_otr = cfg.get('otr_station_url', _OTR_DEFAULT) or _OTR_DEFAULT
    otr_opts = ''
    matched = False
    for sname, surl in _OTR_STATIONS:
        sel = ' selected' if surl == current_otr else ''
        if sel:
            matched = True
        otr_opts += f'<option value="{surl}"{sel}>{sname}</option>\n'
    if not matched:
        otr_opts += f'<option value="{current_otr}" selected>Custom: {current_otr}</option>\n'
    return f"""<!DOCTYPE html><html><head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RaspyJackProbe Settings</title><style>
body{{background:#111;color:#eee;font-family:monospace;padding:16px;max-width:480px;margin:auto}}
h2{{color:#0af}}label{{display:block;margin-top:12px;color:#aaa;font-size:13px}}
input[type=text],input[type=password],input[type=number]{{width:100%;box-sizing:border-box;background:#222;color:#fff;border:1px solid #444;padding:6px;border-radius:4px;font-family:monospace;font-size:13px}}
.sec{{border-left:3px solid #0af;padding-left:10px;margin-top:20px}}
.sec h3{{color:#0af;margin:0 0 4px 0;font-size:14px}}
.hint{{font-size:11px;color:#666;margin-top:2px}}
.row{{display:flex;align-items:center;gap:8px;margin-top:10px}}
.row input{{width:auto}}
button{{margin-top:24px;width:100%;padding:12px;background:#0a6;color:#fff;border:none;border-radius:6px;font-size:16px;cursor:pointer}}
</style></head><body>
<h2>&#9881; RaspyJackProbe Settings</h2>
<p style="color:#666;font-size:12px">Saved to config.json &mdash; restart service to apply.</p>
<form method="POST" action="/save">

<div class="sec"><h3>Bettercap MITM Test</h3>
<label>Target IP</label>
<input type="text" name="mitm_target" value="{v('mitm_target')}">
<div class="hint">IP to ARP spoof &mdash; use your own phone/laptop for testing</div>
<label>DNS Spoof Domains</label>
<input type="text" name="mitm_dns_domains" value="{v('mitm_dns_domains')}">
<div class="hint">Comma-separated domains e.g. <i>*.google.com,*.facebook.com</i> &mdash; leave blank to skip</div>
<label>DNS Redirect IP</label>
<input type="text" name="mitm_dns_address" value="{v('mitm_dns_address')}">
<div class="hint">Where hijacked DNS queries point (blank = this Pi&apos;s IP)</div>
<div class="row">
<input type="checkbox" name="mitm_http_proxy" value="true" {"checked" if cfg.get("mitm_http_proxy", False) else ""}>
<span style="font-size:13px">Enable HTTP Proxy (intercept &amp; log plain HTTP)</span></div>
</div>

<div class="sec"><h3>Anomaly Detector</h3>
<label>Poll Interval (seconds)</label>
<input type="number" name="anomaly_poll_interval" value="{v('anomaly_poll_interval', '30')}">
<div class="hint">How often to query Bettercap for device changes (default: 30)</div>
<label>Spike Threshold (# new devices)</label>
<input type="number" name="anomaly_spike_threshold" value="{v('anomaly_spike_threshold', '3')}">
<div class="hint">How many new devices in one poll triggers a SPIKE alert (default: 3)</div>
</div>

<div class="sec"><h3>Network</h3>
<div class="row">
<input type="checkbox" name="ip_forward_persistent" value="true" {ip_fwd_checked}>
<span style="font-size:13px">Persistent IP Forwarding (survives reboot)</span></div>
<div class="hint">Writes <code style="color:#0af">net.ipv4.ip_forward=1</code> to <code style="color:#0af">/etc/sysctl.d/</code> &mdash; required for MITM. MITM mode sets this automatically while active.</div>
</div>

<div class="sec"><h3>YouTube Live Streaming</h3>
<label>Stream Key</label>
<input type="password" name="youtube_stream_key" value="{v('youtube_stream_key')}">
<div class="hint">From YouTube Studio &rarr; Go Live &rarr; Stream key. Stored locally &mdash; never leaves the Pi.</div>
<label>OTR Audio Station</label>
<select name="otr_station_url" style="width:100%;background:#222;color:#fff;border:1px solid #444;padding:6px;border-radius:4px;font-family:monospace;font-size:13px">
{otr_opts}</select>
<div class="hint">Live audio overlaid on stream &mdash; ROKiT Radio Network OTR streams. Default: 1940s Radio.</div>
</div>

<button type="submit">&#128190; Save Config</button>
</form></body></html>"""


def _draw_settings_screen(lcd, ip, port):
    img  = Image.new('RGB', (128, 128), (0, 0, 0))
    draw = ImageDraw.Draw(img)
    f9b  = _font(_FONT_PATH_BOLD, 9)
    f8   = _font(_FONT_PATH, 8)
    f7   = _font(_FONT_PATH, 7)
    draw.rectangle([(0, 0), (128, 14)], fill=(140, 100, 0))
    draw.text((4, 3), '\u2699 SETTINGS PORTAL', font=f8, fill=(255, 255, 255))
    draw.text((4, 20), 'Browse to:', font=f8, fill=(160, 160, 160))
    draw.text((4, 33), f'{ip}', font=f9b, fill=(0, 220, 255))
    draw.text((4, 47), f'port {port}', font=f8, fill=(0, 180, 200))
    draw.line([(0, 60), (128, 60)], fill=(50, 50, 50))
    draw.text((4, 64), 'from any device on', font=f7, fill=(130, 130, 130))
    draw.text((4, 74), 'your network.', font=f7, fill=(130, 130, 130))
    draw.text((4, 90), 'Press any KEY', font=f8, fill=(180, 180, 0))
    draw.text((4, 101), 'to cancel.', font=f8, fill=(130, 130, 130))
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_saved_screen(lcd):
    img  = Image.new('RGB', (128, 128), (0, 60, 0))
    draw = ImageDraw.Draw(img)
    f12b = _font(_FONT_PATH_BOLD, 12)
    f9   = _font(_FONT_PATH, 9)
    draw.text((10, 45), 'CONFIG SAVED', font=f12b, fill=(255, 255, 255))
    draw.text((10, 68), 'Returning to menu', font=f9, fill=(180, 255, 180))
    lcd.LCD_ShowImage(img, 0, 0)


def launch_settings_portal(lcd):
    local_ip = _get_local_ip()
    PORT     = 8090
    _draw_settings_screen(lcd, local_ip, PORT)
    saved    = threading.Event()

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass

        def do_GET(self):
            try:
                cfg = json.load(open(_CONFIG_PATH))
            except Exception:
                cfg = {}
            html = _settings_html(cfg).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(html)))
            self.end_headers()
            self.wfile.write(html)

        def do_POST(self):
            length = int(self.headers.get('Content-Length', 0))
            body   = self.rfile.read(length).decode()
            params = parse_qs(body)

            def get(key, default=''):
                vals = params.get(key, [default])
                return unquote_plus(vals[0]) if vals else default

            try:
                cfg = json.load(open(_CONFIG_PATH))
            except Exception:
                cfg = {}

            cfg['mitm_target']      = get('mitm_target').strip()
            cfg['mitm_dns_domains'] = get('mitm_dns_domains').strip()
            cfg['mitm_dns_address'] = get('mitm_dns_address').strip()
            cfg['mitm_http_proxy']  = (get('mitm_http_proxy') == 'true')
            cfg['ip_forward_persistent'] = (get('ip_forward_persistent') == 'true')
            cfg['youtube_stream_key'] = get('youtube_stream_key').strip()
            cfg['otr_station_url']    = get('otr_station_url').strip() or _OTR_DEFAULT

            try:
                cfg['anomaly_poll_interval'] = int(get('anomaly_poll_interval', '30'))
            except ValueError:
                cfg['anomaly_poll_interval'] = 30
            try:
                cfg['anomaly_spike_threshold'] = int(get('anomaly_spike_threshold', '3'))
            except ValueError:
                cfg['anomaly_spike_threshold'] = 3

            with open(_CONFIG_PATH, 'w') as f:
                json.dump(cfg, f, indent=4)

            _apply_ip_forward_persistent(cfg)

            resp = b"""<html><body style="background:#111;color:#0f0;font-family:monospace;padding:20px">
<h2>&#10003; Config Saved!</h2>
<p>You can close this page. Press any button on the device to return to the menu.</p>
</body></html>"""
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            saved.set()

    server = HTTPServer(('0.0.0.0', PORT), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    k1w = k2w = k3w = False
    while not saved.is_set():
        time.sleep(0.1)
        k1 = GPIO.input(KEY1_PIN) == GPIO.LOW
        k2 = GPIO.input(KEY2_PIN) == GPIO.LOW
        k3 = GPIO.input(KEY3_PIN) == GPIO.LOW
        if (k1 and not k1w) or (k2 and not k2w) or (k3 and not k3w):
            break
        k1w, k2w, k3w = k1, k2, k3

    server.shutdown()
    if saved.is_set():
        _draw_saved_screen(lcd)
        time.sleep(2)

    os.execv(sys.executable, [sys.executable] + sys.argv)


# ── Bettercap helpers ─────────────────────────────────────────────────────────
_BC_API  = 'http://localhost:8081/api/session'
_BC_AUTH = base64.b64encode(b'user:pass').decode()
_BC_DASH_SCRIPT = os.path.join(_PROJECT_DIR, 'bc_dashboard.py')
_BC_PASSIVE_CAP = '/tmp/probe-passive.cap'
_MITM_CAP = '/tmp/probe-mitm.cap'
_AIRMON_BIN = '/usr/sbin/airmon-ng'
_NMCLI_BIN  = '/usr/bin/nmcli'


def _wireless_ifaces():
    try:
        out = subprocess.check_output(['ip', '-o', 'link', 'show'], text=True)
        ifaces = []
        for line in out.splitlines():
            parts = line.split(':', 2)
            if len(parts) < 2:
                continue
            name = parts[1].strip()
            if (name != 'lo' and
                name.startswith(('wlan', 'wl')) and
                not name.endswith('mon')):
                ifaces.append(name)
        return ifaces
    except Exception:
        return []


def _best_wifi_iface(primary_iface=None):
    """Prefer a secondary wireless interface for passive Wi-Fi recon."""
    try:
        out = subprocess.check_output(['ip', '-o', '-4', 'addr', 'show'], text=True)
        with_ipv4 = {
            line.split()[1]
            for line in out.splitlines()
            if len(line.split()) >= 4 and line.split()[2] == 'inet'
        }
    except Exception:
        with_ipv4 = set()

    candidates = [iface for iface in _wireless_ifaces() if iface != primary_iface]
    if not candidates:
        return None

    no_ipv4 = [iface for iface in candidates if iface not in with_ipv4]
    return (no_ipv4 or candidates)[0]


def _existing_monitor_iface():
    try:
        out = subprocess.check_output(['ip', '-o', 'link', 'show'], text=True)
        monitors = []
        for line in out.splitlines():
            parts = line.split(':', 2)
            if len(parts) < 2:
                continue
            name = parts[1].strip()
            if name.startswith(('wlan', 'wl')) and name.endswith('mon'):
                monitors.append(name)
        return monitors[0] if monitors else None
    except Exception:
        return None


def _ipv4_sort_key(value):
    try:
        return [int(part) for part in value.split('.')]
    except Exception:
        return [999, 999, 999, 999]


def _normalize_hosts(hosts, limit=32):
    items = []
    for host in hosts or []:
        ip = (host.get('ipv4') or '').strip()
        mac = (host.get('mac') or '').strip().lower()
        if not ip and not mac:
            continue
        items.append({
            'ipv4': ip,
            'mac': mac,
            'hostname': (host.get('hostname') or '').strip(),
            'vendor': (host.get('vendor') or '').strip(),
        })
    items.sort(key=lambda item: _ipv4_sort_key(item.get('ipv4', '')))
    return items[:limit]


def _normalize_wifi_aps(aps, limit=32):
    items = []
    for ap in aps or []:
        essid = (ap.get('hostname') or ap.get('alias') or '').strip()
        enc = (ap.get('encryption') or '').strip()
        cipher = (ap.get('cipher') or '').strip()
        auth = (ap.get('authentication') or '').strip()
        if enc and cipher:
            security = f'{enc}/{cipher}'
        elif enc and auth:
            security = f'{enc}/{auth}'
        else:
            security = enc or auth or 'OPEN'
        items.append({
            'essid': essid,
            'bssid': (ap.get('mac') or '').strip().lower(),
            'channel': ap.get('channel') or 0,
            'rssi': ap.get('rssi') or 0,
            'security': security,
        })
    items.sort(key=lambda item: (item.get('rssi', -999), item.get('essid', '')), reverse=True)
    return items[:limit]


def _bc_fetch():
    try:
        req = urllib.request.Request(
            _BC_API, headers={'Authorization': f'Basic {_BC_AUTH}'}
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
        iface   = data.get('interface', {}).get('name') or '?'
        modules = [m['name'] for m in data.get('modules', []) if m.get('running')]
        hosts   = _normalize_hosts(data.get('lan', {}).get('hosts', []))
        wifi_aps = _normalize_wifi_aps(data.get('wifi', {}).get('aps', []))
        return {
            'iface': iface,
            'modules': modules,
            'hosts': hosts,
            'wifi_aps': wifi_aps,
            'host_count': len(hosts),
            'wifi_ap_count': len(wifi_aps),
        }
    except Exception:
        return None


def _write_passive_cap(wifi_iface=None):
    lines = [
        'set net.probe.throttle 100',
        'net.probe on',
        'set api.rest.username user',
        'set api.rest.password pass',
        'set api.rest.port 8081',
        'set api.rest.address 0.0.0.0',
        'set api.rest.websocket true',
        'api.rest on',
    ]
    if wifi_iface:
        lines += [
            f'set wifi.interface {wifi_iface}',
            'wifi.recon on',
        ]
    with open(_BC_PASSIVE_CAP, 'w') as f:
        f.write('\n'.join(lines) + '\n')


def _start_monitor_iface(wifi_iface):
    if not wifi_iface:
        return None, None
    if not os.path.exists(_AIRMON_BIN):
        return None, 'airmon-ng not installed'

    if os.path.exists(_NMCLI_BIN):
        subprocess.run(
            [_NMCLI_BIN, 'device', 'set', wifi_iface, 'managed', 'no'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    result = subprocess.run(
        [_AIRMON_BIN, 'start', wifi_iface],
        capture_output=True,
        text=True,
    )
    output = '\n'.join(part for part in (result.stdout, result.stderr) if part).strip()

    mon_iface = None
    match = re.search(r'on \[phy\d+\](\S+)', output)
    if match:
        mon_iface = match.group(1)
    elif os.path.exists(f'/sys/class/net/{wifi_iface}mon'):
        mon_iface = f'{wifi_iface}mon'

    if mon_iface and os.path.exists(f'/sys/class/net/{mon_iface}'):
        return mon_iface, None

    if output:
        return None, output.splitlines()[-1]
    return None, f'could not enable monitor mode on {wifi_iface}'


def _stop_monitor_iface(monitor_iface, wifi_iface):
    if not wifi_iface and monitor_iface and monitor_iface.endswith('mon'):
        wifi_iface = monitor_iface[:-3]
    if monitor_iface and os.path.exists(_AIRMON_BIN):
        subprocess.run(
            [_AIRMON_BIN, 'stop', monitor_iface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    if wifi_iface and os.path.exists(_NMCLI_BIN):
        subprocess.run(
            [_NMCLI_BIN, 'device', 'set', wifi_iface, 'managed', 'yes'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def _terminate_proc(proc):
    if not proc:
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        pass


def _start_bettercap_passive():
    primary_iface = _best_iface()
    monitor_iface = _existing_monitor_iface()
    wifi_iface = monitor_iface[:-3] if monitor_iface and monitor_iface.endswith('mon') else None
    wifi_error = None
    if not monitor_iface:
        wifi_iface = _best_wifi_iface(primary_iface)
        monitor_iface, wifi_error = _start_monitor_iface(wifi_iface)
    _write_passive_cap(monitor_iface)

    subprocess.run(['systemctl', 'stop', 'bettercap.service'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    cmd = ['/usr/bin/bettercap', '-no-colors']
    if primary_iface:
        cmd += ['-iface', primary_iface]
    cmd += ['-caplet', _BC_PASSIVE_CAP]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return proc, primary_iface, wifi_iface, monitor_iface, wifi_error


def _generate_mitm_cap(target, dns_domains, dns_address, local_ip, http_proxy=False):
    lines = [
        f'set arp.spoof.targets {target}',
        'set arp.spoof.internal true',
        'arp.spoof on',
        'net.sniff on',
    ]
    if dns_domains:
        redirect = dns_address if dns_address else local_ip
        lines += [
            f'set dns.spoof.domains {dns_domains}',
            f'set dns.spoof.address {redirect}',
            'dns.spoof on',
        ]
    if http_proxy:
        lines += [
            'set http.proxy.port 8888',
            'set http.proxy.sslstrip true',
            'http.proxy on',
        ]
    lines += [
        'set api.rest.username user',
        'set api.rest.password pass',
        'set api.rest.port 8081',
        'set api.rest.address 0.0.0.0',
        'set api.rest.websocket true',
        'api.rest on',
    ]
    with open(_MITM_CAP, 'w') as f:
        f.write('\n'.join(lines) + '\n')


def _draw_bettercap_screen(lcd, local_ip, status, iface, modules, wifi_iface=None, wifi_ap_count=0):
    img  = Image.new('RGB', (128, 128), (0, 0, 0))
    draw = ImageDraw.Draw(img)
    f8b  = _font(_FONT_PATH_BOLD, 8)
    f8   = _font(_FONT_PATH, 8)
    f7   = _font(_FONT_PATH, 7)

    hdr_col = (0, 110, 140) if status == 'running' else (100, 60, 0)
    draw.rectangle([(0, 0), (128, 14)], fill=hdr_col)
    draw.text((4, 3), f'BETTERCAP  {status.upper()}', font=f7, fill=(255, 255, 255))

    y = 18
    draw.text((4, y), f'IF: {iface}', font=f8, fill=(150, 200, 255)); y += 12
    wifi_text = f'WiFi: {wifi_iface}  APs: {wifi_ap_count}' if wifi_iface else 'WiFi: passive off'
    draw.text((4, y), wifi_text[:27], font=f7, fill=(255, 190, 80)); y += 10
    draw.line([(0, y), (128, y)], fill=(40, 40, 40)); y += 4

    if modules:
        draw.text((4, y), 'MODULES:', font=f7, fill=(120, 120, 120)); y += 10
        for m in modules[:4]:
            draw.text((6, y), f'\u25b6 {m}', font=f7, fill=(80, 220, 120)); y += 9
    else:
        draw.text((4, y), 'Starting modules...', font=f7, fill=(160, 120, 0)); y += 10

    y = max(y + 4, 84)
    draw.line([(0, y), (128, y)], fill=(40, 40, 40)); y += 4
    draw.text((4, y), 'Web UI:', font=f7, fill=(120, 120, 120)); y += 9
    draw.text((4, y), f'{local_ip}:8082', font=f8b, fill=(0, 220, 255)); y += 12
    draw.text((4, 118), 'KEY1/2/3 = back  JOY\u2190=MITM', font=f7, fill=(80, 80, 80))

    lcd.LCD_ShowImage(img, 0, 0)


def _draw_mitm_screen(lcd, target, dns_on, http_proxy_on, local_ip):
    img  = Image.new('RGB', (128, 128), (0, 0, 0))
    draw = ImageDraw.Draw(img)
    f9b  = _font(_FONT_PATH_BOLD, 9)
    f8   = _font(_FONT_PATH, 8)
    f7   = _font(_FONT_PATH, 7)
    draw.rectangle([(0, 0), (128, 18)], fill=(160, 0, 0))
    draw.text((4, 4), '!! MITM ACTIVE !!', font=f9b, fill=(255, 255, 0))
    draw.text((4, 22), 'Target:', font=f7, fill=(180, 180, 180))
    draw.text((4, 32), target or '(none set)', font=f8, fill=(255, 80, 80))
    draw.text((4, 46), 'ARP Spoof: ON', font=f7, fill=(80, 255, 80))
    dns_col   = (80, 255, 80) if dns_on        else (100, 100, 100)
    proxy_col = (80, 255, 80) if http_proxy_on else (100, 100, 100)
    draw.text((4, 57), f'DNS Spoof: {"ON" if dns_on else "OFF"}',              font=f7, fill=dns_col)
    draw.text((4, 68), f'HTTP Proxy: {"ON :8888" if http_proxy_on else "OFF"}', font=f7, fill=proxy_col)
    draw.line([(4, 80), (124, 80)], fill=(60, 60, 60))
    draw.text((4, 84), 'JOY\u2190 = stop MITM',  font=f7, fill=(200, 200, 0))
    draw.text((4, 94), 'KEY = exit mode',          font=f7, fill=(150, 150, 150))
    draw.text((4, 108), f'{local_ip}:8082',         font=f8, fill=(0, 180, 255))
    lcd.LCD_ShowImage(img, 0, 0)


# ── Mode: Bettercap Monitor ──────────────────────────────────────────────────
def launch_bettercap(lcd):
    draw_selected(lcd, 'Bettercap', (0, 80, 110))
    time.sleep(0.8)
    _set_mode('bettercap')

    bc_proc, _, wifi_iface, monitor_iface, wifi_error = _start_bettercap_passive()

    dash_proc = subprocess.Popen(
        [sys.executable, _BC_DASH_SCRIPT],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    local_ip  = _get_local_ip()
    mitm_proc = None
    mitm_on   = False
    wifi_label = monitor_iface or wifi_iface
    if wifi_error:
        _push_event('BC', f'WiFi recon unavailable: {wifi_error}')
    _set_bc_snapshot({'interface': '?', 'wifi_interface': wifi_label or '', 'modules': [], 'hosts': [], 'wifi_aps': []})
    _draw_bettercap_screen(lcd, local_ip, 'starting', '?', [], wifi_label, 0)

    k1w = k2w = k3w = jlw = False
    joy_hold = 0

    while True:
        time.sleep(2)

        if not mitm_on:
            result = _bc_fetch()
            if result:
                iface = result['iface']
                modules = result['modules']
                global _bc_device_count, _bc_wifi_ap_count
                _bc_device_count = result['host_count']
                _bc_wifi_ap_count = result['wifi_ap_count']
                _set_bc_snapshot({
                    'interface': iface,
                    'wifi_interface': wifi_label or '',
                    'modules': modules,
                    'hosts': result['hosts'],
                    'wifi_aps': result['wifi_aps'],
                })
                summary = f'BC: {len(modules)} modules, {_bc_device_count} hosts'
                if wifi_label:
                    summary += f', {_bc_wifi_ap_count} APs'
                _push_event('BC', summary)
                _draw_bettercap_screen(lcd, local_ip, 'running', iface, modules, wifi_label, _bc_wifi_ap_count)
            else:
                _set_bc_snapshot({'interface': '?', 'wifi_interface': wifi_label or '', 'modules': [], 'hosts': [], 'wifi_aps': []})
                _draw_bettercap_screen(lcd, local_ip, 'starting', '?', [], wifi_label, 0)

        k1 = GPIO.input(KEY1_PIN)       == GPIO.LOW
        k2 = GPIO.input(KEY2_PIN)       == GPIO.LOW
        k3 = GPIO.input(KEY3_PIN)       == GPIO.LOW
        jl = GPIO.input(JOYSTICK_LEFT)  == GPIO.LOW
        jp = GPIO.input(JOYSTICK_PRESS) == GPIO.LOW
        joy_hold = (joy_hold + 1) if jp else 0
        joy_hold = _check_reboot_hold(lcd, joy_hold)

        if jl and not jlw:
            if not mitm_on:
                try:
                    cfg = json.load(open(_CONFIG_PATH))
                except Exception:
                    cfg = {}
                target     = cfg.get('mitm_target', '').strip()
                dns_dom    = cfg.get('mitm_dns_domains', '').strip()
                dns_addr   = cfg.get('mitm_dns_address', '').strip()
                http_proxy = cfg.get('mitm_http_proxy', False)
                if target:
                    _terminate_proc(bc_proc)
                    _stop_monitor_iface(monitor_iface, wifi_iface)
                    bc_proc = None
                    monitor_iface = None
                    _set_bc_snapshot()
                    subprocess.run(['systemctl', 'stop', 'bettercap.service'],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    time.sleep(1)
                    _generate_mitm_cap(target, dns_dom, dns_addr, local_ip, http_proxy)
                    _set_ip_forward(True)
                    mitm_proc = subprocess.Popen(
                        ['/usr/bin/bettercap', '-no-colors', '-caplet', _MITM_CAP],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                    mitm_on = True
                    _set_mode('mitm')
                    _draw_mitm_screen(lcd, target, bool(dns_dom), http_proxy, local_ip)
                    print(f'[MITM] started → target={target}')
            else:
                if mitm_proc:
                    _terminate_proc(mitm_proc)
                    mitm_proc = None
                _restore_ip_forward()
                mitm_on = False
                _set_mode('bettercap')
                bc_proc, _, wifi_iface, monitor_iface, wifi_error = _start_bettercap_passive()
                wifi_label = monitor_iface or wifi_iface
                if wifi_error:
                    _push_event('BC', f'WiFi recon unavailable: {wifi_error}')
                _set_bc_snapshot({'interface': '?', 'wifi_interface': wifi_label or '', 'modules': [], 'hosts': [], 'wifi_aps': []})
                _draw_bettercap_screen(lcd, local_ip, 'starting', '?', [], wifi_label, 0)
                print('[MITM] stopped — back to passive recon')

        if (k1 and not k1w) or (k2 and not k2w) or (k3 and not k3w):
            _terminate_proc(mitm_proc)
            _terminate_proc(bc_proc)
            _stop_monitor_iface(monitor_iface, wifi_iface)
            _set_bc_snapshot()
            _restore_ip_forward()
            _terminate_proc(dash_proc)
            subprocess.run(['systemctl', 'stop', 'bettercap.service'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            os.execv(sys.executable, [sys.executable] + sys.argv)

        k1w, k2w, k3w = k1, k2, k3
        jlw = jl


# ── Mode: Anomaly Detector ───────────────────────────────────────────────────
def launch_anomaly_detector(lcd):
    draw_selected(lcd, 'Anomaly Det.', (0, 80, 40))
    time.sleep(0.8)
    _set_mode('anomaly_detector')
    sys.path.insert(0, _PROJECT_DIR)
    import anomaly_detector
    # Patch anomaly_detector's _log so events also go to the CYD buffer
    _orig_log = anomaly_detector._log
    def _patched_log(msg):
        _orig_log(msg)
        if '[NEW]' in msg:   _push_event('ALERT', msg.strip())
        elif '[MAC]' in msg: _push_event('ALERT', msg.strip())
        elif '[SPIKE]' in msg: _push_event('ALERT', msg.strip())
        elif '[GONE]' in msg:  _push_event('ALERT', msg.strip())
        elif '[DETECTOR]' in msg: _push_event('INFO', msg.strip())
    anomaly_detector._log = _patched_log
    anomaly_detector.run(lcd, stop_event=_stop_event)
    _set_mode('idle')
    os.execv(sys.executable, [sys.executable] + sys.argv)


# ── RaspyJack CYD helpers ─────────────────────────────────────────────────────
def _get_subnet():
    """Return /24 subnet string for the best interface, e.g. '192.168.0.0/24'."""
    import re
    try:
        iface = _best_iface()
        r = subprocess.run(['ip', '-4', 'addr', 'show', iface], capture_output=True, text=True)
        m = re.search(r'inet (\d+\.\d+\.\d+)\.\d+/(\d+)', r.stdout)
        if m:
            return f'{m.group(1)}.0/{m.group(2)}'
    except Exception:
        pass
    return '192.168.0.0/24'


def _rj_run_scan(cmd_args, label):
    """Run a shell scan command, stream each output line as an RJ event."""
    _push_event('RJ', f'▷ {label}...')
    try:
        r = subprocess.run(cmd_args, capture_output=True, text=True, timeout=90)
        lines = [l.strip() for l in r.stdout.splitlines() if l.strip() and not l.startswith('#')]
        for ln in lines:
            _push_event('RJ', ln[:60])
        if not lines:
            _push_event('RJ', f'{label}: no results')
        if r.returncode != 0 and r.stderr.strip():
            _push_event('RJ', f'err: {r.stderr.strip()[:58]}')
    except subprocess.TimeoutExpired:
        _push_event('RJ', f'{label} timed out')
    except Exception as e:
        _push_event('RJ', f'{label} error: {e}')


def _rj_show_loot():
    """Push the newest loot file contents as LOOT events to the CYD terminal."""
    loot_dir = '/root/Raspyjack/loot'
    try:
        found = []
        for root, _, files in os.walk(loot_dir):
            for f in files:
                if not f.endswith('.pcap'):
                    found.append(os.path.join(root, f))
        found.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        for fpath in found[:3]:
            rel = os.path.relpath(fpath, loot_dir)
            try:
                with open(fpath) as fh:
                    lines = [l.rstrip() for l in fh if l.strip()]
                _push_event('LOOT', f'── {rel} ──')
                for ln in lines[-8:]:
                    _push_event('LOOT', ln[:58])
            except Exception as e:
                _push_event('LOOT', f'{rel}: {e}')
        if not found:
            _push_event('LOOT', 'No loot files found yet')
    except Exception as e:
        _push_event('LOOT', f'loot error: {e}')


# ── Mode: RaspyJack ──────────────────────────────────────────────────────────
def launch_raspyjack(lcd):
    draw_selected(lcd, 'RaspyJack', (120, 0, 40))
    time.sleep(0.8)
    _set_mode('raspyjack')
    _stop_event.clear()

    # Kill any leftover bettercap/ettercap so they don't appear as "already running"
    # inside RaspyJack. IP forwarding is managed by RaspyJack itself.
    for proc_name in ('bettercap', 'ettercap'):
        try:
            result = subprocess.run(['pgrep', '-x', proc_name], capture_output=True, text=True)
            for pid in result.stdout.split():
                subprocess.run(['kill', pid])
            if result.stdout.strip():
                time.sleep(0.5)
        except Exception:
            pass
    _set_ip_forward(False)   # let RaspyJack enable this when it actually needs it

    # Release GPIO so raspyjack.py can take it, but keep the event server alive
    GPIO.cleanup()

    proc = subprocess.Popen(
        ['/usr/bin/python3', '/root/Raspyjack/raspyjack.py'],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, cwd='/root/Raspyjack'
    )

    _push_event('RJ', '▶ RaspyJack started')

    def _stream():
        for line in proc.stdout:
            line = line.rstrip()
            if line and not any(line.startswith(p) for p in ('[LCD]', 'GPIO', 'Traceback')):
                _push_event('RJ', line[:60])

    threading.Thread(target=_stream, daemon=True).start()

    def _rj_cmd_consumer():
        """Process CYD RJ commands while RaspyJack subprocess is running."""
        while proc.poll() is None:
            with _cmd_lock:
                pending = _cmd_queue.copy()
                _cmd_queue.clear()
            for c in pending:
                if c in ('stop', 'rj_stop'):
                    _push_event('RJ', '■ Stop — terminating RaspyJack')
                    proc.terminate()
                    return
                elif c == 'rj_net_scan':
                    threading.Thread(
                        target=_rj_run_scan,
                        args=(['nmap', '-sn', _get_subnet()], 'NET SCAN'),
                        daemon=True).start()
                elif c == 'rj_arp_scan':
                    iface = _best_iface()
                    threading.Thread(
                        target=_rj_run_scan,
                        args=(['arp-scan', f'--interface={iface}', '--localnet'], 'ARP SCAN'),
                        daemon=True).start()
                elif c == 'rj_port_scan':
                    subnet = _get_subnet()
                    threading.Thread(
                        target=_rj_run_scan,
                        args=(['nmap', '-T4', '-F', '--open', subnet], 'PORT SCAN'),
                        daemon=True).start()
                elif c == 'rj_loot':
                    threading.Thread(target=_rj_show_loot, daemon=True).start()
            time.sleep(0.5)

    threading.Thread(target=_rj_cmd_consumer, daemon=True).start()
    proc.wait()

    _push_event('RJ', f'■ RaspyJack exited (code {proc.returncode})')
    _set_mode('idle')
    # Restart mode_selector to re-init GPIO and LCD
    os.execv(sys.executable, [sys.executable] + sys.argv)


# ── Mode: Quick Scan ─────────────────────────────────────────────────────────
def launch_quick_scan(lcd):
    draw_selected(lcd, 'Quick Scan', (100, 60, 0))
    time.sleep(0.5)
    _set_mode('quick_scan')

    img  = Image.new('RGB', (128, 128), (0, 0, 0))
    draw = ImageDraw.Draw(img)
    f8   = _font(_FONT_PATH, 8)
    f7   = _font(_FONT_PATH, 7)
    draw.rectangle([(0, 0), (128, 14)], fill=(100, 60, 0))
    draw.text((4, 3), 'QUICK SCAN', font=f8, fill=(255, 200, 0))
    draw.text((4, 20), 'Running arp-scan...', font=f7, fill=(180, 180, 0))
    lcd.LCD_ShowImage(img, 0, 0)

    # Run arp-scan (fast, ships with Kali)
    try:
        result = subprocess.run(
            ['arp-scan', '--localnet', '--retry=2'],
            capture_output=True, text=True, timeout=20
        )
        lines = [l for l in result.stdout.splitlines()
                 if l and not l.startswith('Interface') and not l.startswith('Starting')
                 and not l.startswith('Ending') and '\t' in l]
        _push_event('INFO', f'Quick scan: {len(lines)} hosts found')
        for ln in lines[:10]:
            parts = ln.split('\t')
            _push_event('INFO', f'  {parts[0]}  {parts[1][:17] if len(parts)>1 else ""}')
    except Exception as e:
        lines = [str(e)]
        _push_event('ALERT', f'Scan error: {e}')

    # Display results on LCD
    img  = Image.new('RGB', (128, 128), (0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.rectangle([(0, 0), (128, 14)], fill=(100, 60, 0))
    draw.text((4, 3), f'SCAN DONE — {len(lines)} hosts', font=f7, fill=(255, 200, 0))
    y = 18
    for line in lines[:6]:
        parts = line.split('\t')
        ip  = parts[0] if len(parts) > 0 else '?'
        mac = parts[1][:11] if len(parts) > 1 else ''
        draw.text((4, y), ip,  font=f7, fill=(150, 220, 255))
        draw.text((68, y), mac, font=f7, fill=(100, 100, 100))
        y += 10
    if len(lines) > 6:
        draw.text((4, y), f'...+{len(lines)-6} more', font=f7, fill=(80, 80, 80))
    draw.text((4, 118), 'Press any KEY to exit', font=f7, fill=(80, 80, 80))
    lcd.LCD_ShowImage(img, 0, 0)

    # Wait for keypress
    while True:
        if (GPIO.input(KEY1_PIN) == GPIO.LOW or
                GPIO.input(KEY2_PIN) == GPIO.LOW or
                GPIO.input(KEY3_PIN) == GPIO.LOW or
                GPIO.input(JOYSTICK_UP) == GPIO.LOW):
            break
        time.sleep(0.05)

    _set_mode('idle')
    # Return to menu
    os.execv(sys.executable, [sys.executable] + sys.argv)


# ── Mode: Port Scanner ────────────────────────────────────────────────────────
def launch_port_scanner(lcd):
    draw_selected(lcd, 'Port Scanner', (40, 0, 80))
    time.sleep(0.8)
    _set_mode('port_scan')
    sys.path.insert(0, _PROJECT_DIR)
    import port_scanner
    # Bridge scanner events into CYD buffer
    port_scanner._push_event = _push_event
    port_scanner.run(lcd, key1=KEY1_PIN, key2=KEY2_PIN, key3=KEY3_PIN, stop_event=_stop_event)
    _set_mode('idle')
    os.execv(sys.executable, [sys.executable] + sys.argv)


def launch_wifi_scanner(lcd):
    global _bc_device_count, _bc_wifi_ap_count
    draw_selected(lcd, 'WiFi Scan', (0, 80, 110))
    time.sleep(0.8)
    _stop_event.clear()
    _set_mode('wifi_scan')
    _bc_device_count = 0
    _bc_wifi_ap_count = 0
    _set_bc_snapshot()
    sys.path.insert(0, _PROJECT_DIR)
    import wifi_scanner
    def _update_wifi_status(ap_count):
        global _bc_wifi_ap_count
        _bc_wifi_ap_count = ap_count
    wifi_scanner._push_event = _push_event
    wifi_scanner._status_update = _update_wifi_status
    wifi_scanner.run(lcd, key1=KEY1_PIN, key2=KEY2_PIN, key3=KEY3_PIN, stop_event=_stop_event)
    _set_mode('idle')
    os.execv(sys.executable, [sys.executable] + sys.argv)


# ── Mode: YouTube Stream ──────────────────────────────────────────────────────
_YT_SNAP_PATH  = '/tmp/yt_snap.jpg'
_YT_RTMP_BASE  = 'rtmp://a.rtmp.youtube.com/live2'
_YT_VIDEO_DEV  = '/dev/video0'

# ── OTR radio stations (ROKiT Radio Network, 48 kbps MP3 HTTP streams) ────────
_OTR_STATIONS = [
    ('1940s Radio',       'http://149.255.60.195:8256/stream'),
    ('American Comedy',   'http://149.255.60.193:8162/stream'),
    ('American Classics', 'http://149.255.60.194:8043/stream'),
    ('Jazz Central',      'http://149.255.60.195:8027/stream'),
    ('Comedy Gold',       'http://149.255.60.195:8150/stream'),
    ('Mystery Radio',     'http://149.255.60.195:8168/stream'),
    ('Crime & Suspense',  'http://149.255.60.193:8168/stream'),
    ('Crime Radio',       'http://149.255.60.194:8039/stream'),
    ('Adventure Stories', 'http://149.255.60.195:8162/stream'),
    ('Drama Radio',       'http://149.255.60.195:8174/stream'),
    ('Nostalgia Lane',    'http://149.255.60.195:8180/stream'),
    ('Science Fiction',   'http://149.255.60.194:8110/stream'),
]
_OTR_DEFAULT = 'http://149.255.60.195:8256/stream'  # 1940s Radio

def _otr_name_for_url(url):
    for name, u in _OTR_STATIONS:
        if u == url:
            return name
    return 'Custom Station'

# ── Camera profiles ────────────────────────────────────────────────────────────
# type 'usb' → v4l2 H264 device input (USB microscope, existing hardware)
# type 'csi' → rpicam-vid H264 pipe into ffmpeg (ribbon CSI cameras, Bookworm)
_YT_CAMERAS = [
    {'name': 'USB Microscope', 'short': 'USB-CAM',
     'type': 'usb', 'device': None, 'audio': 'silent',
     'width': 1280, 'height': 720,  'fps': 30},
    {'name': 'Arducam CSI',    'short': 'ARDUCAM',
     'type': 'csi', 'audio': 'otr',
     'width': 1280, 'height': 720,  'fps': 30},
    {'name': 'Pi Camera v2.1', 'short': 'PI-CAM',
     'type': 'csi', 'audio': 'otr',
     'width': 1280, 'height': 720,  'fps': 30},
    {'name': 'HQ Camera',      'short': 'HQ-CAM',
     'type': 'csi', 'audio': 'otr',
     'width': 1920, 'height': 1080, 'fps': 30},
]


def _find_usb_video_device():
    """Return the first /dev/videoN whose bus info contains 'usb' (case-insensitive).
    Falls back to /dev/video0 if nothing found."""
    try:
        import glob as _glob
        for dev in sorted(_glob.glob('/dev/video*')):
            try:
                out = subprocess.check_output(
                    ['v4l2-ctl', '-d', dev, '--info'],
                    stderr=subprocess.DEVNULL, text=True, timeout=2
                )
                if 'usb' in out.lower():
                    return dev
            except Exception:
                continue
    except Exception:
        pass
    return '/dev/video0'


def _draw_youtube_nokey_screen(lcd):
    img  = Image.new('RGB', (128, 128), (0, 0, 0))
    draw = ImageDraw.Draw(img)
    f8b  = _font(_FONT_PATH_BOLD, 8)
    f8   = _font(_FONT_PATH, 8)
    f7   = _font(_FONT_PATH, 7)
    draw.rectangle([(0, 0), (128, 14)], fill=(180, 0, 0))
    draw.text((4, 3), 'NO STREAM KEY', font=f8b, fill=(255, 255, 0))
    draw.text((4, 22), 'Open Settings Portal', font=f7, fill=(200, 200, 200))
    draw.text((4, 33), 'and enter your', font=f7, fill=(200, 200, 200))
    draw.text((4, 44), 'YouTube stream key.', font=f7, fill=(200, 200, 200))
    draw.line([(0, 58), (128, 58)], fill=(50, 50, 50))
    draw.text((4, 63), 'JOY\u25cf = Settings', font=f8, fill=(180, 140, 0))
    draw.text((4, 78), 'Any KEY = back', font=f7, fill=(120, 120, 120))
    lcd.LCD_ShowImage(img, 0, 0)


def _take_snapshot(cam):
    """Capture one frame from cam to _YT_SNAP_PATH. Returns True on success."""
    if cam['type'] == 'usb':
        try:
            r = subprocess.run(
                ['fswebcam', '-d', cam['device'], '-r', '640x480',
                 '--jpeg', '90', '--skip', '20', '--no-banner', _YT_SNAP_PATH],
                timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            return r.returncode == 0 and os.path.exists(_YT_SNAP_PATH)
        except Exception:
            return False
    else:
        try:
            r = subprocess.run(
                ['rpicam-still', '-o', _YT_SNAP_PATH,
                 '--width', '640', '--height', '480',
                 '--nopreview', '-t', '1000'],
                timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            return r.returncode == 0 and os.path.exists(_YT_SNAP_PATH)
        except Exception:
            return False


def _draw_align_screen(lcd, snap_loaded, cam_name):
    img  = Image.new('RGB', (128, 128), (0, 0, 0))
    draw = ImageDraw.Draw(img)
    f8b  = _font(_FONT_PATH_BOLD, 8)
    f7   = _font(_FONT_PATH, 7)

    # Paste snapshot into preview area (y=14 to y=104)
    if snap_loaded and os.path.exists(_YT_SNAP_PATH):
        try:
            snap = Image.open(_YT_SNAP_PATH).resize((128, 90))
            img.paste(snap, (0, 14))
        except Exception:
            pass

    draw.rectangle([(0, 0), (128, 14)], fill=(0, 100, 160))
    draw.text((4, 3), f'\u25ce ALIGN  {cam_name}', font=f8b, fill=(255, 255, 255))

    # Rule-of-thirds guide lines over preview area
    for x in (43, 85):
        draw.line([(x, 14), (x, 104)], fill=(255, 255, 80), width=1)
    for y in (44, 74):
        draw.line([(0, y), (128, y)], fill=(255, 255, 80), width=1)

    draw.rectangle([(0, 104), (128, 128)], fill=(0, 0, 0))
    draw.line([(0, 104), (128, 104)], fill=(50, 50, 50))
    draw.text((4,  107), 'K1=snap', font=f7, fill=(200, 200, 0))
    draw.text((50, 107), '\u25cf=LIVE', font=f7, fill=(80, 255, 80))
    draw.text((90, 107), 'K2=back', font=f7, fill=(160, 80, 80))
    draw.text((4,  118), ':9090/align \u2192 browser', font=f7, fill=(70, 140, 200))
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_youtube_camera_menu(lcd, selected_idx):
    img  = Image.new('RGB', (128, 128), (0, 0, 0))
    draw = ImageDraw.Draw(img)
    f8b  = _font(_FONT_PATH_BOLD, 8)
    f8   = _font(_FONT_PATH, 8)
    f7   = _font(_FONT_PATH, 7)
    draw.rectangle([(0, 0), (128, 14)], fill=(180, 20, 20))
    draw.text((4, 3), '\u25b6 SELECT CAMERA', font=f8b, fill=(255, 255, 255))
    labels = [
        ('USB Microscope', '720p30 \u00b7 USB'),
        ('Arducam CSI',    '720p30 \u00b7 Ribbon'),
        ('Pi Camera v2.1', '720p30 \u00b7 CSI'),
        ('HQ Camera',      '1080p30 \u00b7 CSI'),
    ]
    for i, (name, sub) in enumerate(labels):
        y0 = 17 + i * 23
        bg = (120, 20, 20) if i == selected_idx else (25, 25, 25)
        draw.rectangle([(2, y0), (125, y0 + 20)], fill=bg, outline=(60, 60, 60))
        prefix = '\u25ba ' if i == selected_idx else '  '
        draw.text((5,  y0 + 2),  prefix + name, font=f8, fill=(255, 255, 255))
        draw.text((14, y0 + 12), sub,            font=f7, fill=(160, 160, 160))
    draw.line([(0, 109), (128, 109)], fill=(50, 50, 50))
    draw.text((4, 111), '\u2191\u2193=sel  \u25cf=LIVE  \u2192=Setup', font=f7,
              fill=(130, 130, 130))
    draw.text((4, 120), 'K1/K2/K3 = cancel', font=f7, fill=(90, 90, 90))
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_youtube_live_screen(lcd, is_live, uptime_s, key_hint, snap_loaded,
                              cam_name='', station_name=''):
    img  = Image.new('RGB', (128, 128), (10, 0, 0))
    draw = ImageDraw.Draw(img)

    if snap_loaded and os.path.exists(_YT_SNAP_PATH):
        try:
            snap = Image.open(_YT_SNAP_PATH).resize((128, 128))
            img.paste(snap, (0, 0))
        except Exception:
            pass

    draw = ImageDraw.Draw(img)
    f8b  = _font(_FONT_PATH_BOLD, 8)
    f8   = _font(_FONT_PATH, 8)
    f7   = _font(_FONT_PATH, 7)

    hdr_col = (200, 0, 0) if is_live else (80, 80, 80)
    draw.rectangle([(0, 0), (128, 14)], fill=hdr_col)
    status_lbl = '\u25cf LIVE' if is_live else '\u25a0 STOPPED'
    draw.text((4, 3), f'YOUTUBE  {status_lbl}', font=f7, fill=(255, 255, 255))

    draw.rectangle([(0, 79), (128, 128)], fill=(0, 0, 0))
    h = uptime_s // 3600
    m = (uptime_s % 3600) // 60
    s = uptime_s % 60
    uptime_col = (80, 255, 80) if is_live else (150, 150, 150)
    cam_lbl = f'{cam_name}  key:{key_hint}' if cam_name else f'key:{key_hint}'
    draw.text((4, 81), cam_lbl[:22],                          font=f7, fill=(180, 180, 180))
    draw.text((4, 91), f'\u266a {station_name[:18]}',         font=f7, fill=(100, 180, 100))
    draw.text((4, 101), f'Up: {h:02d}:{m:02d}:{s:02d}',      font=f8b, fill=uptime_col)
    draw.line([(0, 112), (128, 112)], fill=(50, 50, 50))
    draw.text((4, 115), 'KEY1/2/3 = stop', font=f7, fill=(130, 130, 130))

    lcd.LCD_ShowImage(img, 0, 0)


def launch_youtube_stream(lcd):
    draw_selected(lcd, 'YT Stream', (180, 20, 20))
    time.sleep(0.5)

    try:
        cfg = json.load(open(_CONFIG_PATH))
    except Exception:
        cfg = {}

    stream_key = cfg.get('youtube_stream_key', '').strip()
    if not stream_key:
        _draw_youtube_nokey_screen(lcd)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if (GPIO.input(KEY1_PIN) == GPIO.LOW or
                    GPIO.input(KEY2_PIN) == GPIO.LOW or
                    GPIO.input(KEY3_PIN) == GPIO.LOW):
                break
            time.sleep(0.05)
        os.execv(sys.executable, [sys.executable] + sys.argv)
        return

    # ── Camera selection menu ─────────────────────────────────────────────────
    cam_idx       = 0
    ju_was = jd_was = jp_was = jr_was = False
    cam_confirmed = False
    align_mode    = False
    while True:
        _draw_youtube_camera_menu(lcd, cam_idx)
        time.sleep(0.05)
        ju = GPIO.input(JOYSTICK_UP)    == GPIO.LOW
        jd = GPIO.input(JOYSTICK_DOWN)  == GPIO.LOW
        jp = GPIO.input(JOYSTICK_PRESS) == GPIO.LOW
        jr = GPIO.input(JOYSTICK_RIGHT) == GPIO.LOW
        k1 = GPIO.input(KEY1_PIN)       == GPIO.LOW
        k2 = GPIO.input(KEY2_PIN)       == GPIO.LOW
        k3 = GPIO.input(KEY3_PIN)       == GPIO.LOW
        if ju and not ju_was:
            cam_idx = (cam_idx - 1) % len(_YT_CAMERAS)
        if jd and not jd_was:
            cam_idx = (cam_idx + 1) % len(_YT_CAMERAS)
        if jp and not jp_was:
            cam_confirmed = True          # JOY● → fast path: snap + go live
            align_mode    = False
            break
        if jr and not jr_was:
            cam_confirmed = True          # JOY→ → setup path: alignment mode first
            align_mode    = True
            break
        if k1 or k2 or k3:
            break
        ju_was, jd_was, jp_was, jr_was = ju, jd, jp, jr

    if not cam_confirmed:
        os.execv(sys.executable, [sys.executable] + sys.argv)
        return

    cam          = _YT_CAMERAS[cam_idx]
    # Resolve USB device dynamically so it works regardless of CSI/USB ordering
    if cam['type'] == 'usb':
        cam = dict(cam, device=_find_usb_video_device())
    otr_url      = cfg.get('otr_station_url', _OTR_DEFAULT).strip() or _OTR_DEFAULT
    station_name = _otr_name_for_url(otr_url)

    # ── Pre-stream alignment mode (JOY→ path only) ────────────────────────────
    global _align_cam
    _align_cam  = cam
    snap_loaded = _take_snapshot(cam)
    snap_mtime  = os.path.getmtime(_YT_SNAP_PATH) if os.path.exists(_YT_SNAP_PATH) else 0

    if align_mode:
        # Full setup loop — browser accessible, K1 retakes snap, JOY● goes live
        align_done  = False
        k1w = k2w = k3w = jp_was = False
        while True:
            _draw_align_screen(lcd, snap_loaded, cam['short'])
            time.sleep(0.1)

            # HTTP /snap handler may have refreshed the file from another thread
            try:
                mt = os.path.getmtime(_YT_SNAP_PATH)
                if mt != snap_mtime:
                    snap_mtime  = mt
                    snap_loaded = True
            except Exception:
                pass

            k1 = GPIO.input(KEY1_PIN)       == GPIO.LOW
            k2 = GPIO.input(KEY2_PIN)       == GPIO.LOW
            k3 = GPIO.input(KEY3_PIN)       == GPIO.LOW
            jp = GPIO.input(JOYSTICK_PRESS) == GPIO.LOW

            if k1 and not k1w:
                snap_loaded = _take_snapshot(cam)
                try:
                    snap_mtime = os.path.getmtime(_YT_SNAP_PATH)
                except Exception:
                    pass
            if jp and not jp_was:
                align_done = True
                break
            if (k2 and not k2w) or (k3 and not k3w):
                break
            k1w, k2w, k3w, jp_was = k1, k2, k3, jp

        _align_cam = None
        if not align_done:
            os.execv(sys.executable, [sys.executable] + sys.argv)
            return
    else:
        # Fast path — snapshot already taken above, clear global and go live
        _align_cam = None

    _set_mode('youtube_stream')
    _stop_event.clear()

    key_hint = f'****{stream_key[-4:]}' if len(stream_key) >= 4 else '****'
    rtmp_url  = f'{_YT_RTMP_BASE}/{stream_key}'

    # ── Build ffmpeg + optional libcamera-vid commands ────────────────────────
    w, h, fps = cam['width'], cam['height'], cam['fps']

    if cam['type'] == 'usb':
        libcam_cmd = None
        if cam.get('audio') == 'silent':
            audio_args = ['-f', 'lavfi', '-i', 'anullsrc=channel_layout=stereo:sample_rate=44100']
        else:
            audio_args = ['-i', otr_url]
        # H264 passthrough: camera encodes H264 natively; Pi just relays it.
        # Force a keyframe every 2s via v4l2-ctl so YouTube doesn't stall.
        # Re-encoding (MJPEG or H264→libx264) exceeds Pi Zero 2W CPU budget.
        subprocess.run(
            ['v4l2-ctl', '-d', cam['device'],
             '--set-ctrl=h264_i_frame_period=60'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        ffmpeg_cmd = [
            'ffmpeg',
            '-f', 'v4l2', '-input_format', 'h264',
            '-video_size', f'{w}x{h}', '-framerate', str(fps),
            '-i', cam['device'],
            *audio_args,
            '-map', '0:v', '-map', '1:a',
            '-c:v', 'copy',
            '-b:v', '2500k',
            '-c:a', 'aac', '-b:a', '128k',
            '-f', 'flv', rtmp_url,
        ]
    else:  # csi — rpicam-vid hardware encoder piped into ffmpeg
        libcam_cmd = [
            'rpicam-vid', '-t', '0',
            '--codec', 'h264',
            '--profile', 'high', '--level', '4.1',
            '--width',  str(w), '--height', str(h),
            '--framerate', str(fps),
            '--bitrate', '2500000',
            '--intra', str(fps * 2),
            '--inline', '--nopreview',
            '-o', '-',
        ]
        ffmpeg_cmd = [
            'ffmpeg',
            '-f', 'h264', '-i', 'pipe:0',
            '-i', otr_url,
            '-map', '0:v', '-map', '1:a',
            '-c:v', 'copy',
            '-c:a', 'aac', '-b:a', '128k',
            '-f', 'flv', rtmp_url,
        ]

    def _start_stream():
        if libcam_cmd:
            lc = subprocess.Popen(
                libcam_cmd,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
            )
            ff = subprocess.Popen(
                ffmpeg_cmd,
                stdin=lc.stdout,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            lc.stdout.close()  # transfer pipe ownership to ffmpeg
            return lc, ff
        return None, subprocess.Popen(
            ffmpeg_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

    libcam_proc, stream_proc = _start_stream()
    _push_event('YT', f'\u25b6 Stream \u2192 {cam["short"]} / {station_name[:12]}')

    start_time  = time.monotonic()
    k1w = k2w = k3w = False
    retries     = 0
    MAX_RETRIES = 5
    stopped     = False

    while not stopped:
        uptime_s = int(time.monotonic() - start_time)
        is_live  = stream_proc.poll() is None
        _draw_youtube_live_screen(
            lcd, is_live, uptime_s, key_hint,
            snap_loaded or os.path.exists(_YT_SNAP_PATH),
            cam_name=cam['short'], station_name=station_name,
        )

        if not is_live and not _stop_event.is_set():
            retries += 1
            if retries <= MAX_RETRIES:
                _push_event('YT', f'\u26a0 Connection lost — retry {retries}/{MAX_RETRIES}')
                _terminate_proc(libcam_proc)
                time.sleep(5)
                libcam_proc, stream_proc = _start_stream()
                continue
            else:
                _push_event('YT', f'\u25a0 Stream failed after {MAX_RETRIES} retries')
                time.sleep(3)
                stopped = True
                break

        if _stop_event.is_set():
            _stop_event.clear()
            stopped = True
            break

        with _cmd_lock:
            pending = _cmd_queue.copy()
            _cmd_queue.clear()
        for c in pending:
            if c in ('stop', 'youtube_stop'):
                _stop_event.set()

        if _stop_event.is_set():
            _stop_event.clear()
            stopped = True
            break

        k1 = GPIO.input(KEY1_PIN) == GPIO.LOW
        k2 = GPIO.input(KEY2_PIN) == GPIO.LOW
        k3 = GPIO.input(KEY3_PIN) == GPIO.LOW
        if (k1 and not k1w) or (k2 and not k2w) or (k3 and not k3w):
            stopped = True
            break
        k1w, k2w, k3w = k1, k2, k3

        time.sleep(2)

    _terminate_proc(libcam_proc)
    _terminate_proc(stream_proc)
    _push_event('YT', '\u25a0 YouTube stream stopped')
    _set_mode('idle')
    os.execv(sys.executable, [sys.executable] + sys.argv)


def main():
    # Restore ip_forward to configured persistent value on startup
    try:
        cfg = json.load(open(_CONFIG_PATH))
    except Exception:
        cfg = {}
    _set_ip_forward(cfg.get('ip_forward_persistent', False))

    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()

    _start_cyd_server()
    _set_mode('idle')

    GPIO.setup(KEY1_PIN,       GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(KEY2_PIN,       GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(KEY3_PIN,       GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(JOYSTICK_UP,    GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(JOYSTICK_DOWN,  GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(JOYSTICK_PRESS, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(JOYSTICK_LEFT,  GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(JOYSTICK_RIGHT, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    draw_menu(lcd)

    # Seed edge-tracking from the live pin state so a held/noisy joystick
    # signal right after restart does not immediately trigger a mode.
    jp_was = GPIO.input(JOYSTICK_PRESS) == GPIO.LOW
    ju_was = GPIO.input(JOYSTICK_UP) == GPIO.LOW
    jd_was = GPIO.input(JOYSTICK_DOWN) == GPIO.LOW
    jl_was = GPIO.input(JOYSTICK_LEFT) == GPIO.LOW
    jr_was = GPIO.input(JOYSTICK_RIGHT) == GPIO.LOW

    while True:
        # CYD remote commands
        with _cmd_lock:
            pending = _cmd_queue.copy()
            _cmd_queue.clear()
        for cmd in pending:
            if cmd == 'anomaly_detector':
                _stop_event.clear()
                draw_menu(lcd, selected=1); time.sleep(0.15)
                launch_anomaly_detector(lcd)
            elif cmd == 'raspyjack':
                _stop_event.clear()
                draw_menu(lcd, selected=2); time.sleep(0.15)
                launch_raspyjack(lcd)
            elif cmd == 'bettercap':
                _stop_event.clear()
                draw_menu(lcd, selected=3); time.sleep(0.15)
                launch_bettercap(lcd)
            elif cmd == 'quick_scan':
                _stop_event.clear()
                draw_menu(lcd, selected=4); time.sleep(0.15)
                launch_quick_scan(lcd)
            elif cmd == 'port_scan':
                _stop_event.clear()
                draw_menu(lcd, selected=5); time.sleep(0.15)
                launch_port_scanner(lcd)
            elif cmd == 'wifi_scan':
                _stop_event.clear()
                draw_menu(lcd, selected=6); time.sleep(0.15)
                launch_wifi_scanner(lcd)
            elif cmd == 'youtube_stream':
                _stop_event.clear()
                draw_menu(lcd, selected=7); time.sleep(0.15)
                launch_youtube_stream(lcd)
            elif cmd == 'stop':
                _stop_event.clear()
                _set_mode('idle')
                os.execv(sys.executable, [sys.executable] + sys.argv)

        if GPIO.input(KEY1_PIN) == GPIO.LOW:
            draw_menu(lcd, selected=1)
            time.sleep(0.25)
            launch_anomaly_detector(lcd)

        if GPIO.input(KEY2_PIN) == GPIO.LOW:
            draw_menu(lcd, selected=2)
            time.sleep(0.25)
            launch_raspyjack(lcd)

        if GPIO.input(KEY3_PIN) == GPIO.LOW:
            draw_menu(lcd, selected=3)
            time.sleep(0.25)
            launch_bettercap(lcd)

        ju = GPIO.input(JOYSTICK_UP) == GPIO.LOW
        if ju and not ju_was:
            draw_menu(lcd, selected=4)
            time.sleep(0.25)
            launch_quick_scan(lcd)
        ju_was = ju

        jd = GPIO.input(JOYSTICK_DOWN) == GPIO.LOW
        if jd and not jd_was:
            draw_menu(lcd, selected=5)
            time.sleep(0.25)
            launch_port_scanner(lcd)
        jd_was = jd

        jl = GPIO.input(JOYSTICK_LEFT) == GPIO.LOW
        if jl and not jl_was:
            draw_menu(lcd, selected=6)
            time.sleep(0.25)
            launch_wifi_scanner(lcd)
        jl_was = jl

        jr = GPIO.input(JOYSTICK_RIGHT) == GPIO.LOW
        if jr and not jr_was:
            draw_menu(lcd, selected=7)
            time.sleep(0.25)
            launch_youtube_stream(lcd)
        jr_was = jr

        jp = GPIO.input(JOYSTICK_PRESS) == GPIO.LOW
        if jp and not jp_was:
            launch_settings_portal(lcd)
            draw_menu(lcd)
        jp_was = jp

        time.sleep(0.05)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        try:
            GPIO.cleanup()
        except Exception:
            pass
        print(f'[mode_selector] fatal: {e}')
        sys.exit(1)
