#!/usr/bin/env python3
"""
RaspyJackProbe — Standalone Anomaly Detector
Starts Bettercap in passive recon mode, polls its REST API, and watches for:
  - New device joined the network
  - Known device disappeared
  - Device MAC address changed
  - Sudden device count spike

Results are shown on the Waveshare 1.44" LCD and written to anomaly.log.
Press KEY1 / KEY2 / KEY3 to stop and return to the boot menu.
"""

import sys, os, json, time, subprocess, base64, signal
import urllib.request

sys.path.insert(0, '/root/Raspyjack')

import RPi.GPIO as GPIO
from PIL import Image, ImageDraw, ImageFont
import LCD_1in44
import LCD_Config

# ── Paths ────────────────────────────────────────────────────────────────────
_PROJECT_DIR   = '/root/RaspyJackProbe'
_CONFIG_PATH   = os.path.join(_PROJECT_DIR, 'config.json')
_KNOWN_PATH    = os.path.join(_PROJECT_DIR, 'known_devices.json')
_LOG_PATH      = os.path.join(_PROJECT_DIR, 'anomaly.log')
_RECON_CAP     = '/tmp/probe-recon.cap'

# ── Bettercap REST ────────────────────────────────────────────────────────────
_BC_API  = 'http://127.0.0.1:8081/api/session'
_BC_AUTH = base64.b64encode(b'user:pass').decode()

# ── Button pins ───────────────────────────────────────────────────────────────
KEY1_PIN = 21
KEY2_PIN = 20
KEY3_PIN = 16

# ── Font helper ───────────────────────────────────────────────────────────────
_FONT_PATH_BOLD = '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'
_FONT_PATH      = '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'

def _font(path, size):
    try:
        return ImageFont.truetype(path, size)
    except Exception:
        return ImageFont.load_default()


# ── Interface detection ───────────────────────────────────────────────────────
def _best_iface():
    """Return the best interface for scanning: prefer wired (eth*) over wireless."""
    try:
        import subprocess as _sp
        out = _sp.check_output(['ip', '-o', 'addr', 'show'], text=True)
        eth = []
        wlan = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4 or parts[2] != 'inet':
                continue
            name = parts[1]
            if name == 'lo':
                continue
            if name.startswith('eth') or name.startswith('en'):
                eth.append(name)
            elif name.startswith('wlan') or name.startswith('wl'):
                wlan.append(name)
        if eth:
            return eth[0]
        if wlan:
            return wlan[0]
    except Exception:
        pass
    return None


# ── Recon caplet ──────────────────────────────────────────────────────────────
def _write_recon_cap():
    # NOTE: net.recon auto-starts in bettercap v2.32+ when net.probe starts.
    # Including an explicit 'net.recon on' causes a "already running" error that
    # aborts the rest of the caplet — so we omit it here.
    lines = [
        'set net.probe.throttle 100',
        'net.probe on',
        'set api.rest.username user',
        'set api.rest.password pass',
        'set api.rest.port 8081',
        'set api.rest.address 127.0.0.1',
        'api.rest on',
    ]
    with open(_RECON_CAP, 'w') as f:
        f.write('\n'.join(lines) + '\n')


# ── Logging ───────────────────────────────────────────────────────────────────
def _log(msg):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    line = f'[{ts}] {msg}'
    print(line)
    try:
        with open(_LOG_PATH, 'a') as f:
            f.write(line + '\n')
    except Exception:
        pass


# ── Bettercap API ─────────────────────────────────────────────────────────────
def _bc_fetch():
    """Returns list of endpoint dicts or None on failure."""
    try:
        req = urllib.request.Request(
            _BC_API,
            headers={'Authorization': f'Basic {_BC_AUTH}'}
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read())
        # bettercap v2.32+ uses lan.hosts, older versions used endpoints
        return data.get('lan', {}).get('hosts', data.get('endpoints', []))
    except Exception:
        return None


# ── Known-device store ────────────────────────────────────────────────────────
def _load_known():
    try:
        with open(_KNOWN_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_known(known):
    try:
        with open(_KNOWN_PATH, 'w') as f:
            json.dump(known, f, indent=2)
    except Exception as e:
        _log(f'[WARN] could not save known_devices: {e}')


# ── Anomaly detection ─────────────────────────────────────────────────────────
def _detect(endpoints, known, spike_threshold):
    """
    Returns list of (level, message) tuples.
    level: 'NEW' | 'GONE' | 'MAC' | 'SPIKE'
    Mutates `known` in-place to reflect current state.
    """
    alerts = []
    current = {}
    for ep in endpoints:
        ip  = ep.get('ipv4', '').strip()
        mac = ep.get('mac', '').strip().lower()
        if not ip or not mac:
            continue
        current[ip] = mac

    # Spike: many new IPs in one poll
    new_ips = [ip for ip in current if ip not in known]
    if len(new_ips) >= spike_threshold:
        alerts.append(('SPIKE', f'{len(new_ips)} new devices at once'))

    # New devices
    for ip in new_ips:
        if ('SPIKE', f'{len(new_ips)} new devices at once') not in alerts:
            alerts.append(('NEW', f'{ip}  {current[ip]}'))
        _log(f'[NEW] {ip}  mac={current[ip]}')

    # MAC changed
    for ip, mac in current.items():
        if ip in known and known[ip] != mac:
            alerts.append(('MAC', f'{ip} MAC changed'))
            _log(f'[MAC] {ip} was={known[ip]} now={mac}')

    # Gone devices (only log, don't spam LCD unless significant)
    gone = [ip for ip in known if ip not in current]
    for ip in gone:
        _log(f'[GONE] {ip}  was={known[ip]}')
    if len(gone) >= spike_threshold:
        alerts.append(('GONE', f'{len(gone)} devices disappeared'))

    # Update known
    known.clear()
    known.update(current)

    return alerts


# ── LCD screens ───────────────────────────────────────────────────────────────
def _draw_startup(lcd):
    img  = Image.new('RGB', (128, 128), (0, 0, 0))
    draw = ImageDraw.Draw(img)
    f9b  = _font(_FONT_PATH_BOLD, 9)
    f8   = _font(_FONT_PATH, 8)
    f7   = _font(_FONT_PATH, 7)
    draw.rectangle([(0, 0), (128, 16)], fill=(0, 90, 160))
    draw.text((4, 3), 'ANOMALY DETECTOR', font=f8, fill=(255, 255, 255))
    draw.text((4, 22), 'Starting Bettercap...', font=f8, fill=(180, 180, 0))
    draw.text((4, 36), 'net.probe + net.recon', font=f7, fill=(100, 100, 100))
    draw.text((4, 55), 'Waiting for API...', font=f7, fill=(80, 80, 80))
    draw.text((4, 108), 'KEY1/2/3 = back', font=f7, fill=(80, 80, 80))
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_watching(lcd, device_count, poll_num, iface):
    img  = Image.new('RGB', (128, 128), (0, 0, 0))
    draw = ImageDraw.Draw(img)
    f9b  = _font(_FONT_PATH_BOLD, 9)
    f8   = _font(_FONT_PATH, 8)
    f7   = _font(_FONT_PATH, 7)
    draw.rectangle([(0, 0), (128, 16)], fill=(0, 90, 40))
    draw.text((4, 3), '● WATCHING NETWORK', font=f8, fill=(80, 255, 120))
    draw.text((4, 22), f'IF: {iface}', font=f8,  fill=(150, 200, 255))
    draw.text((4, 36), f'Devices: {device_count}', font=f9b, fill=(255, 255, 255))
    draw.text((4, 52), f'Poll #{poll_num}', font=f7, fill=(100, 100, 100))
    draw.line([(0, 65), (128, 65)], fill=(40, 40, 40))
    draw.text((4, 70), 'No anomalies', font=f8, fill=(80, 160, 80))
    draw.text((4, 108), 'KEY1/2/3 = back', font=f7, fill=(80, 80, 80))
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_alert(lcd, alerts):
    """Show up to 3 alerts on a red-banner screen."""
    img  = Image.new('RGB', (128, 128), (0, 0, 0))
    draw = ImageDraw.Draw(img)
    f9b  = _font(_FONT_PATH_BOLD, 9)
    f8   = _font(_FONT_PATH, 8)
    f7   = _font(_FONT_PATH, 7)

    level_colors = {
        'NEW':   (255, 80,  80),
        'GONE':  (255, 140, 0),
        'MAC':   (255, 200, 0),
        'SPIKE': (255, 0,   0),
    }
    hdr_col = (180, 0, 0) if any(a[0] in ('NEW','SPIKE') for a in alerts) else (160, 90, 0)
    draw.rectangle([(0, 0), (128, 16)], fill=hdr_col)
    draw.text((4, 3), f'!! {len(alerts)} ANOMAL{"Y" if len(alerts)==1 else "IES"}', font=f8, fill=(255, 255, 0))

    y = 22
    for level, msg in alerts[:4]:
        col = level_colors.get(level, (200, 200, 200))
        draw.text((4, y), f'[{level}]', font=f9b, fill=col)
        draw.text((44, y), msg[:16], font=f7, fill=(220, 220, 220))
        y += 20

    draw.line([(0, 105), (128, 105)], fill=(60, 60, 60))
    draw.text((4, 108), 'KEY1/2/3 = back', font=f7, fill=(80, 80, 80))
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_no_api(lcd):
    img  = Image.new('RGB', (128, 128), (0, 0, 0))
    draw = ImageDraw.Draw(img)
    f8   = _font(_FONT_PATH, 8)
    f7   = _font(_FONT_PATH, 7)
    draw.rectangle([(0, 0), (128, 16)], fill=(120, 60, 0))
    draw.text((4, 3), 'BETTERCAP OFFLINE', font=f7, fill=(255, 180, 0))
    draw.text((4, 24), 'API not responding.', font=f8, fill=(200, 200, 200))
    draw.text((4, 38), 'Retrying...', font=f7, fill=(100, 100, 100))
    draw.text((4, 108), 'KEY1/2/3 = back', font=f7, fill=(80, 80, 80))
    lcd.LCD_ShowImage(img, 0, 0)


# ── Main entry point ──────────────────────────────────────────────────────────
def run(lcd):
    """
    Called by mode_selector after GPIO is already set up and buttons are configured.
    Blocks until a KEY is pressed, then returns so the selector can re-exec.
    """
    try:
        cfg = json.load(open(_CONFIG_PATH))
    except Exception:
        cfg = {}

    poll_interval   = int(cfg.get('anomaly_poll_interval', 30))
    spike_threshold = int(cfg.get('anomaly_spike_threshold', 3))

    _write_recon_cap()

    # Stop any running bettercap, then start fresh with recon caplet
    subprocess.run(['systemctl', 'stop', 'bettercap.service'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)

    iface = _best_iface()
    cmd = ['/usr/bin/bettercap', '-no-colors', '-caplet', _RECON_CAP]
    if iface:
        cmd += ['-iface', iface]
        _log(f'[DETECTOR] using interface {iface}')

    bc_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _log('[DETECTOR] started — waiting for Bettercap API')
    _draw_startup(lcd)

    # Load or init the known-device baseline
    known = _load_known()
    if not known:
        _log('[DETECTOR] no baseline yet — first poll will establish it')

    def _keys_pressed():
        return (GPIO.input(KEY1_PIN) == GPIO.LOW or
                GPIO.input(KEY2_PIN) == GPIO.LOW or
                GPIO.input(KEY3_PIN) == GPIO.LOW)

    # Wait for API to come up (up to 30s)
    for _ in range(30):
        if _keys_pressed():
            break
        if _bc_fetch() is not None:
            break
        time.sleep(1)

    poll_num = 0
    last_alert_time = 0
    iface = '?'
    alert_hold = 0  # seconds to keep alert screen up

    while True:
        if _keys_pressed():
            break

        endpoints = _bc_fetch()

        if endpoints is None:
            _draw_no_api(lcd)
            time.sleep(5)
            continue

        # Pull interface name from session data (best effort)
        try:
            req = urllib.request.Request(
                _BC_API, headers={'Authorization': f'Basic {_BC_AUTH}'}
            )
            with urllib.request.urlopen(req, timeout=4) as resp:
                session = json.loads(resp.read())
            iface = session.get('interface', {}).get('name', '?')
        except Exception:
            pass

        poll_num += 1

        # First poll — just establish baseline, don't alert
        if poll_num == 1 and not known:
            for ep in endpoints:
                ip  = ep.get('ipv4', '').strip()
                mac = ep.get('mac', '').strip().lower()
                if ip and mac:
                    known[ip] = mac
            _save_known(known)
            _log(f'[DETECTOR] baseline set — {len(known)} devices')
            _draw_watching(lcd, len(known), poll_num, iface)
        else:
            alerts = _detect(endpoints, known, spike_threshold)
            _save_known(known)

            if alerts:
                _log(f'[DETECTOR] {len(alerts)} alert(s) this poll')
                _draw_alert(lcd, alerts)
                alert_hold = 20  # hold alert screen for 20s
            elif alert_hold > 0:
                alert_hold -= poll_interval
            else:
                _draw_watching(lcd, len(known), poll_num, iface)

        # Poll sleep, checking keys every second
        for _ in range(poll_interval):
            if _keys_pressed():
                break
            time.sleep(1)

    # Cleanup
    bc_proc.terminate()
    _log('[DETECTOR] stopped by user')


if __name__ == '__main__':
    # Standalone test — init hardware ourselves
    LCD_Config.GPIO_Init()
    lcd = LCD_1in44.LCD()
    lcd.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
    lcd.LCD_Clear()
    GPIO.setup(KEY1_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(KEY2_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(KEY3_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    try:
        run(lcd)
    finally:
        GPIO.cleanup()
