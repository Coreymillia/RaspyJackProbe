#!/usr/bin/env python3
"""
RaspyJackProbe — Port Scanner Mode
Fetches discovered hosts from Bettercap API (or arp-scan fallback),
runs nmap -T4 -F --open against each, grabs service banners, streams
results to LCD + CYD event log.
"""
import subprocess, json, time, urllib.request, base64, socket, ssl
import RPi.GPIO as GPIO
from PIL import Image, ImageDraw, ImageFont

_BC_API  = 'http://localhost:8081/api/session'
_BC_AUTH = base64.b64encode(b'user:pass').decode()

_FONT_PATH_BOLD = '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'
_FONT_PATH      = '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'

# Patched by mode_selector to bridge events into CYD buffer
_push_event = None


def _font(path, size):
    try:
        return ImageFont.truetype(path, size)
    except Exception:
        return ImageFont.load_default()


def _log(msg):
    print(f'[PORT_SCAN] {msg}')
    if _push_event:
        _push_event('SCAN', msg.strip())


# ── Service banner grab ───────────────────────────────────────────────────────
_HTTP_PORTS  = {80, 8080, 8081, 8888, 8000, 3000, 5000, 9090, 9000}
_HTTPS_PORTS = {443, 8443}
_RAW_PORTS   = {21, 22, 23, 25, 110, 143, 587, 1883, 3306, 5432}


def _grab_http(ip, port, use_ssl=False, timeout=2):
    """Return short Server: header or first title, e.g. 'nginx/1.18' or 'Apache'."""
    scheme = 'https' if use_ssl else 'http'
    try:
        ctx = ssl.create_default_context() if use_ssl else None
        if use_ssl:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        req = urllib.request.Request(
            f'{scheme}://{ip}:{port}/',
            headers={'User-Agent': 'RaspyJackProbe/1.0'}
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            server = r.headers.get('Server', '')
            via    = r.headers.get('X-Powered-By', '')
            if server:
                return server.split(' ')[0][:24]   # e.g. 'Apache/2.4.54'
            if via:
                return via[:24]
            return 'HTTP/OK'
    except urllib.error.HTTPError as e:
        server = e.headers.get('Server', '')
        return server.split(' ')[0][:24] if server else f'HTTP/{e.code}'
    except Exception:
        return ''


def _grab_raw(ip, port, timeout=2):
    """Connect and read the first 128 bytes — works for SSH/FTP/SMTP etc."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(128)
            except socket.timeout:
                return ''
            text = data.decode('utf-8', errors='replace').strip()
            # Return first non-empty line, truncated
            for line in text.splitlines():
                line = line.strip()
                if line:
                    return line[:32]
    except Exception:
        pass
    return ''


def _banner_grab(ip, port):
    """Return a short human-readable service string for a known-open port."""
    if port in _HTTPS_PORTS:
        return _grab_http(ip, port, use_ssl=True) or 'HTTPS'
    if port in _HTTP_PORTS:
        return _grab_http(ip, port, use_ssl=False) or 'HTTP'
    if port in _RAW_PORTS:
        banner = _grab_raw(ip, port)
        if banner:
            # Clean common prefixes
            for prefix in ('SSH-', '220 ', '230 ', '+OK ', '* OK'):
                if banner.startswith(prefix):
                    return banner[:28]
            return banner[:28]
        # Fallback to known port names
        names = {21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP', 110:'POP3',
                 143:'IMAP', 587:'SMTP', 1883:'MQTT', 3306:'MySQL', 5432:'Postgres'}
        return names.get(port, '')
    return ''


def _get_own_ips():
    """Return set of this device's own IP addresses so we can skip self-scanning."""
    try:
        result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True)
        ips = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith('inet ') and not line.startswith('inet 127.'):
                ips.add(line.split()[1].split('/')[0])
        return ips
    except Exception:
        return set()


def _get_hosts_from_bettercap():
    try:
        req = urllib.request.Request(_BC_API, headers={'Authorization': f'Basic {_BC_AUTH}'})
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read())
        hosts = data.get('lan', {}).get('hosts', data.get('endpoints', []))
        return [h['ipv4'] for h in hosts if h.get('ipv4')]
    except Exception:
        return []


def _get_hosts_from_arpscan():
    try:
        result = subprocess.run(
            ['arp-scan', '--localnet', '--retry=2'],
            capture_output=True, text=True, timeout=20
        )
        ips = []
        for line in result.stdout.splitlines():
            if '\t' in line and not line.startswith('Interface'):
                parts = line.split('\t')
                ip = parts[0].strip()
                if ip.count('.') == 3:
                    ips.append(ip)
        return ips
    except Exception:
        return []


def _draw_scanning(lcd, ip, current, total):
    img  = Image.new('RGB', (128, 128), (0, 0, 0))
    draw = ImageDraw.Draw(img)
    f8b  = _font(_FONT_PATH_BOLD, 8)
    f7   = _font(_FONT_PATH, 7)
    draw.rectangle([(0, 0), (128, 14)], fill=(0, 55, 100))
    draw.text((4, 3), f'PORT SCAN  {current}/{total}', font=f7, fill=(0, 200, 255))
    draw.text((4, 20), 'Scanning:', font=f7, fill=(120, 120, 120))
    draw.text((4, 31), ip[:20], font=f8b, fill=(0, 200, 255))
    if total > 0:
        pct = int((current / total) * 116)
        draw.rectangle([(6, 46), (122, 55)], outline=(40, 40, 40))
        if pct > 0:
            draw.rectangle([(7, 47), (7 + pct, 54)], fill=(0, 120, 200))
    draw.text((4, 62), 'nmap -T4 -F --open', font=f7, fill=(60, 60, 60))
    draw.text((4, 118), 'KEY1/2/3 = abort', font=f7, fill=(80, 80, 80))
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_progress_line(lcd, ip, current, total, port_str):
    """Update the 'last result' line while scanning continues."""
    img  = Image.new('RGB', (128, 128), (0, 0, 0))
    draw = ImageDraw.Draw(img)
    f8b  = _font(_FONT_PATH_BOLD, 8)
    f8   = _font(_FONT_PATH, 8)
    f7   = _font(_FONT_PATH, 7)
    draw.rectangle([(0, 0), (128, 14)], fill=(0, 55, 100))
    draw.text((4, 3), f'PORT SCAN  {current}/{total}', font=f7, fill=(0, 200, 255))
    pct = int((current / max(total, 1)) * 116)
    draw.rectangle([(6, 16), (122, 25)], outline=(40, 40, 40))
    if pct > 0:
        draw.rectangle([(7, 17), (7 + pct, 24)], fill=(0, 120, 200))
    draw.text((4, 30), f'Done: {ip[:20]}', font=f7, fill=(120, 120, 120))
    col = (80, 255, 80) if port_str and port_str != 'closed' else (80, 80, 80)
    draw.text((4, 42), port_str[:22], font=f8, fill=col)
    draw.text((4, 118), 'KEY1/2/3 = abort', font=f7, fill=(80, 80, 80))
    lcd.LCD_ShowImage(img, 0, 0)


def _draw_results(lcd, results, total_hosts, total_open):
    img  = Image.new('RGB', (128, 128), (0, 0, 0))
    draw = ImageDraw.Draw(img)
    f8b  = _font(_FONT_PATH_BOLD, 8)
    f8   = _font(_FONT_PATH, 8)
    f7   = _font(_FONT_PATH, 7)
    draw.rectangle([(0, 0), (128, 14)], fill=(0, 55, 100))
    draw.text((4, 3), f'SCAN DONE  {total_open} open', font=f7, fill=(0, 200, 255))
    y = 18
    if results:
        for ip, port_banners in list(results.items())[:5]:
            last_octet = ip.rsplit('.', 1)[-1].rjust(3)
            # Show up to 3 ports with service abbreviation
            parts = []
            for p, banner in port_banners[:3]:
                svc = banner.split('/')[0][:6] if banner else ''
                parts.append(f'{p}/{svc}' if svc else str(p))
            extra = f'+{len(port_banners)-3}' if len(port_banners) > 3 else ''
            line  = ' '.join(parts) + extra
            draw.text((4, y),   f'.{last_octet}', font=f7, fill=(0, 180, 255))
            draw.text((32, y),  line[:18],         font=f7, fill=(80, 255, 80))
            y += 10
        if len(results) > 5:
            draw.text((4, y), f'...+{len(results)-5} more hosts', font=f7, fill=(60, 60, 60))
    else:
        draw.text((4, 40), 'No open ports found', font=f8, fill=(120, 120, 120))
    draw.text((4, y + 8 if y < 100 else 105),
              f'{total_hosts} hosts scanned', font=f7, fill=(60, 60, 60))
    draw.text((4, 118), 'Press any KEY to exit', font=f7, fill=(80, 80, 80))
    lcd.LCD_ShowImage(img, 0, 0)


def _check_abort(key1, key2, key3):
    try:
        return (GPIO.input(key1) == GPIO.LOW or
                GPIO.input(key2) == GPIO.LOW or
                GPIO.input(key3) == GPIO.LOW)
    except Exception:
        return False


def _wait_key(key1, key2, key3, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _check_abort(key1, key2, key3):
            time.sleep(0.15)
            break
        time.sleep(0.05)


def run(lcd, key1=21, key2=20, key3=16):
    """
    Entry point called by mode_selector.
    key1/key2/key3 are BCM pin numbers used to abort the scan.
    """
    _log('Collecting hosts...')
    _draw_scanning(lcd, 'Collecting...', 0, 1)

    hosts = _get_hosts_from_bettercap()
    source = 'bettercap'
    if not hosts:
        _log('Bettercap offline — falling back to arp-scan')
        hosts = _get_hosts_from_arpscan()
        source = 'arp-scan'

    if not hosts:
        _log('No hosts found')
        _draw_results(lcd, {}, 0, 0)
        _wait_key(key1, key2, key3)
        return

    _log(f'{len(hosts)} hosts via {source}')
    own_ips = _get_own_ips()
    hosts   = [h for h in hosts if h not in own_ips]
    if own_ips:
        _log(f'Skipping own IPs: {", ".join(sorted(own_ips))}')
    results    = {}   # ip → [(port, banner), ...]
    total_open = 0

    for idx, ip in enumerate(hosts, 1):
        if _check_abort(key1, key2, key3):
            _log('Aborted by user')
            break

        _draw_scanning(lcd, ip, idx - 1, len(hosts))
        _log(f'Scanning {ip} ({idx}/{len(hosts)})')

        try:
            proc = subprocess.run(
                ['nmap', '-T4', '-F', '--open', '-oG', '-', ip],
                capture_output=True, text=True, timeout=30
            )
            open_ports   = []
            port_banners = []  # defined here so _draw_progress_line always has it
            for line in proc.stdout.splitlines():
                if 'Ports:' in line:
                    for entry in line.split('Ports:')[1].split(','):
                        entry = entry.strip()
                        if '/open/' in entry:
                            try:
                                open_ports.append(int(entry.split('/')[0]))
                            except ValueError:
                                pass

            if open_ports:
                total_open += len(open_ports)
                port_str = ','.join(str(p) for p in sorted(open_ports)[:6])
                _log(f'{ip}: OPEN {port_str}')
                for p in sorted(open_ports):
                    banner = _banner_grab(ip, p)
                    port_banners.append((p, banner))
                    if banner:
                        _log(f'  {ip}:{p} → {banner}')
                results[ip] = port_banners
            else:
                _log(f'{ip}: closed')

            _draw_progress_line(
                lcd, ip, idx, len(hosts),
                ','.join(str(p) for p, _ in port_banners[:6]) if port_banners else 'closed'
            )

        except subprocess.TimeoutExpired:
            _log(f'{ip}: timeout (skipped)')
            _draw_progress_line(lcd, ip, idx, len(hosts), 'timeout')
        except Exception as e:
            _log(f'{ip}: error {e}')

        time.sleep(0.1)

    _log(f'Done — {len(results)}/{len(hosts)} hosts with open ports, {total_open} total open')
    _draw_results(lcd, results, len(hosts), total_open)
    _wait_key(key1, key2, key3)

