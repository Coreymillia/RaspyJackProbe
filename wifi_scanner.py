#!/usr/bin/env python3
"""
Dedicated passive Wi-Fi scanner mode for RaspyJackProbe.
Uses airmon-ng + airodump-ng to list nearby APs across 2.4 GHz and 5 GHz.
"""
import csv
import os
import re
import subprocess
import tempfile
import time

import RPi.GPIO as GPIO
from PIL import Image, ImageDraw, ImageFont

_AIRMON_BIN = '/usr/sbin/airmon-ng'
_AIRODUMP_BIN = '/usr/sbin/airodump-ng'
_NMCLI_BIN = '/usr/bin/nmcli'

_FONT_PATH_BOLD = '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'
_FONT_PATH = '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
_SCAN_CHANNELS_24G = '1,2,3,4,5,6,7,8,9,10,11'
_SCAN_CHANNELS_5G = '36,40,44,48,149,153,157,161,165'

_push_event = None
_status_update = None


def _font(path, size):
    try:
        return ImageFont.truetype(path, size)
    except Exception:
        return ImageFont.load_default()


def _log(msg):
    print(f'[WIFI_SCAN] {msg}')
    if _push_event:
        _push_event('SCAN', msg.strip())


def _set_status(ap_count):
    if _status_update:
        _status_update(ap_count)


def _wireless_ifaces():
    try:
        out = subprocess.check_output(['ip', '-o', 'link', 'show'], text=True)
    except Exception:
        return []
    ifaces = []
    for line in out.splitlines():
        parts = line.split(':', 2)
        if len(parts) < 2:
            continue
        name = parts[1].strip()
        if name != 'lo' and name.startswith(('wlan', 'wl')) and not name.endswith('mon'):
            ifaces.append(name)
    return ifaces


def _best_wifi_iface():
    try:
        out = subprocess.check_output(['ip', '-o', '-4', 'addr', 'show'], text=True)
        with_ipv4 = {
            line.split()[1]
            for line in out.splitlines()
            if len(line.split()) >= 4 and line.split()[2] == 'inet'
        }
    except Exception:
        with_ipv4 = set()
    candidates = _wireless_ifaces()
    if not candidates:
        return None
    idle = [iface for iface in candidates if iface not in with_ipv4]
    return (idle or candidates)[0]


def _existing_monitor_iface():
    try:
        out = subprocess.check_output(['ip', '-o', 'link', 'show'], text=True)
    except Exception:
        return None
    for line in out.splitlines():
        parts = line.split(':', 2)
        if len(parts) < 2:
            continue
        name = parts[1].strip()
        if name.startswith(('wlan', 'wl')) and name.endswith('mon'):
            return name
    return None


def _start_monitor_iface(wifi_iface):
    if not wifi_iface:
        return None, 'no wireless interface found'
    if not os.path.exists(_AIRMON_BIN):
        return None, 'airmon-ng not installed'
    if os.path.exists(_NMCLI_BIN):
        subprocess.run([_NMCLI_BIN, 'device', 'set', wifi_iface, 'managed', 'no'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    result = subprocess.run([_AIRMON_BIN, 'start', wifi_iface], capture_output=True, text=True)
    output = '\n'.join(part for part in (result.stdout, result.stderr) if part).strip()
    match = re.search(r'on \[phy\d+\](\S+)', output)
    mon_iface = match.group(1) if match else None
    if not mon_iface and os.path.exists(f'/sys/class/net/{wifi_iface}mon'):
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
        subprocess.run([_AIRMON_BIN, 'stop', monitor_iface],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if wifi_iface and os.path.exists(_NMCLI_BIN):
        subprocess.run([_NMCLI_BIN, 'device', 'set', wifi_iface, 'managed', 'yes'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _parse_airodump_csv(path):
    if not os.path.exists(path):
        return []
    with open(path, newline='', errors='replace') as fh:
        rows = list(csv.reader(fh))
    aps = []
    in_ap_section = False
    for row in rows:
        if not row or not row[0].strip():
            if in_ap_section:
                break
            continue
        header = row[0].strip()
        if header == 'BSSID':
            in_ap_section = True
            continue
        if header == 'Station MAC':
            break
        if len(row) < 14:
            continue
        bssid = header.lower()
        if not bssid or bssid == 'bssid':
            continue
        essid = row[13].strip()
        privacy = row[5].strip()
        cipher = row[6].strip()
        auth = row[7].strip()
        if privacy and cipher:
            security = f'{privacy}/{cipher}'
        elif privacy and auth:
            security = f'{privacy}/{auth}'
        else:
            security = privacy or auth or 'OPEN'
        try:
            channel = int(row[3].strip() or '0')
        except ValueError:
            channel = 0
        try:
            rssi = int(row[8].strip() or '-999')
        except ValueError:
            rssi = -999
        aps.append({
            'essid': essid,
            'bssid': bssid,
            'channel': channel,
            'rssi': rssi,
            'security': security[:18],
        })
    seen = set()
    unique = []
    for ap in sorted(aps, key=lambda item: item['rssi'], reverse=True):
        if ap['bssid'] in seen:
            continue
        seen.add(ap['bssid'])
        unique.append(ap)
    return unique[:24]


def _scan_once(monitor_iface, channels, seconds=12):
    prefix = os.path.join(tempfile.gettempdir(), f'probe-wifi-{int(time.time())}')
    csv_path = prefix + '-01.csv'
    try:
        subprocess.run(
            ['timeout', str(seconds), _AIRODUMP_BIN, monitor_iface, '-c', channels,
             '--output-format', 'csv', '-w', prefix],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        return _parse_airodump_csv(csv_path)
    finally:
        for suffix in ('-01.csv', '-01.kismet.csv', '-01.kismet.netxml', '-01.log.csv'):
            path = prefix + suffix
            if os.path.exists(path):
                os.remove(path)


def _draw_wifi_screen(lcd, monitor_iface, aps, cycle, status):
    ap_5g = sum(1 for ap in aps if ap['channel'] > 14)
    ap_24g = sum(1 for ap in aps if 0 < ap['channel'] <= 14)
    img = Image.new('RGB', (128, 128), (0, 0, 0))
    draw = ImageDraw.Draw(img)
    f8b = _font(_FONT_PATH_BOLD, 8)
    f8 = _font(_FONT_PATH, 8)
    f7 = _font(_FONT_PATH, 7)
    draw.rectangle([(0, 0), (128, 14)], fill=(0, 90, 120))
    draw.text((4, 3), f'WIFI SCAN {status}', font=f7, fill=(255, 255, 255))
    draw.text((4, 18), f'IF: {monitor_iface or "?"}', font=f7, fill=(140, 220, 255))
    draw.text((4, 28), f'Cycle:{cycle}  5G:{ap_5g}', font=f7, fill=(100, 100, 100))
    draw.text((4, 38), f'APs:{len(aps)}  2.4G:{ap_24g}', font=f8b, fill=(0, 220, 255))
    if not aps:
        draw.text((4, 58), 'No AP details yet.', font=f8, fill=(150, 150, 150))
        draw.text((4, 70), 'Scanning 2.4/5 GHz...', font=f7, fill=(100, 100, 100))
    y = 52
    for ap in aps[:5]:
        name = ap['essid'] or '[Hidden]'
        draw.text((4, y), name[:16], font=f8, fill=(255, 255, 255))
        draw.text((4, y + 9), f'ch{ap["channel"]} {ap["rssi"]} {ap["security"][:10]}', font=f7, fill=(120, 180, 120))
        y += 15
    draw.text((4, 118), 'KEY1/2/3 = back', font=f7, fill=(80, 80, 80))
    lcd.LCD_ShowImage(img, 0, 0)


def _read_exit_buttons(key1, key2, key3):
    return (
        GPIO.input(key1) == GPIO.LOW,
        GPIO.input(key2) == GPIO.LOW,
        GPIO.input(key3) == GPIO.LOW,
    )


def _merge_ap_cache(cache, fresh_aps, cycle, max_age=3):
    for ap in fresh_aps:
        cache[ap['bssid']] = {**ap, 'seen_cycle': cycle}
    expired = [bssid for bssid, ap in cache.items() if cycle - ap['seen_cycle'] > max_age]
    for bssid in expired:
        cache.pop(bssid, None)
    merged = sorted(cache.values(), key=lambda item: item['rssi'], reverse=True)
    return [{k: v for k, v in ap.items() if k != 'seen_cycle'} for ap in merged[:24]]


def run(lcd, key1=21, key2=20, key3=16, stop_event=None):
    def _stopped():
        return stop_event is not None and stop_event.is_set()

    monitor_iface = _existing_monitor_iface()
    wifi_iface = monitor_iface[:-3] if monitor_iface and monitor_iface.endswith('mon') else None
    created_monitor = False
    if not monitor_iface:
        wifi_iface = _best_wifi_iface()
        monitor_iface, err = _start_monitor_iface(wifi_iface)
        created_monitor = bool(monitor_iface)
        if err:
            _log(f'WiFi scanner unavailable: {err}')
        if not monitor_iface:
            _draw_wifi_screen(lcd, wifi_iface or '?', [], 0, 'OFF')
            time.sleep(2)
            return

    _log(f'WiFi scan active on {monitor_iface}')
    _set_status(0)
    cycle = 0
    aps = []
    ap_cache = {}
    last_signature = None
    exit_was = _read_exit_buttons(key1, key2, key3)
    exit_armed = not any(exit_was)
    try:
        while not _stopped():
            exit_now = _read_exit_buttons(key1, key2, key3)
            if not exit_armed and not any(exit_now):
                exit_armed = True
            if exit_armed and any(now and not was for now, was in zip(exit_now, exit_was)):
                break
            exit_was = exit_now
            cycle += 1
            _draw_wifi_screen(lcd, monitor_iface, aps, cycle, 'LIVE')
            scan_band = '5G' if cycle % 2 == 0 else '2.4G'
            scan_channels = _SCAN_CHANNELS_5G if scan_band == '5G' else _SCAN_CHANNELS_24G
            fresh_aps = _scan_once(monitor_iface, scan_channels, seconds=10)
            aps = _merge_ap_cache(ap_cache, fresh_aps, cycle)
            _set_status(len(aps))
            ap_5g = sum(1 for ap in aps if ap['channel'] > 14)
            ap_24g = sum(1 for ap in aps if 0 < ap['channel'] <= 14)
            _log(f'Cycle {cycle} [{scan_band}]: {len(aps)} APs (2.4G:{ap_24g} 5G:{ap_5g})')
            signature = tuple((ap['bssid'], ap['channel'], ap['rssi']) for ap in aps[:6])
            if signature != last_signature:
                for ap in aps[:5]:
                    name = ap['essid'] or '[Hidden]'
                    _log(f'{name[:18]} ch{ap["channel"]} {ap["rssi"]}dBm {ap["security"][:12]}')
                last_signature = signature
            _draw_wifi_screen(lcd, monitor_iface, aps, cycle, 'LIVE')
            for _ in range(10):
                exit_now = _read_exit_buttons(key1, key2, key3)
                if not exit_armed and not any(exit_now):
                    exit_armed = True
                if _stopped() or (exit_armed and any(now and not was for now, was in zip(exit_now, exit_was))):
                    return
                exit_was = exit_now
                time.sleep(0.1)
    finally:
        _set_status(0)
        if created_monitor:
            _stop_monitor_iface(monitor_iface, wifi_iface)
        _log('WiFi scan stopped')
