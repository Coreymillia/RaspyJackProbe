# RaspyJackProbe

A boot-selectable network probe toolkit for Raspberry Pi Zero 2 W running RaspyJack (Kali Linux for Pi).
Pairs with the Waveshare 1.44" LCD HAT and a Waveshare Ethernet HAT. No Meshtastic, no cloud AI — fully offline.

## Boot Mode Menu

| Button   | Mode                | Description                                               |
|----------|---------------------|-----------------------------------------------------------|
| KEY1     | Anomaly Detector    | Bettercap recon + device baseline watcher, alerts on LCD  |
| KEY2     | RaspyJack           | Launches the existing RaspyJack toolkit                   |
| KEY3     | Bettercap Monitor   | Passive recon + dark web UI at `:8082`, JOY LEFT → MITM  |
| JOY ↑    | Quick Scan          | One-shot `arp-scan --localnet`, results on LCD            |
| JOY ●    | Settings Portal     | Web config UI at `:8080`                                  |

> **Reboot hold:** Hold JOY PRESS for ~3 seconds → reboot confirm screen → JOY ↑ to confirm.

---

## Install

### 1. Dependencies

```bash
apt update && apt install -y bettercap arp-scan
pip install -r requirements.txt
```

### 2. Deploy project files

```bash
git clone <this-repo> /root/RaspyJackProbe
cd /root/RaspyJackProbe
cp config.example.json config.json
```

### 3. Enable the mode selector service

```bash
cp systemd/mode-selector.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable mode-selector.service
systemctl start mode-selector.service
```

### 4. Enable bettercap service (for Bettercap Monitor and Anomaly Detector modes)

```bash
# Bettercap ships a service unit — just enable it
systemctl enable bettercap.service
```

> Note: The mode selector starts/stops `bettercap.service` automatically. No need to have it running at boot.

---

## Configuration

Edit settings via the **Settings Portal** (JOY PRESS at the boot menu) from any browser on the network, or edit `/root/RaspyJackProbe/config.json` directly.

| Field                    | Default | Description                                              |
|--------------------------|---------|----------------------------------------------------------|
| `mitm_target`            | `""`    | Target IP for ARP spoof (device you own)                 |
| `mitm_dns_domains`       | `""`    | Comma-separated domains to hijack e.g. `*.google.com`   |
| `mitm_dns_address`       | `""`    | Where hijacked DNS points (blank = this Pi's IP)         |
| `mitm_http_proxy`        | `false` | Intercept plain HTTP via port 8888                       |
| `ip_forward_persistent`  | `false` | Persist `net.ipv4.ip_forward=1` across reboots          |
| `anomaly_poll_interval`  | `30`    | Seconds between Bettercap device scans                   |
| `anomaly_spike_threshold`| `3`     | New devices in one poll that triggers a SPIKE alert      |

---

## Anomaly Detector — How It Works

1. Starts Bettercap with `net.probe` + `net.recon` + REST API
2. First poll establishes a **baseline** of known devices → saved to `known_devices.json`
3. Every subsequent poll compares live devices against the baseline
4. Alerts shown on LCD and appended to `anomaly.log`:
   - **NEW** — unseen IP/MAC joined the network
   - **GONE** — known device count dropped by spike threshold or more
   - **MAC** — same IP is now advertising a different MAC (potential spoofing)
   - **SPIKE** — many new devices appeared in a single poll

---

## Bettercap MITM — How It Works

From **Bettercap Monitor** mode (KEY3), press **JOY LEFT** to toggle MITM:
- Reads `mitm_target`, `mitm_dns_domains`, `mitm_http_proxy` from `config.json`
- Generates a caplet at `/tmp/probe-mitm.cap` and launches bettercap with it
- ARP spoof + optional DNS spoof + optional HTTP proxy
- Press **JOY LEFT** again to stop MITM and return to passive recon
- Press **KEY** to exit Bettercap Monitor entirely

> Always use MITM on devices **you own**. Running it against others without permission is illegal.

---

## File Layout (on device)

```
/root/RaspyJackProbe/
├── mode_selector.py       # Boot menu
├── anomaly_detector.py    # Standalone anomaly watcher
├── bc_dashboard.py        # Bettercap dark UI proxy (:8082)
├── config.json            # Runtime config (gitignored)
├── config.example.json    # Template
├── known_devices.json     # Anomaly detector baseline (auto-created)
├── anomaly.log            # Alert log (auto-created)
├── requirements.txt
└── systemd/
    └── mode-selector.service
```

## Related Project

[RaspyMeshBot2.0](../RaspyMeshBot2.0) — the mesh radio version with Groq AI + Meshtastic + Pi.Alert.
