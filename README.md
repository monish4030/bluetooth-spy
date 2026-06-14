# 🕵️ Bluetooth Spy

> **Bluetooth Security Monitor & Analyzer for Kali Linux**
> Made by **Monish Paramasivam**

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-red?style=flat-square)
![Purpose](https://img.shields.io/badge/Purpose-Academic%20Research-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-18%20passing-brightgreen?style=flat-square)

> ⚠️ **For authorized academic research and lab environments only.**
> Do not use against devices you do not own.

---

## What is Bluetooth Spy?

**Bluetooth Spy** is a passive Bluetooth **monitor and analyzer** for cybersecurity students on Kali Linux. It watches the air around you, shows every Bluetooth device nearby, tracks connection and disconnection events in real time, and flags security weaknesses — all through a clean terminal UI.

It does **not** transmit, jam, or disrupt any device. It is a **spy** in the original sense: it watches and reports.

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/bluetooth-spy.git
cd bluetooth-spy

# 2. Install dependencies (run as root)
sudo bash scripts/install_dependencies.sh

# 3. Install Python packages
pip3 install -r requirements.txt

# 4. Run
sudo python3 bluetooth_spy.py
```

> **No Bluetooth adapter?** The tool has a built-in demo mode with simulated devices — great for classroom demos without hardware.

---

## Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | 🔍 **Device Discovery** | Finds Bluetooth Classic and BLE devices nearby |
| 2 | 📡 **Connection Monitor** | Real-time log of connect / disconnect / pair events |
| 3 | 🔑 **Pairing Analysis** | Shows the pairing mode for every device and flags weak ones |
| 4 | 🔬 **Protocol Capture** | HCI-level packet monitoring via `btmon` |
| 5 | 🗺️ **Device Graph** | ASCII tree showing all devices, their type, and security state |
| 6 | 🚨 **Anomaly Detection** | Catches repeated auth failures, connection cycling (DoS patterns) |
| 7 | 📄 **Report Generator** | Saves a full JSON security report to `reports/` |
| 8 | 📚 **Educational Mode** | 5-topic interactive Bluetooth security tutorial (no hardware needed) |

---

## Usage

### Interactive Menu (recommended)
```bash
sudo python3 bluetooth_spy.py
```
You'll see a numbered menu — just pick what you want to do.

### Command Line (headless / scripted)
```bash
# Scan for devices for 60 seconds
sudo python3 bluetooth_spy.py --no-ui --scan --duration 60

# Monitor connection events for 2 minutes
sudo python3 bluetooth_spy.py --no-ui --monitor --duration 120

# Generate a security report
sudo python3 bluetooth_spy.py --no-ui --report

# Learn Bluetooth security concepts (no adapter needed)
python3 bluetooth_spy.py --educational
```

### All flags
```
--scan              Discover Classic + BLE devices
--monitor           Watch connection events live
--analyze           Run security analysis on found devices
--report            Save JSON report to reports/
--educational       Interactive security tutorial
--duration N        How long to scan/monitor (seconds, default 60)
--interface hci0    Which BT adapter to use (default hci0)
--output ./reports  Where to save reports and logs
--no-ui             Skip the TUI, output plain text
--verbose           Extra logging
```

---

## Project Structure

```
bluetooth-spy/
├── bluetooth_spy.py            ← Run this
├── requirements.txt
├── README.md
├── LICENSE
│
├── src/
│   ├── core/
│   │   └── bluetooth_engine.py ← Discovery, monitoring, analysis, reporting
│   ├── modules/
│   │   ├── education.py        ← Interactive Bluetooth security tutorial
│   │   └── visualizer.py       ← ASCII device relationship graph
│   ├── ui/
│   │   └── dashboard.py        ← Rich TUI menus and panels
│   └── utils/
│       ├── banner.py           ← ASCII banner
│       └── logger.py           ← File + console logging
│
├── scripts/
│   └── install_dependencies.sh ← One-command Kali installer
│
├── docs/
│   └── LAB_EXERCISES.md        ← 6 graded lab exercises
│
├── tests/
│   └── test_engine.py          ← 18 unit tests (all passing)
│
├── reports/                    ← Auto-created, JSON reports saved here
└── logs/                       ← Auto-created, session logs saved here
```

---

## How to Upload to GitHub

```bash
# Inside the bluetooth-spy folder:
git init
git add .
git commit -m "Initial release - Bluetooth Spy by Monish Paramasivam"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/bluetooth-spy.git
git push -u origin main
```

---

## Security Concepts Covered (Educational Mode)

1. **Bluetooth Architecture** — Protocol stack, piconets, Classic vs BLE
2. **Pairing & Authentication** — Just Works vs Numeric Comparison vs Passkey Entry; LE Secure Connections
3. **Known Attacks** — BlueSnarfing, KNOB (CVE-2019-9506), BIAS (CVE-2020-10135), BLE tracking
4. **Defensive Measures** — Hardening checklist, pairing policy, firmware updates
5. **Protocol Analysis Tools** — `hcitool`, `btmon`, `bluetoothctl`, `gatttool`, Wireshark

---

## Security Risk Detection

The tool automatically scores every discovered device:

| Risk Detected | Severity |
|---|---|
| Just Works pairing (no MITM protection) | 🔴 HIGH |
| Legacy PIN pairing (brute-forceable) | 🟡 MEDIUM |
| Anonymous device (no name broadcast) | 🔵 LOW |
| Extremely close-range device | 🔵 LOW |

**Anomaly detection** flags:
- 3+ authentication failures from the same device → possible brute force
- Rapid connect/disconnect cycles → possible DoS pattern

---

## Report Format

Reports are saved as `reports/bt_security_report_YYYYMMDD_HHMMSS.json`:

```json
{
  "title": "Bluetooth Security Analysis Report",
  "author": "Monish Paramasivam",
  "generated_at": "2025-...",
  "summary": {
    "total_devices": 6,
    "security_risks": [...],
    "anomalies": [...],
    "recommendations": [...]
  },
  "devices": { "AA:BB:CC:DD:EE:FF": { ... } },
  "connection_events": [...]
}
```

View with: `cat reports/*.json | python3 -m json.tool`

---

## Running Tests

```bash
python3 tests/test_engine.py
# Expected: 18 tests, 0 failures
```

---

## Requirements

- Kali Linux (or any Debian/Ubuntu with BlueZ)
- Python 3.9+
- Root/sudo access
- Bluetooth adapter (USB dongle works fine)

Python packages: `bleak`, `rich`, `scapy` — all installed by `install_dependencies.sh`

---

## References

- [Bluetooth Core Specification 5.4](https://www.bluetooth.com/specifications/specs/)
- [NIST SP 800-121 Rev 2 — Bluetooth Security Guide](https://csrc.nist.gov/publications/detail/sp/800-121/rev-2/final)
- [KNOB Attack — CVE-2019-9506](https://knobattack.com/)
- [BIAS Attack — CVE-2020-10135](https://biasattack.com/)

---

**Made by Monish Paramasivam** | Academic Cybersecurity Research | MIT License
