#!/usr/bin/env python3
"""
Bluetooth Engine - Core scanning, monitoring, and analysis engine.
Made by Monish Paramasivam
"""

import asyncio
import subprocess
import re
import json
import time
import threading
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, Callable
from enum import Enum


class DeviceType(Enum):
    CLASSIC = "Bluetooth Classic"
    BLE = "Bluetooth Low Energy"
    DUAL = "Dual Mode (Classic + BLE)"
    UNKNOWN = "Unknown"


class PairingMode(Enum):
    JUST_WORKS = "Just Works (No authentication)"
    NUMERIC_COMPARISON = "Numeric Comparison"
    PASSKEY_ENTRY = "Passkey Entry"
    OUT_OF_BAND = "Out of Band (OOB)"
    LEGACY_PIN = "Legacy PIN (Bluetooth Classic)"
    UNKNOWN = "Unknown"


class SecurityLevel(Enum):
    NONE = ("NONE", "red", 0)
    LOW = ("LOW", "yellow", 1)
    MEDIUM = ("MEDIUM", "orange1", 2)
    HIGH = ("HIGH", "green", 3)

    def __init__(self, label, color, rank):
        self.label = label
        self.color = color
        self.rank = rank


@dataclass
class BluetoothDevice:
    """Represents a discovered Bluetooth device with all metadata."""
    address: str
    name: str = "Unknown"
    device_type: DeviceType = DeviceType.UNKNOWN
    rssi: int = 0
    manufacturer: str = "Unknown"
    services: list = field(default_factory=list)
    pairing_mode: PairingMode = PairingMode.UNKNOWN
    security_level: SecurityLevel = SecurityLevel.NONE
    is_paired: bool = False
    is_connected: bool = False
    is_trusted: bool = False
    vendor_class: str = ""
    lmp_version: str = ""
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    connection_count: int = 0
    flags: list = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)
    anomalies: list = field(default_factory=list)
    security_risks: list = field(default_factory=list)

    def update_seen(self):
        self.last_seen = datetime.now().isoformat()

    def assess_security(self):
        """Perform automated security assessment of this device."""
        risks = []
        if self.pairing_mode == PairingMode.JUST_WORKS:
            risks.append({
                "severity": "HIGH",
                "title": "Just Works Pairing",
                "description": "Device uses Just Works pairing which provides no MITM protection.",
                "recommendation": "Use Numeric Comparison or Passkey Entry pairing instead."
            })
        if self.pairing_mode == PairingMode.LEGACY_PIN:
            risks.append({
                "severity": "MEDIUM",
                "title": "Legacy PIN Pairing",
                "description": "Legacy PIN pairing is vulnerable to brute-force attacks.",
                "recommendation": "Upgrade to Secure Simple Pairing (SSP) modes."
            })
        if self.rssi > -40:
            risks.append({
                "severity": "LOW",
                "title": "Very Close Range Device",
                "description": f"Device is extremely close (RSSI: {self.rssi} dBm). High signal strength.",
                "recommendation": "Verify this is an expected device in your environment."
            })
        if self.name == "Unknown" or self.name == "":
            risks.append({
                "severity": "LOW",
                "title": "Anonymous Device",
                "description": "Device broadcasts no name, which may indicate stealth mode.",
                "recommendation": "Investigate device identity through service discovery."
            })
        self.security_risks = risks
        if len(risks) == 0:
            self.security_level = SecurityLevel.HIGH
        elif all(r["severity"] == "LOW" for r in risks):
            self.security_level = SecurityLevel.MEDIUM
        elif any(r["severity"] == "HIGH" for r in risks):
            self.security_level = SecurityLevel.NONE
        else:
            self.security_level = SecurityLevel.LOW
        return risks

    def to_dict(self):
        d = asdict(self)
        d['device_type'] = self.device_type.value
        d['pairing_mode'] = self.pairing_mode.value
        d['security_level'] = self.security_level.label
        return d


@dataclass
class ConnectionEvent:
    """Represents a Bluetooth connection or disconnection event."""
    event_type: str  # "connect", "disconnect", "pair", "auth_fail", "link_key"
    device_address: str
    device_name: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    details: dict = field(default_factory=dict)
    is_anomalous: bool = False
    anomaly_reason: str = ""


class BluetoothEngine:
    """
    Core engine for Bluetooth discovery, monitoring, and analysis.
    Made by Monish Paramasivam
    """

    def __init__(self, interface: str = "hci0", output_dir: str = "./reports",
                 logger=None):
        self.interface = interface
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logger

        self.devices: dict[str, BluetoothDevice] = {}
        self.connection_events: list[ConnectionEvent] = []
        self.is_scanning = False
        self.is_monitoring = False
        self.scan_start_time = None

        self._callbacks: dict[str, list[Callable]] = {
            "device_found": [],
            "device_updated": [],
            "connection_event": [],
            "anomaly_detected": [],
            "scan_complete": [],
        }

        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        self._oui_db = self._load_oui_database()

    def on(self, event: str, callback: Callable):
        """Register a callback for an event."""
        if event in self._callbacks:
            self._callbacks[event].append(callback)

    def _emit(self, event: str, data=None):
        """Emit an event to all registered callbacks."""
        for cb in self._callbacks.get(event, []):
            try:
                cb(data)
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Callback error for {event}: {e}")

    def _load_oui_database(self) -> dict:
        """Load basic OUI (Organizationally Unique Identifier) database."""
        return {
            "00:1A:7D": "Apple Inc.",
            "00:17:F2": "Apple Inc.",
            "AC:DE:48": "Apple Inc.",
            "00:23:12": "Apple Inc.",
            "FC:FB:FB": "Apple Inc.",
            "28:CF:E9": "Apple Inc.",
            "00:1B:63": "Apple Inc.",
            "B8:8D:12": "Samsung Electronics",
            "A0:07:98": "Samsung Electronics",
            "00:15:99": "Samsung Electronics",
            "38:16:D1": "Samsung Electronics",
            "CC:3A:61": "Samsung Electronics",
            "00:23:76": "Samsung Electronics",
            "00:21:86": "Sony Corporation",
            "00:24:BE": "Sony Corporation",
            "00:13:A9": "Sony Corporation",
            "00:1D:BA": "Sony Corporation",
            "00:22:43": "Broadcom",
            "00:0F:61": "LG Electronics",
            "00:E0:91": "LG Electronics",
            "00:50:F2": "Microsoft Corporation",
            "28:18:78": "Microsoft Corporation",
            "7C:ED:8D": "Intel Corporate",
            "00:1F:E2": "Intel Corporate",
            "00:11:22": "Intel Corporate",
            "00:19:86": "Fitbit Inc.",
            "C4:9D:ED": "Fitbit Inc.",
        }

    def get_manufacturer(self, mac: str) -> str:
        """Lookup manufacturer from MAC OUI prefix."""
        oui = mac[:8].upper()
        return self._oui_db.get(oui, "Unknown Manufacturer")

    def run_hci_command(self, cmd: str, timeout: int = 10) -> tuple[str, str, int]:
        """Execute an HCI command and return stdout, stderr, returncode."""
        try:
            result = subprocess.run(
                cmd.split(),
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timed out", 1
        except FileNotFoundError as e:
            return "", str(e), 1

    def initialize_interface(self) -> bool:
        """Initialize and validate the Bluetooth interface."""
        stdout, stderr, rc = self.run_hci_command(f"hciconfig {self.interface} up")
        if rc != 0:
            if self.logger:
                self.logger.error(f"Failed to bring up {self.interface}: {stderr}")
            return False

        stdout, stderr, rc = self.run_hci_command(f"hciconfig {self.interface}")
        if self.logger:
            self.logger.info(f"Interface {self.interface} initialized")
        return True

    def run_discovery(self, duration: int = 30, callback=None) -> dict:
        """
        Discover both Bluetooth Classic and BLE devices.
        Returns dict of discovered devices.
        """
        self.is_scanning = True
        self.scan_start_time = datetime.now()
        if self.logger:
            self.logger.info(f"Starting device discovery for {duration}s on {self.interface}")

        # Run Classic BT scan
        classic_devices = self._scan_classic(duration // 2)
        # Run BLE scan
        ble_devices = self._scan_ble(duration // 2)

        # Merge results
        for addr, dev in {**classic_devices, **ble_devices}.items():
            if addr in self.devices:
                self.devices[addr].update_seen()
                self.devices[addr].connection_count += 1
                self._emit("device_updated", self.devices[addr])
            else:
                self.devices[addr] = dev
                dev.assess_security()
                self._emit("device_found", dev)

        self.is_scanning = False
        self._emit("scan_complete", self.devices)
        if callback:
            callback(self.devices)
        return self.devices

    def _scan_classic(self, duration: int) -> dict:
        """Scan for Bluetooth Classic devices using hcitool."""
        devices = {}
        try:
            stdout, stderr, rc = self.run_hci_command(
                f"hcitool -i {self.interface} scan --flush",
                timeout=duration + 5
            )
            if rc == 0 and stdout:
                for line in stdout.strip().split('\n'):
                    line = line.strip()
                    if ':' in line and len(line.split()) >= 1:
                        parts = line.split(None, 1)
                        if len(parts) >= 1:
                            addr = parts[0].strip()
                            name = parts[1].strip() if len(parts) > 1 else "Unknown"
                            if re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', addr):
                                dev = BluetoothDevice(
                                    address=addr,
                                    name=name,
                                    device_type=DeviceType.CLASSIC,
                                    manufacturer=self.get_manufacturer(addr)
                                )
                                self._enrich_classic_device(dev)
                                devices[addr] = dev
        except Exception as e:
            if self.logger:
                self.logger.warning(f"Classic scan error: {e}. Using simulated data for demo.")
            devices = self._get_demo_classic_devices()
        return devices

    def _scan_ble(self, duration: int) -> dict:
        """Scan for BLE devices using hcitool lescan."""
        devices = {}
        try:
            proc = subprocess.Popen(
                ["hcitool", "-i", self.interface, "lescan", "--duplicate"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            time.sleep(duration)
            proc.terminate()
            stdout, _ = proc.communicate(timeout=5)

            seen = set()
            for line in stdout.strip().split('\n'):
                parts = line.strip().split(None, 1)
                if len(parts) >= 1:
                    addr = parts[0].strip()
                    if re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', addr) and addr not in seen:
                        seen.add(addr)
                        name = parts[1].strip() if len(parts) > 1 else "(unknown)"
                        if name == "(unknown)":
                            name = "Unknown BLE Device"
                        dev = BluetoothDevice(
                            address=addr,
                            name=name,
                            device_type=DeviceType.BLE,
                            manufacturer=self.get_manufacturer(addr)
                        )
                        self._enrich_ble_device(dev)
                        devices[addr] = dev
        except Exception as e:
            if self.logger:
                self.logger.warning(f"BLE scan error: {e}. Using simulated data for demo.")
            devices = self._get_demo_ble_devices()
        return devices

    def _enrich_classic_device(self, device: BluetoothDevice):
        """Get additional info about a Classic BT device."""
        stdout, _, rc = self.run_hci_command(
            f"hcitool -i {self.interface} info {device.address}", timeout=8
        )
        if rc == 0 and stdout:
            for line in stdout.split('\n'):
                if 'LMP Version' in line:
                    device.lmp_version = line.split(':', 1)[-1].strip()
                if 'Device Class' in line:
                    device.vendor_class = line.split(':', 1)[-1].strip()

        # Check pairing info via bluetoothctl
        stdout, _, rc = self.run_hci_command("bluetoothctl devices Paired", timeout=5)
        if device.address in stdout:
            device.is_paired = True
            device.pairing_mode = PairingMode.LEGACY_PIN

    def _enrich_ble_device(self, device: BluetoothDevice):
        """Enrich BLE device with service information."""
        device.pairing_mode = PairingMode.JUST_WORKS  # Default for many BLE devices
        device.flags = ["LE General Discoverable Mode", "BR/EDR Not Supported"]

    def _get_demo_classic_devices(self) -> dict:
        """Return demo Classic BT devices for educational demonstration."""
        demo = {
            "AA:BB:CC:11:22:33": BluetoothDevice(
                address="AA:BB:CC:11:22:33",
                name="Demo Laptop (HP EliteBook)",
                device_type=DeviceType.CLASSIC,
                rssi=-65,
                manufacturer="Intel Corporate",
                pairing_mode=PairingMode.NUMERIC_COMPARISON,
                lmp_version="Bluetooth 5.0",
                vendor_class="Computer - Laptop",
                services=["Serial Port", "Audio Source", "HID"],
            ),
            "DD:EE:FF:44:55:66": BluetoothDevice(
                address="DD:EE:FF:44:55:66",
                name="Demo Speaker (JBL Flip 5)",
                device_type=DeviceType.CLASSIC,
                rssi=-78,
                manufacturer="Unknown Manufacturer",
                pairing_mode=PairingMode.JUST_WORKS,
                lmp_version="Bluetooth 4.2",
                services=["A2DP Audio Sink", "AVRCP"],
            ),
            "11:22:33:AA:BB:CC": BluetoothDevice(
                address="11:22:33:AA:BB:CC",
                name="Demo Phone (Samsung Galaxy)",
                device_type=DeviceType.DUAL,
                rssi=-55,
                manufacturer="Samsung Electronics",
                pairing_mode=PairingMode.PASSKEY_ENTRY,
                lmp_version="Bluetooth 5.2",
                services=["Handsfree", "OBEX Push", "PAN"],
                is_paired=True,
            ),
        }
        for dev in demo.values():
            dev.assess_security()
        return demo

    def _get_demo_ble_devices(self) -> dict:
        """Return demo BLE devices for educational demonstration."""
        demo = {
            "BE:EF:DE:AD:00:01": BluetoothDevice(
                address="BE:EF:DE:AD:00:01",
                name="Demo Fitness Tracker",
                device_type=DeviceType.BLE,
                rssi=-72,
                manufacturer="Fitbit Inc.",
                pairing_mode=PairingMode.JUST_WORKS,
                services=["Heart Rate", "Battery Service", "Device Info"],
                flags=["LE General Discoverable Mode"],
            ),
            "CA:FE:BA:BE:00:02": BluetoothDevice(
                address="CA:FE:BA:BE:00:02",
                name="BLE Smart Lock",
                device_type=DeviceType.BLE,
                rssi=-61,
                manufacturer="Unknown Manufacturer",
                pairing_mode=PairingMode.JUST_WORKS,
                services=["Generic Access", "Lock Service"],
                flags=["LE General Discoverable Mode", "BR/EDR Not Supported"],
            ),
            "DE:AD:BE:EF:00:03": BluetoothDevice(
                address="DE:AD:BE:EF:00:03",
                name="Unknown BLE Device",
                device_type=DeviceType.BLE,
                rssi=-88,
                manufacturer="Unknown Manufacturer",
                pairing_mode=PairingMode.UNKNOWN,
                services=[],
            ),
        }
        for dev in demo.values():
            dev.assess_security()
        return demo

    def run_monitor(self, duration: int = 0, callback=None):
        """Monitor Bluetooth connection and disconnection events via btmon."""
        self.is_monitoring = True
        self._stop_event.clear()
        if self.logger:
            self.logger.info("Starting Bluetooth event monitor...")

        def monitor_loop():
            try:
                proc = subprocess.Popen(
                    ["btmon", "-i", self.interface],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1
                )
                start = time.time()
                for line in proc.stdout:
                    if self._stop_event.is_set():
                        break
                    if duration > 0 and (time.time() - start) > duration:
                        break
                    event = self._parse_btmon_line(line)
                    if event:
                        self.connection_events.append(event)
                        self._emit("connection_event", event)
                        self._check_anomaly(event)
                        if callback:
                            callback(event)
                proc.terminate()
            except FileNotFoundError:
                # btmon not available — use simulated events for demo
                self._run_demo_monitor(duration, callback)

        self._monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self._monitor_thread.start()

    def _run_demo_monitor(self, duration: int, callback=None):
        """Simulate connection events for educational demo when btmon unavailable."""
        demo_events = [
            ConnectionEvent("connect", "AA:BB:CC:11:22:33", "Demo Laptop",
                            details={"reason": "User initiated", "link_type": "ACL"}),
            ConnectionEvent("pair", "DD:EE:FF:44:55:66", "Demo Speaker",
                            details={"pairing_mode": "Just Works", "auth": "None (MITM risk)"}),
            ConnectionEvent("auth_fail", "11:22:33:AA:BB:CC", "Unknown Device",
                            details={"reason": "Authentication failure", "attempts": 3},
                            is_anomalous=True, anomaly_reason="Repeated auth failures — possible brute force"),
            ConnectionEvent("disconnect", "AA:BB:CC:11:22:33", "Demo Laptop",
                            details={"reason": "Remote user ended connection", "duration_sec": 45}),
            ConnectionEvent("connect", "BE:EF:DE:AD:00:01", "Demo Fitness Tracker",
                            details={"link_type": "LE", "encryption": "AES-CCM"}),
        ]
        for i, event in enumerate(demo_events):
            if self._stop_event.is_set():
                break
            time.sleep(2)
            self.connection_events.append(event)
            self._emit("connection_event", event)
            if event.is_anomalous:
                self._emit("anomaly_detected", event)
            if callback:
                callback(event)

    def _parse_btmon_line(self, line: str) -> Optional[ConnectionEvent]:
        """Parse a btmon output line into a ConnectionEvent."""
        line = line.strip()
        if "Connect Complete" in line or "Connection Request" in line:
            addr_match = re.search(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', line)
            addr = addr_match.group(0) if addr_match else "Unknown"
            name = self.devices.get(addr, BluetoothDevice(addr)).name
            return ConnectionEvent("connect", addr, name, details={"raw": line})
        elif "Disconnect Complete" in line:
            addr_match = re.search(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', line)
            addr = addr_match.group(0) if addr_match else "Unknown"
            name = self.devices.get(addr, BluetoothDevice(addr)).name
            return ConnectionEvent("disconnect", addr, name, details={"raw": line})
        elif "Link Key" in line:
            addr_match = re.search(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', line)
            addr = addr_match.group(0) if addr_match else "Unknown"
            name = self.devices.get(addr, BluetoothDevice(addr)).name
            return ConnectionEvent("link_key", addr, name,
                                   details={"raw": line, "note": "Link key negotiated"})
        elif "Authentication" in line and "Failed" in line:
            addr_match = re.search(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', line)
            addr = addr_match.group(0) if addr_match else "Unknown"
            name = self.devices.get(addr, BluetoothDevice(addr)).name
            return ConnectionEvent("auth_fail", addr, name,
                                   details={"raw": line}, is_anomalous=True,
                                   anomaly_reason="Authentication failure detected")
        return None

    def _check_anomaly(self, event: ConnectionEvent):
        """Check if an event represents anomalous behavior."""
        if event.event_type == "auth_fail":
            # Count recent auth failures from same device
            recent_fails = sum(1 for e in self.connection_events[-20:]
                               if e.event_type == "auth_fail" and e.device_address == event.device_address)
            if recent_fails >= 3:
                event.is_anomalous = True
                event.anomaly_reason = f"Repeated auth failures ({recent_fails}x) — possible brute force"
                self._emit("anomaly_detected", event)

        # Detect rapid connection cycling
        recent_connects = [e for e in self.connection_events[-10:]
                           if e.device_address == event.device_address and
                           e.event_type in ("connect", "disconnect")]
        if len(recent_connects) >= 4:
            event.is_anomalous = True
            event.anomaly_reason = "Rapid connect/disconnect cycling — possible DoS pattern"
            self._emit("anomaly_detected", event)

    def run_analysis(self) -> dict:
        """Analyze captured devices and events for security issues."""
        report = {
            "total_devices": len(self.devices),
            "device_types": {},
            "security_risks": [],
            "anomalies": [],
            "pairing_modes": {},
            "recommendations": [],
            "timestamp": datetime.now().isoformat(),
            "analyst": "Monish Paramasivam - Bluetooth Spy"
        }

        for dtype in DeviceType:
            count = sum(1 for d in self.devices.values() if d.device_type == dtype)
            if count:
                report["device_types"][dtype.value] = count

        for pmode in PairingMode:
            count = sum(1 for d in self.devices.values() if d.pairing_mode == pmode)
            if count:
                report["pairing_modes"][pmode.value] = count

        for device in self.devices.values():
            for risk in device.security_risks:
                report["security_risks"].append({
                    "device": device.name,
                    "address": device.address,
                    **risk
                })

        report["anomalies"] = [
            {
                "event": e.event_type,
                "device": e.device_name,
                "address": e.device_address,
                "time": e.timestamp,
                "reason": e.anomaly_reason
            }
            for e in self.connection_events if e.is_anomalous
        ]

        # Build recommendations
        just_works_count = sum(1 for d in self.devices.values()
                               if d.pairing_mode == PairingMode.JUST_WORKS)
        if just_works_count > 0:
            report["recommendations"].append(
                f"{just_works_count} device(s) use Just Works pairing. "
                "Disable or reconfigure to use authenticated pairing methods."
            )
        if report["anomalies"]:
            report["recommendations"].append(
                "Investigate anomalous authentication failures for signs of active attacks."
            )
        report["recommendations"].append(
            "Enable Bluetooth only when needed. Use 'Non-discoverable' mode when not pairing."
        )
        report["recommendations"].append(
            "Regularly audit paired device lists and remove unknown or unused entries."
        )

        return report

    def generate_report(self, fmt: str = "json") -> str:
        """Generate and save a full security report."""
        analysis = self.run_analysis()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.output_dir / f"bt_security_report_{ts}.json"

        report_data = {
            "title": "Bluetooth Security Analysis Report",
            "tool": "Bluetooth Spy",
            "author": "Monish Paramasivam",
            "generated_at": datetime.now().isoformat(),
            "interface": self.interface,
            "summary": analysis,
            "devices": {addr: dev.to_dict() for addr, dev in self.devices.items()},
            "connection_events": [
                {
                    "type": e.event_type,
                    "address": e.device_address,
                    "name": e.device_name,
                    "time": e.timestamp,
                    "details": e.details,
                    "anomalous": e.is_anomalous,
                    "anomaly_reason": e.anomaly_reason
                }
                for e in self.connection_events
            ]
        }

        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)

        if self.logger:
            self.logger.info(f"Report saved to {filename}")
        return str(filename)

    def stop_monitor(self):
        """Stop active monitoring."""
        self._stop_event.set()
        self.is_monitoring = False

    def run_full_scan(self, duration: int = 60):
        """Run a complete scan: discovery + monitoring."""
        self.run_discovery(duration=duration // 2)
        self.run_monitor(duration=duration // 2)
