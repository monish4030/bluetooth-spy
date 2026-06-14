#!/usr/bin/env python3
"""
Unit Tests — Bluetooth Spy
Made by Monish Paramasivam
"""

import sys
import os
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.bluetooth_engine import (
    BluetoothEngine, BluetoothDevice, ConnectionEvent,
    DeviceType, SecurityLevel, PairingMode
)


class TestBluetoothDevice(unittest.TestCase):
    """Tests for BluetoothDevice dataclass and security assessment."""

    def setUp(self):
        self.device = BluetoothDevice(
            address="AA:BB:CC:DD:EE:FF",
            name="Test Device",
            device_type=DeviceType.BLE,
            rssi=-70,
            manufacturer="Test Corp",
            pairing_mode=PairingMode.JUST_WORKS
        )

    def test_device_creation(self):
        self.assertEqual(self.device.address, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(self.device.name, "Test Device")
        self.assertEqual(self.device.device_type, DeviceType.BLE)

    def test_just_works_is_high_risk(self):
        risks = self.device.assess_security()
        risk_titles = [r["title"] for r in risks]
        self.assertIn("Just Works Pairing", risk_titles)
        self.assertEqual(self.device.security_level.label, "NONE")

    def test_numeric_comparison_is_safer(self):
        self.device.pairing_mode = PairingMode.NUMERIC_COMPARISON
        self.device.security_risks = []
        risks = self.device.assess_security()
        risk_titles = [r["title"] for r in risks]
        self.assertNotIn("Just Works Pairing", risk_titles)

    def test_anonymous_device_detected(self):
        self.device.pairing_mode = PairingMode.NUMERIC_COMPARISON
        self.device.name = "Unknown"
        risks = self.device.assess_security()
        risk_titles = [r["title"] for r in risks]
        self.assertIn("Anonymous Device", risk_titles)

    def test_very_close_range_detected(self):
        self.device.pairing_mode = PairingMode.NUMERIC_COMPARISON
        self.device.name = "Named Device"
        self.device.rssi = -30  # Very strong signal
        risks = self.device.assess_security()
        risk_titles = [r["title"] for r in risks]
        self.assertIn("Very Close Range Device", risk_titles)

    def test_to_dict(self):
        d = self.device.to_dict()
        self.assertIn("address", d)
        self.assertIn("device_type", d)
        self.assertIsInstance(d["device_type"], str)  # Should be value, not enum

    def test_update_seen(self):
        old_time = self.device.last_seen
        import time; time.sleep(0.01)
        self.device.update_seen()
        self.assertNotEqual(self.device.last_seen, old_time)


class TestBluetoothEngine(unittest.TestCase):
    """Tests for the BluetoothEngine core logic."""

    def setUp(self):
        self.engine = BluetoothEngine(
            interface="hci0",
            output_dir="/tmp/bt_test_output"
        )

    def test_engine_init(self):
        self.assertEqual(self.engine.interface, "hci0")
        self.assertIsInstance(self.engine.devices, dict)
        self.assertIsInstance(self.engine.connection_events, list)
        self.assertFalse(self.engine.is_scanning)
        self.assertFalse(self.engine.is_monitoring)

    def test_oui_lookup_known(self):
        # Apple OUI
        mfr = self.engine.get_manufacturer("00:1A:7D:AA:BB:CC")
        self.assertEqual(mfr, "Apple Inc.")

    def test_oui_lookup_unknown(self):
        mfr = self.engine.get_manufacturer("FF:FF:FF:00:00:00")
        self.assertEqual(mfr, "Unknown Manufacturer")

    def test_demo_classic_devices(self):
        devices = self.engine._get_demo_classic_devices()
        self.assertGreater(len(devices), 0)
        for addr, dev in devices.items():
            self.assertIsInstance(dev, BluetoothDevice)
            self.assertIn(dev.device_type, (DeviceType.CLASSIC, DeviceType.DUAL))

    def test_demo_ble_devices(self):
        devices = self.engine._get_demo_ble_devices()
        self.assertGreater(len(devices), 0)
        for addr, dev in devices.items():
            self.assertIsInstance(dev, BluetoothDevice)
            self.assertEqual(dev.device_type, DeviceType.BLE)

    def test_callback_registration(self):
        called_with = []
        self.engine.on("device_found", lambda d: called_with.append(d))
        test_device = BluetoothDevice("AA:BB:CC:DD:EE:FF", "Test")
        self.engine._emit("device_found", test_device)
        self.assertEqual(len(called_with), 1)
        self.assertEqual(called_with[0].address, "AA:BB:CC:DD:EE:FF")

    def test_anomaly_detection_repeated_auth_fails(self):
        device_addr = "11:22:33:44:55:66"
        # Add 3 auth failures
        for i in range(3):
            event = ConnectionEvent(
                event_type="auth_fail",
                device_address=device_addr,
                device_name="Attacker Device"
            )
            self.engine.connection_events.append(event)
            self.engine._check_anomaly(event)

        # Last event should be marked anomalous
        last = self.engine.connection_events[-1]
        self.assertTrue(last.is_anomalous)
        self.assertIn("brute force", last.anomaly_reason.lower())

    def test_analysis_output(self):
        # Load some demo devices
        self.engine.devices = self.engine._get_demo_classic_devices()
        analysis = self.engine.run_analysis()

        self.assertIn("total_devices", analysis)
        self.assertIn("security_risks", analysis)
        self.assertIn("recommendations", analysis)
        self.assertIn("pairing_modes", analysis)
        self.assertGreater(analysis["total_devices"], 0)
        self.assertIn("Monish Paramasivam", analysis["analyst"])

    def test_report_generation(self):
        self.engine.devices = self.engine._get_demo_ble_devices()
        filename = self.engine.generate_report()
        self.assertTrue(Path(filename).exists())
        import json
        with open(filename) as f:
            data = json.load(f)
        self.assertEqual(data["author"], "Monish Paramasivam")
        self.assertIn("devices", data)


class TestConnectionEvent(unittest.TestCase):
    """Tests for ConnectionEvent."""

    def test_event_creation(self):
        event = ConnectionEvent(
            event_type="connect",
            device_address="AA:BB:CC:DD:EE:FF",
            device_name="Test Device"
        )
        self.assertEqual(event.event_type, "connect")
        self.assertFalse(event.is_anomalous)
        self.assertIsNotNone(event.timestamp)

    def test_anomalous_event(self):
        event = ConnectionEvent(
            event_type="auth_fail",
            device_address="AA:BB:CC:DD:EE:FF",
            device_name="Unknown",
            is_anomalous=True,
            anomaly_reason="Repeated auth failures"
        )
        self.assertTrue(event.is_anomalous)
        self.assertEqual(event.anomaly_reason, "Repeated auth failures")


if __name__ == "__main__":
    print("="*60)
    print("Bluetooth Spy — Unit Tests")
    print("Made by Monish Paramasivam")
    print("="*60)
    unittest.main(verbosity=2)
