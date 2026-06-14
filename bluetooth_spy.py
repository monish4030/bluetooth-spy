#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          BLUETOOTH SPY - Security Research Toolkit              ║
║                    Made by Monish Paramasivam                               ║
║             Academic Cybersecurity Research Tool for Kali Linux             ║
╚══════════════════════════════════════════════════════════════════════════════╝

This tool is designed exclusively for:
  - Academic cybersecurity research and education
  - Authorized penetration testing in controlled lab environments
  - Understanding Bluetooth protocol security mechanisms
  - Defensive security analysis

WARNING: Unauthorized use against devices you do not own or have explicit
         permission to test is illegal and unethical.
"""

import sys
import os
import argparse
import signal
import logging
from datetime import datetime
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from ui.dashboard import BluetoothDashboard
from core.bluetooth_engine import BluetoothEngine
from utils.logger import setup_logger
from utils.banner import print_banner


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Bluetooth Spy - Security Research Toolkit by Monish Paramasivam",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 bluetooth_spy.py                    # Launch interactive dashboard
  python3 bluetooth_spy.py --scan --duration 30  # Scan for 30 seconds
  python3 bluetooth_spy.py --monitor          # Monitor connection events
  python3 bluetooth_spy.py --analyze          # Analyze captured data
  python3 bluetooth_spy.py --report           # Generate security report

Academic Use Only. Made by Monish Paramasivam.
        """
    )

    parser.add_argument("--scan", action="store_true",
                        help="Discover Bluetooth Classic and BLE devices")
    parser.add_argument("--monitor", action="store_true",
                        help="Monitor connection/disconnection events")
    parser.add_argument("--analyze", action="store_true",
                        help="Analyze pairing and authentication processes")
    parser.add_argument("--capture", action="store_true",
                        help="Capture Bluetooth protocol data")
    parser.add_argument("--report", action="store_true",
                        help="Generate detailed security report")
    parser.add_argument("--duration", type=int, default=60,
                        help="Scan/monitor duration in seconds (default: 60)")
    parser.add_argument("--interface", type=str, default="hci0",
                        help="Bluetooth interface (default: hci0)")
    parser.add_argument("--output", type=str, default="./reports",
                        help="Output directory for reports/logs")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose output")
    parser.add_argument("--no-ui", action="store_true",
                        help="Run in headless CLI mode (no TUI dashboard)")
    parser.add_argument("--educational", action="store_true",
                        help="Show educational Bluetooth security concepts")

    return parser.parse_args()


def check_root():
    """Bluetooth operations require root privileges."""
    if os.geteuid() != 0:
        print("\n[!] Root privileges required for Bluetooth operations.")
        print("    Run with: sudo python3 bluetooth_spy.py\n")
        sys.exit(1)


def check_dependencies():
    """Verify required tools and Python packages are available."""
    missing = []
    optional_missing = []

    required_tools = ["hciconfig", "hcitool", "bluetoothctl"]
    optional_tools = ["btlejack", "wireshark", "ubertooth-util"]

    for tool in required_tools:
        if os.system(f"which {tool} > /dev/null 2>&1") != 0:
            missing.append(tool)

    for tool in optional_tools:
        if os.system(f"which {tool} > /dev/null 2>&1") != 0:
            optional_missing.append(tool)

    required_packages = ["bleak", "rich", "scapy"]
    for pkg in required_packages:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(f"python3-{pkg}")

    if missing:
        print(f"\n[!] Missing required dependencies: {', '.join(missing)}")
        print("    Run: ./scripts/install_dependencies.sh\n")
        sys.exit(1)

    if optional_missing:
        print(f"[~] Optional tools not found (reduced functionality): {', '.join(optional_missing)}")

    return True


def signal_handler(signum, frame):
    """Graceful shutdown on Ctrl+C."""
    print("\n\n[*] Shutdown signal received. Saving logs and generating report...")
    print("[*] Bluetooth Spy stopped gracefully.")
    print("[*] Made by Monish Paramasivam\n")
    sys.exit(0)


def run_educational_mode():
    """Display Bluetooth security educational content."""
    from modules.education import BluetoothEducation
    edu = BluetoothEducation()
    edu.run_interactive_tutorial()


def main():
    print_banner()
    args = parse_arguments()

    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger = setup_logger(log_level, args.output)
    logger.info("Bluetooth Spy starting - Made by Monish Paramasivam")

    # Root check (can be bypassed in demo mode)
    check_root()

    # Dependency check
    check_dependencies()

    # Educational mode
    if args.educational:
        run_educational_mode()
        return

    # Initialize Bluetooth engine
    engine = BluetoothEngine(
        interface=args.interface,
        output_dir=args.output,
        logger=logger
    )

    # CLI mode (no TUI)
    if args.no_ui:
        if args.scan:
            engine.run_discovery(duration=args.duration)
        elif args.monitor:
            engine.run_monitor(duration=args.duration)
        elif args.analyze:
            engine.run_analysis()
        elif args.capture:
            engine.run_capture(duration=args.duration)
        elif args.report:
            engine.generate_report()
        else:
            # Run full scan by default
            engine.run_full_scan(duration=args.duration)
    else:
        # Launch interactive TUI dashboard
        dashboard = BluetoothDashboard(engine=engine, args=args)
        dashboard.run()


if __name__ == "__main__":
    main()
