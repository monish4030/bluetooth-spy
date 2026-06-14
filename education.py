#!/usr/bin/env python3
"""
Bluetooth Security Educational Module
Made by Monish Paramasivam
"""

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.tree import Tree
    from rich.columns import Columns
    from rich import box
    from rich.prompt import Prompt
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


CONCEPTS = {
    "1": {
        "title": "Bluetooth Architecture Overview",
        "icon": "🏗️",
        "content": """
Bluetooth operates on a layered protocol stack:

┌─────────────────────────────────────────────┐
│         APPLICATION LAYER                    │
│  Profiles: A2DP, HFP, HID, GATT, etc.       │
├─────────────────────────────────────────────┤
│         HOST LAYER                           │
│  L2CAP │ SDP │ RFCOMM │ ATT │ SMP │ GAP     │
├─────────────────────────────────────────────┤
│         HCI (Host Controller Interface)      │
├─────────────────────────────────────────────┤
│         CONTROLLER LAYER                     │
│  Link Manager │ Baseband │ Radio             │
└─────────────────────────────────────────────┘

KEY CONCEPTS:
• Piconet: 1 master + up to 7 active slaves
• Scatternet: Multiple overlapping piconets
• Classic BT: 2.4 GHz, FHSS (1600 hops/sec)
• BLE: 40 channels, 3 advertising channels
• Both operate in the 2.4 GHz ISM band
        """,
        "key_points": [
            "Bluetooth uses frequency hopping spread spectrum (FHSS) to resist interference",
            "BLE uses a different physical layer optimized for low power devices",
            "The HCI is the boundary between hardware and software stack",
            "ATT/GATT (Attribute Protocol) is the core of BLE data exchange"
        ]
    },
    "2": {
        "title": "Pairing & Authentication Deep Dive",
        "icon": "🔑",
        "content": """
BLUETOOTH CLASSIC PAIRING EVOLUTION:
─────────────────────────────────────
Legacy Pairing (BT < 2.1):
  • PIN-based, symmetric key
  • Vulnerable to offline brute force
  • Short PINs (4-digit) easily cracked
  • MITM possible during PIN exchange

Secure Simple Pairing / SSP (BT 2.1+):
  • Elliptic Curve Diffie-Hellman (ECDH)
  • Public key exchange protects against MITM
  • 4 sub-methods (see below)

BLE PAIRING:
─────────────────────────────────────
Phase 1: Pairing Feature Exchange
  → Determine IO capabilities
  → Agree on pairing method

Phase 2: Key Generation  
  → LE Legacy: STK (Short Term Key) via SMP
  → LE Secure: ECDH + LTK (Long Term Key)

Phase 3: Key Distribution
  → Exchange IRK, CSRK, LTK

SSP / BLE PAIRING METHODS:
┌──────────────────────┬────────────┬────────────┐
│ Method               │ MITM Prot. │ User Input │
├──────────────────────┼────────────┼────────────┤
│ Just Works           │ ❌ None    │ None       │
│ Numeric Comparison   │ ✅ Yes     │ Confirm Y/N│
│ Passkey Entry        │ ✅ Yes     │ 6-digit PIN│
│ Out of Band (OOB)    │ ✅ Yes     │ External   │
└──────────────────────┴────────────┴────────────┘
        """,
        "key_points": [
            "Just Works provides no MITM protection — anyone nearby can pair silently",
            "Numeric Comparison requires user to verify a 6-digit code on BOTH devices",
            "Passkey Entry requires one device to show a code and user type it on other",
            "LE Secure Connections uses stronger ECDH and is resistant to passive eavesdropping",
            "Legacy BLE pairing (LE Legacy) is vulnerable to offline decryption if sniffed"
        ]
    },
    "3": {
        "title": "Known Bluetooth Attack Vectors",
        "icon": "⚔️",
        "content": """
CLASSIC BLUETOOTH ATTACKS:
──────────────────────────
🔴 BlueSnarfing
   • Unauthorized access to device data (contacts, calendar)
   • Exploits OBEX Push Profile vulnerabilities
   • Range: ~10m (can be extended with directional antenna)

🔴 BlueJacking
   • Sending unsolicited messages to nearby devices
   • Relatively harmless but demonstrates discovery risk
   • Exploits Bluetooth name broadcast

🔴 BlueBugging
   • Full device control via AT commands over RFCOMM
   • Makes calls, sends SMS, reads data without user knowledge

🔴 KNOB Attack (Key Negotiation of Bluetooth)
   • CVE-2019-9506 | Affects Bluetooth 1.0–5.1
   • Attacker forces entropy of session key to 1 byte
   • Makes brute force trivial (256 combinations)
   • Fixed: Entropy must be ≥7 bytes

🔴 BIAS Attack (Bluetooth Impersonation Attacks)
   • CVE-2020-10135 | Affects all Bluetooth versions
   • Authentication role switching mid-session
   • Allows device impersonation without link key

BLE-SPECIFIC ATTACKS:
──────────────────────────
🟡 BTLE Replay Attack
   • Capture and replay BLE advertisements
   • Affects smart home devices, garage doors, key fobs

🟡 BLE Passive Eavesdropping
   • LE Legacy pairing: session key derivable from sniff
   • Tools: Ubertooth One, TI CC2540 sniffer

🟡 Advertising Channel MITM
   • Attacker relays/modifies advertising packets
   • Can intercept pairing before completion

🟡 BLE Tracking (MAC Address)
   • Devices using static MACs can be tracked
   • Random resolvable addresses (RPA) mitigate this
   • IRK (Identity Resolving Key) needed to track RPA

DENIAL OF SERVICE:
──────────────────────────
🟠 2.4 GHz RF Jamming
   • Broadband interference disrupts Bluetooth
   • Affects WiFi too (same band)
   • Illegal in most jurisdictions

🟠 LMP/LLCP Flooding  
   • Flood target with Link Manager packets
   • Can cause firmware crashes on some devices
        """,
        "key_points": [
            "Many classic Bluetooth attacks require the attacker to be within radio range (~10-100m)",
            "KNOB and BIAS are protocol-level flaws, not implementation bugs — very widespread",
            "BLE tracking via MAC address is a real privacy concern for wearables and IoT",
            "Modern devices with LE Secure Connections + Numeric Comparison resist most attacks",
            "Always patch firmware — many attacks have been fixed in recent Bluetooth versions"
        ]
    },
    "4": {
        "title": "Defensive Measures & Hardening",
        "icon": "🛡️",
        "content": """
DEVICE HARDENING:
──────────────────────────
✅ Discoverable Mode
   • Set to "Non-discoverable" when not pairing
   • Discoverable mode broadcasts device to all
   • Use "Limited Discoverable" (30-second window)

✅ Pairing Security
   • Always use Numeric Comparison or Passkey Entry
   • Reject Just Works pairing requests if possible
   • Verify pairing codes in person, not over any channel

✅ Firmware & Software
   • Keep Bluetooth firmware updated (KNOB, BIAS patches)
   • Apply OS security patches promptly
   • Disable Bluetooth when not in use

✅ Paired Device Management
   • Regularly audit and remove unknown paired devices
   • Remove devices you no longer use
   • Never pair in public places

BLE-SPECIFIC HARDENING:
──────────────────────────
✅ Use LE Secure Connections (BT 4.2+)
   • Requires LE Secure Connections on both sides
   • Eliminates LE Legacy pairing vulnerabilities

✅ Resolvable Private Addresses (RPA)
   • Prevents device tracking via MAC
   • Requires IRK exchange during bonding
   • Standard on iOS, Android 10+

✅ Encryption & Authentication
   • Enable Link Layer encryption for all connections
   • Use authenticated pairing (not Just Works)
   • Enable MITM protection flags

ENTERPRISE / LAB RECOMMENDATIONS:
──────────────────────────────────
✅ Bluetooth Security Policy
   • Define allowed devices and pairing procedures
   • Log all Bluetooth activity on managed endpoints
   • Block personal BT devices on sensitive networks

✅ Physical Security
   • Control physical access — Bluetooth is short-range
   • Monitor for unauthorized sniffers (Ubertooth, etc.)
   • Use RF shielding in sensitive areas if needed

✅ Monitoring
   • Deploy Bluetooth IDS (this tool!)
   • Alert on new unpaired devices in environment
   • Monitor for authentication failures (brute force)
        """,
        "key_points": [
            "Disabling Bluetooth entirely when not needed is the strongest protection",
            "Enterprise environments should maintain allowlists of approved Bluetooth devices",
            "BLE IoT devices are often the weakest link — prioritize firmware updates",
            "Educate users about pairing in public — Just Works pairing is invisible to users"
        ]
    },
    "5": {
        "title": "Protocol Analysis & Tools",
        "icon": "🔬",
        "content": """
KEY ANALYSIS TOOLS (Kali Linux):
─────────────────────────────────
🔧 hciconfig
   Purpose: Configure Bluetooth interfaces
   Usage:   hciconfig hci0 up / down / reset
            hciconfig -a  (all details)

🔧 hcitool
   Purpose: HCI utility for scan/info
   Usage:   hcitool scan           (Classic)
            hcitool lescan         (BLE)
            hcitool info <addr>    (Device info)
            hcitool cc <addr>      (Connect)

🔧 bluetoothctl
   Purpose: Interactive Bluetooth manager
   Usage:   bluetoothctl
            > scan on
            > pair <addr>
            > info <addr>
            > devices

🔧 btmon
   Purpose: Bluetooth HCI monitor (packet capture)
   Usage:   btmon              (live monitor)
            btmon -w file.bin  (write to file)
            btmon -r file.bin  (read file)

🔧 Wireshark (with btsnoop)
   Purpose: Full packet dissection
   Usage:   wireshark
            Filter: bluetooth || btle
   Notes:   Use btmon to capture, open .bin in Wireshark

🔧 gatttool / bluetoothctl
   Purpose: BLE GATT attribute exploration
   Usage:   gatttool -b <addr> -I
            > connect
            > primary       (list services)
            > characteristics

🔧 Ubertooth One (Hardware)
   Purpose: BLE sniffing, Bluetooth baseband analysis
   Usage:   ubertooth-btle -f -t <addr>
            ubertooth-rx
   Notes:   Hardware dongle required (~$120)

PACKET ANALYSIS WORKFLOW:
─────────────────────────────────
1. Capture:  sudo btmon -w capture.bin
2. Convert:  Use Wireshark or btsnoop2pcap
3. Filter:   bthci_evt || btle_adv
4. Inspect:  HCI events, LMP messages, ATT operations

HCI EVENT TYPES TO WATCH:
─────────────────────────────────
0x05  Disconnection Complete
0x08  Encryption Change
0x09  Change Connection Link Key Complete
0x0E  Command Complete
0x18  Link Key Notification    ← Key exchange
0x1A  Max Slots Change
0x1C  Link Key Request         ← Pairing initiation
0x1D  Pin Code Request         ← Legacy pairing
0x30  IO Capability Request    ← SSP initiation
0x31  IO Capability Response
0x33  User Confirmation Request ← Numeric Comparison
0x34  User Passkey Request     ← Passkey Entry
        """,
        "key_points": [
            "btmon is the most powerful built-in tool for HCI-level protocol analysis",
            "Wireshark can dissect Bluetooth captures from btmon (use btsnoop format)",
            "gatttool allows direct BLE GATT attribute enumeration without special hardware",
            "Ubertooth One is the gold standard for BLE sniffing research hardware"
        ]
    }
}


class BluetoothEducation:
    """Interactive educational module for Bluetooth security concepts."""

    def __init__(self):
        if HAS_RICH:
            self.console = Console()
        else:
            self.console = None

    def run_interactive_tutorial(self, console=None):
        if console:
            self.console = console

        if not HAS_RICH or not self.console:
            self._run_plaintext_tutorial()
            return

        self.console.print(Panel(
            "[bold cyan]🎓 Bluetooth Security Education Center[/bold cyan]\n"
            "[dim]Made by Monish Paramasivam — Academic Reference Material[/dim]",
            border_style="cyan"
        ))

        while True:
            self.console.print("\n[bold]Available Topics:[/bold]")
            for key, concept in CONCEPTS.items():
                self.console.print(f"  [{key}] {concept['icon']} {concept['title']}")
            self.console.print("  [q] ← Back to main menu")

            choice = Prompt.ask("\n[cyan]Select topic[/cyan]",
                                choices=list(CONCEPTS.keys()) + ["q"])
            if choice == "q":
                break

            concept = CONCEPTS[choice]
            self.console.print(Panel(
                concept["content"],
                title=f"[bold cyan]{concept['icon']} {concept['title']}[/bold cyan]",
                border_style="cyan",
                padding=(1, 2)
            ))

            # Show key takeaways
            kp_tree = Tree("💡 [bold yellow]Key Takeaways[/bold yellow]")
            for point in concept["key_points"]:
                kp_tree.add(f"[yellow]→[/yellow] {point}")
            self.console.print(kp_tree)

            Prompt.ask("\n[dim]Press Enter to continue[/dim]", default="")

    def _run_plaintext_tutorial(self):
        """Fallback plaintext tutorial when rich is not available."""
        print("\n=== BLUETOOTH SECURITY EDUCATION ===")
        print("Made by Monish Paramasivam\n")
        for key, concept in CONCEPTS.items():
            print(f"[{key}] {concept['title']}")
        choice = input("\nSelect topic (q to quit): ")
        if choice in CONCEPTS:
            c = CONCEPTS[choice]
            print(f"\n{'='*60}")
            print(f"  {c['title']}")
            print(f"{'='*60}")
            print(c["content"])
            print("\nKey Takeaways:")
            for pt in c["key_points"]:
                print(f"  • {pt}")
