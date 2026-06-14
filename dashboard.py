#!/usr/bin/env python3
"""
Bluetooth Spy - Interactive TUI Dashboard
Made by Monish Paramasivam
"""

import threading
import time
from datetime import datetime

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.live import Live
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.columns import Columns
    from rich.prompt import Prompt, Confirm
    from rich.tree import Tree
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from core.bluetooth_engine import (
    BluetoothEngine, BluetoothDevice, ConnectionEvent,
    DeviceType, SecurityLevel, PairingMode
)


class BluetoothDashboard:
    """
    Interactive terminal dashboard for the Bluetooth Spy.
    Made by Monish Paramasivam
    """

    def __init__(self, engine: BluetoothEngine, args=None):
        self.engine = engine
        self.args = args
        self.console = Console()
        self.running = True
        self._log_lines = []
        self._max_log = 20

        # Register engine callbacks
        self.engine.on("device_found", self._on_device_found)
        self.engine.on("device_updated", self._on_device_updated)
        self.engine.on("connection_event", self._on_connection_event)
        self.engine.on("anomaly_detected", self._on_anomaly_detected)
        self.engine.on("scan_complete", self._on_scan_complete)

    def _log(self, msg: str, level: str = "info"):
        colors = {"info": "cyan", "warn": "yellow", "error": "red",
                  "success": "green", "anomaly": "bold red"}
        color = colors.get(level, "white")
        ts = datetime.now().strftime("%H:%M:%S")
        self._log_lines.append(f"[{color}][{ts}][/{color}] {msg}")
        if len(self._log_lines) > self._max_log:
            self._log_lines.pop(0)

    def _on_device_found(self, device: BluetoothDevice):
        icon = "📡" if device.device_type == DeviceType.BLE else "🔵"
        self._log(f"{icon} Found: [bold]{device.name}[/bold] ({device.address}) — {device.device_type.value}", "success")

    def _on_device_updated(self, device: BluetoothDevice):
        self._log(f"↺  Updated: {device.name} ({device.address})", "info")

    def _on_connection_event(self, event: ConnectionEvent):
        icons = {"connect": "🟢", "disconnect": "🔴", "pair": "🔑",
                 "auth_fail": "⚠️", "link_key": "🔐"}
        icon = icons.get(event.event_type, "•")
        self._log(f"{icon} {event.event_type.upper()}: {event.device_name} ({event.device_address})", "info")

    def _on_anomaly_detected(self, event: ConnectionEvent):
        self._log(f"🚨 ANOMALY: {event.anomaly_reason} — {event.device_name}", "anomaly")

    def _on_scan_complete(self, devices):
        self._log(f"✅ Scan complete. {len(devices)} device(s) found.", "success")

    def _build_device_table(self) -> Table:
        table = Table(
            title="[bold cyan]Discovered Bluetooth Devices[/bold cyan]",
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold magenta",
            show_lines=True
        )
        table.add_column("Address", style="dim", width=18)
        table.add_column("Name", min_width=20)
        table.add_column("Type", width=10)
        table.add_column("RSSI", width=8, justify="right")
        table.add_column("Pairing", min_width=14)
        table.add_column("Security", width=9)
        table.add_column("Manufacturer", min_width=14)
        table.add_column("Risks", width=5, justify="center")

        security_colors = {
            "NONE": "red",
            "LOW": "yellow",
            "MEDIUM": "orange1",
            "HIGH": "green"
        }

        type_colors = {
            DeviceType.BLE: "bright_blue",
            DeviceType.CLASSIC: "blue",
            DeviceType.DUAL: "cyan",
            DeviceType.UNKNOWN: "dim"
        }

        for dev in self.engine.devices.values():
            sec_color = security_colors.get(dev.security_level.label, "white")
            type_color = type_colors.get(dev.device_type, "white")
            rssi_str = f"{dev.rssi} dBm" if dev.rssi != 0 else "N/A"

            pairing_short = {
                PairingMode.JUST_WORKS: "[red]Just Works[/red]",
                PairingMode.NUMERIC_COMPARISON: "[green]Numeric Cmp[/green]",
                PairingMode.PASSKEY_ENTRY: "[green]Passkey[/green]",
                PairingMode.LEGACY_PIN: "[yellow]Legacy PIN[/yellow]",
                PairingMode.OUT_OF_BAND: "[cyan]OOB[/cyan]",
                PairingMode.UNKNOWN: "[dim]Unknown[/dim]",
            }.get(dev.pairing_mode, dev.pairing_mode.value)

            risk_count = len(dev.security_risks)
            risk_str = f"[red]{risk_count}[/red]" if risk_count > 0 else "[green]0[/green]"

            table.add_row(
                dev.address,
                f"[bold]{dev.name}[/bold]",
                f"[{type_color}]{dev.device_type.value.replace('Bluetooth ', '')}[/{type_color}]",
                rssi_str,
                pairing_short,
                f"[{sec_color}]{dev.security_level.label}[/{sec_color}]",
                dev.manufacturer[:18],
                risk_str
            )

        if not self.engine.devices:
            table.add_row(
                "[dim]—[/dim]", "[dim]No devices discovered yet[/dim]",
                "", "", "", "", "", ""
            )
        return table

    def _build_event_panel(self) -> Panel:
        content = "\n".join(self._log_lines[-15:]) if self._log_lines else "[dim]Waiting for events...[/dim]"
        return Panel(
            content,
            title="[bold yellow]📡 Live Event Log[/bold yellow]",
            border_style="yellow",
            padding=(0, 1)
        )

    def _build_stats_panel(self) -> Panel:
        devices = self.engine.devices
        total = len(devices)
        ble = sum(1 for d in devices.values() if d.device_type == DeviceType.BLE)
        classic = sum(1 for d in devices.values() if d.device_type == DeviceType.CLASSIC)
        dual = sum(1 for d in devices.values() if d.device_type == DeviceType.DUAL)
        risky = sum(1 for d in devices.values() if d.security_level.label in ("NONE", "LOW"))
        events = len(self.engine.connection_events)
        anomalies = sum(1 for e in self.engine.connection_events if e.is_anomalous)

        grid = Table.grid(padding=1)
        grid.add_column(justify="right", style="dim")
        grid.add_column(style="bold")
        grid.add_column(justify="right", style="dim")
        grid.add_column(style="bold")

        grid.add_row("Total Devices:", f"[cyan]{total}[/cyan]",
                     "Events:", f"[cyan]{events}[/cyan]")
        grid.add_row("Classic BT:", f"[blue]{classic}[/blue]",
                     "Anomalies:", f"[red]{anomalies}[/red]" if anomalies else f"[green]{anomalies}[/green]")
        grid.add_row("BLE:", f"[bright_blue]{ble}[/bright_blue]",
                     "High-Risk:", f"[red]{risky}[/red]" if risky else f"[green]{risky}[/green]")
        grid.add_row("Dual Mode:", f"[cyan]{dual}[/cyan]",
                     "Interface:", f"[green]{self.engine.interface}[/green]")

        return Panel(grid, title="[bold green]📊 Statistics[/bold green]",
                     border_style="green", padding=(0, 1))

    def _build_header(self) -> Panel:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = "[green]● SCANNING[/green]" if self.engine.is_scanning else \
                 "[yellow]● MONITORING[/yellow]" if self.engine.is_monitoring else \
                 "[dim]○ IDLE[/dim]"
        header_text = Text()
        header_text.append("  🔵 BLUETOOTH SPY", style="bold cyan")
        header_text.append("  |  ", style="dim")
        header_text.append("Made by Monish Paramasivam", style="bold magenta")
        header_text.append("  |  ", style="dim")
        header_text.append(status)
        header_text.append(f"  |  {ts}", style="dim")
        return Panel(header_text, border_style="cyan", padding=(0, 1))

    def _build_risk_panel(self) -> Panel:
        risks = []
        for dev in self.engine.devices.values():
            for risk in dev.security_risks:
                risks.append((dev.name, dev.address, risk))

        if not risks:
            content = "[green]✓ No security risks detected in current scan[/green]"
        else:
            lines = []
            for name, addr, risk in risks[:8]:
                sev_color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}.get(risk["severity"], "white")
                lines.append(
                    f"[{sev_color}][{risk['severity']}][/{sev_color}] "
                    f"[bold]{risk['title']}[/bold] — {name}\n"
                    f"       [dim]{risk['description']}[/dim]"
                )
            content = "\n".join(lines)

        return Panel(content, title="[bold red]🚨 Security Risks[/bold red]",
                     border_style="red", padding=(0, 1))

    def _show_menu(self):
        """Show interactive command menu."""
        self.console.print("\n[bold cyan]═══ MAIN MENU ═══[/bold cyan]")
        options = [
            ("1", "🔍 Start Device Discovery (Classic + BLE)"),
            ("2", "📡 Start Connection Monitor"),
            ("3", "🔬 Analyze Security Risks"),
            ("4", "📊 View Device Details"),
            ("5", "📄 Generate Security Report"),
            ("6", "📚 Educational Mode — Bluetooth Security Concepts"),
            ("7", "🌐 Visualize Device Relationships"),
            ("q", "❌ Quit"),
        ]
        for key, label in options:
            self.console.print(f"  [{key}] {label}")

        choice = Prompt.ask("\n[cyan]Select option[/cyan]", choices=["1","2","3","4","5","6","7","q"])
        return choice

    def _run_discovery_interactive(self):
        duration = int(Prompt.ask("[cyan]Scan duration (seconds)[/cyan]", default="30"))
        self.console.print(f"\n[cyan]Starting {duration}s discovery scan...[/cyan]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.percentage:>3.0f}%"),
        ) as progress:
            task = progress.add_task("[cyan]Scanning for Bluetooth devices...", total=duration)
            scan_thread = threading.Thread(
                target=self.engine.run_discovery,
                kwargs={"duration": duration},
                daemon=True
            )
            scan_thread.start()
            for _ in range(duration):
                time.sleep(1)
                progress.advance(task, 1)
                if not scan_thread.is_alive():
                    break

        self.console.print(f"\n[green]Discovery complete! Found {len(self.engine.devices)} device(s)[/green]")
        self.console.print(self._build_device_table())

    def _run_monitor_interactive(self):
        duration = int(Prompt.ask("[yellow]Monitor duration (0 = continuous)[/yellow]", default="30"))
        self.console.print("\n[yellow]Starting connection event monitor... (Ctrl+C to stop)[/yellow]\n")

        def show_event(event: ConnectionEvent):
            icons = {"connect": "🟢", "disconnect": "🔴", "pair": "🔑",
                     "auth_fail": "⚠️ ", "link_key": "🔐"}
            icon = icons.get(event.event_type, "•")
            color = "red" if event.is_anomalous else "cyan"
            self.console.print(
                f"  {icon} [{color}]{event.event_type.upper():12}[/{color}] "
                f"{event.device_name:25} {event.device_address}"
            )
            if event.is_anomalous:
                self.console.print(f"     [bold red]⚡ ANOMALY: {event.anomaly_reason}[/bold red]")

        monitor_thread = threading.Thread(
            target=self.engine.run_monitor,
            kwargs={"duration": duration, "callback": show_event},
            daemon=True
        )
        monitor_thread.start()
        try:
            monitor_thread.join(timeout=duration if duration > 0 else None)
        except KeyboardInterrupt:
            self.engine.stop_monitor()

    def _show_analysis(self):
        """Show security analysis results."""
        analysis = self.engine.run_analysis()
        self.console.print(Panel(
            f"[bold]Total Devices:[/bold] {analysis['total_devices']}\n"
            f"[bold]Security Risks:[/bold] [red]{len(analysis['security_risks'])}[/red]\n"
            f"[bold]Anomalies:[/bold] [red]{len(analysis['anomalies'])}[/red]\n"
            f"[bold]Pairing Modes:[/bold]\n" +
            "\n".join(f"  • {k}: {v}" for k, v in analysis['pairing_modes'].items()),
            title="[bold cyan]Security Analysis[/bold cyan]",
            border_style="cyan"
        ))

        if analysis['recommendations']:
            rec_tree = Tree("🛡️  [bold green]Recommendations[/bold green]")
            for rec in analysis['recommendations']:
                rec_tree.add(f"[green]→[/green] {rec}")
            self.console.print(rec_tree)

    def _show_device_details(self):
        """Interactive device detail viewer."""
        if not self.engine.devices:
            self.console.print("[yellow]No devices to show. Run a scan first.[/yellow]")
            return

        addrs = list(self.engine.devices.keys())
        self.console.print("\n[cyan]Available devices:[/cyan]")
        for i, addr in enumerate(addrs):
            dev = self.engine.devices[addr]
            self.console.print(f"  [{i+1}] {dev.name} ({addr})")

        choice = Prompt.ask("Select device", choices=[str(i+1) for i in range(len(addrs))])
        dev = self.engine.devices[addrs[int(choice)-1]]

        detail_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        detail_table.add_column("Field", style="dim")
        detail_table.add_column("Value", style="bold")

        detail_table.add_row("Address", dev.address)
        detail_table.add_row("Name", dev.name)
        detail_table.add_row("Type", dev.device_type.value)
        detail_table.add_row("Manufacturer", dev.manufacturer)
        detail_table.add_row("LMP Version", dev.lmp_version or "N/A")
        detail_table.add_row("Pairing Mode", dev.pairing_mode.value)
        detail_table.add_row("Security Level", dev.security_level.label)
        detail_table.add_row("Paired", "Yes" if dev.is_paired else "No")
        detail_table.add_row("Services", ", ".join(dev.services) if dev.services else "None discovered")
        detail_table.add_row("First Seen", dev.first_seen)
        detail_table.add_row("Last Seen", dev.last_seen)

        self.console.print(Panel(detail_table, title=f"[bold cyan]Device: {dev.name}[/bold cyan]",
                                 border_style="cyan"))

        if dev.security_risks:
            risk_tree = Tree(f"🚨 [bold red]Security Risks ({len(dev.security_risks)})[/bold red]")
            for risk in dev.security_risks:
                branch = risk_tree.add(f"[{'red' if risk['severity']=='HIGH' else 'yellow'}][{risk['severity']}][/{'red' if risk['severity']=='HIGH' else 'yellow'}] {risk['title']}")
                branch.add(f"[dim]{risk['description']}[/dim]")
                branch.add(f"[green]→ {risk['recommendation']}[/green]")
            self.console.print(risk_tree)

    def _generate_report_interactive(self):
        """Generate and save a security report."""
        self.console.print("\n[cyan]Generating security report...[/cyan]")
        filename = self.engine.generate_report()
        self.console.print(f"[green]✓ Report saved to:[/green] {filename}")
        self.console.print(Panel(
            f"[bold]Report Contents:[/bold]\n"
            f"  • {len(self.engine.devices)} device profiles\n"
            f"  • {len(self.engine.connection_events)} connection events\n"
            f"  • Security risk assessments\n"
            f"  • Recommendations\n"
            f"  • Full metadata\n\n"
            f"[dim]View with: cat {filename} | python3 -m json.tool[/dim]",
            title="[bold green]Report Generated[/bold green]",
            border_style="green"
        ))

    def _visualize_relationships(self):
        """ASCII visualization of device relationships."""
        from modules.visualizer import DeviceVisualizer
        viz = DeviceVisualizer(self.engine)
        viz.print_ascii_graph(self.console)

    def run(self):
        """Run the interactive dashboard."""
        if not HAS_RICH:
            print("[ERROR] 'rich' library not installed. Run: pip3 install rich")
            return

        self.console.print(self._build_header())

        while self.running:
            try:
                choice = self._show_menu()

                if choice == "1":
                    self._run_discovery_interactive()
                elif choice == "2":
                    self._run_monitor_interactive()
                elif choice == "3":
                    self._show_analysis()
                elif choice == "4":
                    self._show_device_details()
                elif choice == "5":
                    self._generate_report_interactive()
                elif choice == "6":
                    from modules.education import BluetoothEducation
                    edu = BluetoothEducation()
                    edu.run_interactive_tutorial(self.console)
                elif choice == "7":
                    self._visualize_relationships()
                elif choice == "q":
                    if Confirm.ask("[yellow]Save report before exiting?[/yellow]"):
                        self._generate_report_interactive()
                    self.console.print(
                        "\n[bold cyan]Bluetooth Spy stopped.[/bold cyan]\n"
                        "[dim]Made by Monish Paramasivam[/dim]\n"
                    )
                    self.running = False

            except KeyboardInterrupt:
                self.console.print("\n[yellow]Use 'q' to quit gracefully.[/yellow]")
