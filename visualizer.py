#!/usr/bin/env python3
"""
Bluetooth Device Relationship Visualizer
Made by Monish Paramasivam
"""

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.tree import Tree
    from rich.table import Table
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from core.bluetooth_engine import BluetoothEngine, DeviceType, SecurityLevel


class DeviceVisualizer:
    """
    Visualizes Bluetooth device relationships and connection states.
    Made by Monish Paramasivam
    """

    def __init__(self, engine: BluetoothEngine):
        self.engine = engine

    def print_ascii_graph(self, console=None):
        if not console:
            console = Console()

        if not self.engine.devices:
            console.print("[yellow]No devices to visualize. Run a scan first.[/yellow]")
            return

        # Build tree rooted at our interface
        root_label = (
            f"[bold cyan]🖥️  THIS HOST[/bold cyan]\n"
            f"[dim]Interface: {self.engine.interface}[/dim]"
        )
        tree = Tree(root_label)

        # Group by type
        classic_branch = tree.add("[blue]📶 Bluetooth Classic[/blue]")
        ble_branch = tree.add("[bright_blue]📡 Bluetooth Low Energy[/bright_blue]")
        dual_branch = tree.add("[cyan]🔀 Dual Mode[/cyan]")
        unknown_branch = tree.add("[dim]❓ Unknown Type[/dim]")

        branches = {
            DeviceType.CLASSIC: classic_branch,
            DeviceType.BLE: ble_branch,
            DeviceType.DUAL: dual_branch,
            DeviceType.UNKNOWN: unknown_branch,
        }

        sec_icons = {
            "NONE": "🔴",
            "LOW": "🟡",
            "MEDIUM": "🟠",
            "HIGH": "🟢"
        }

        for dev in self.engine.devices.values():
            branch = branches.get(dev.device_type, unknown_branch)
            sec_icon = sec_icons.get(dev.security_level.label, "⚪")
            conn_icon = "🔗" if dev.is_connected else "  "
            paired_icon = "🔑" if dev.is_paired else "  "

            device_node = branch.add(
                f"{sec_icon} {conn_icon}{paired_icon} [bold]{dev.name}[/bold]\n"
                f"   [dim]{dev.address} | {dev.manufacturer}[/dim]\n"
                f"   [dim]Pairing: {dev.pairing_mode.value}[/dim]"
            )

            # Add services
            if dev.services:
                for svc in dev.services[:4]:
                    device_node.add(f"[dim cyan]⚙  {svc}[/dim cyan]")
                if len(dev.services) > 4:
                    device_node.add(f"[dim]... +{len(dev.services)-4} more[/dim]")

            # Add risks
            if dev.security_risks:
                for risk in dev.security_risks:
                    color = "red" if risk["severity"] == "HIGH" else "yellow"
                    device_node.add(f"[{color}]⚠ {risk['title']}[/{color}]")

        console.print(Panel(
            tree,
            title="[bold cyan]🗺️  Device Relationship Map[/bold cyan]",
            border_style="cyan",
            padding=(1, 2)
        ))

        # Legend
        legend = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        legend.add_column("Icon")
        legend.add_column("Meaning")
        legend.add_row("🔴 / 🟡 / 🟠 / 🟢", "Security level: None / Low / Medium / High")
        legend.add_row("🔗", "Currently connected")
        legend.add_row("🔑", "Previously paired")
        legend.add_row("⚠", "Active security risk")
        legend.add_row("⚙", "Available service/profile")

        console.print(Panel(legend, title="[dim]Legend[/dim]", border_style="dim"))

        # Connection event timeline
        if self.engine.connection_events:
            self._print_event_timeline(console)

    def _print_event_timeline(self, console):
        """Print a simple ASCII timeline of connection events."""
        events = self.engine.connection_events[-10:]
        timeline_table = Table(
            title="[bold yellow]Recent Connection Timeline[/bold yellow]",
            box=box.SIMPLE_HEAD,
            border_style="yellow"
        )
        timeline_table.add_column("Time", style="dim", width=12)
        timeline_table.add_column("Event", width=12)
        timeline_table.add_column("Device", min_width=20)
        timeline_table.add_column("Details")
        timeline_table.add_column("⚠", width=3)

        event_colors = {
            "connect": "green",
            "disconnect": "red",
            "pair": "cyan",
            "auth_fail": "bold red",
            "link_key": "yellow"
        }

        for ev in events:
            color = event_colors.get(ev.event_type, "white")
            time_str = ev.timestamp[11:19] if len(ev.timestamp) > 19 else ev.timestamp
            detail_str = str(ev.details.get("reason", ev.details.get("pairing_mode", "")))[:40]
            anomaly = "🚨" if ev.is_anomalous else ""
            timeline_table.add_row(
                time_str,
                f"[{color}]{ev.event_type.upper()}[/{color}]",
                ev.device_name[:22],
                detail_str,
                anomaly
            )

        console.print(timeline_table)
