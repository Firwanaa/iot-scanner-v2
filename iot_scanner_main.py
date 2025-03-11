#!/usr/bin/env python3
"""
Enhanced IoT Network Scanner (PoC)
A command-line tool to scan your home network for IoT devices and perform security analysis using nmap.
"""

import argparse
import ipaddress
import json
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Union

# Import our modules
from scanner_modules.network_scanner import NetworkScanner
from scanner_modules.security_analyzer import SecurityAnalyzer
from scanner_modules.virtual_device_manager import VirtualDeviceManager
from scanner_modules.utils import console, ensure_data_dirs, create_default_files
from scanner_modules.utils import check_nmap_installation, check_python_modules
from scanner_modules.constants import *

# Rich UI components
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box
from rich.text import Text


class IoTScanner:
    """Main application class for the IoT Scanner."""

    def __init__(self, args):
        self.args = args
        self.virtual_mode = args.virtual
        self.aggressive = args.aggressive
        self.target = args.target

        # Ensure data directories exist
        ensure_data_dirs()

        # Create default data files if needed
        create_default_files()

        # Create scanner components
        self.network_scanner = NetworkScanner(
            interface=args.interface,
            virtual_mode=self.virtual_mode,
            aggressive=self.aggressive,
            target=self.target,
        )

        self.security_analyzer = SecurityAnalyzer(
            virtual_mode=self.virtual_mode,
            aggressive=self.aggressive,
            credential_check=args.credential_check,
        )

        # Store scan results
        self.scan_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Define output file
        if args.output:
            self.scan_results_file = args.output
        else:
            self.scan_results_file = os.path.join(
                SCAN_RESULTS_PATH, f"scan_{self.scan_timestamp}.json"
            )

    def scan(self):
        """Perform a full scan of the network and analyze devices."""
        # Print welcome header
        self._print_header()

        # Check for required dependencies
        if not check_python_modules():
            return

        # Check for optional nmap installation
        if not self.virtual_mode and not check_nmap_installation():
            console.print(
                "[yellow]Proceeding with limited scanning capabilities (nmap not found)[/yellow]"
            )

        # Scan the network
        console.print("\n[bold blue]Phase 1: Network Discovery[/bold blue]")
        devices = self.network_scanner.scan_network()

        if not devices:
            console.print(
                "[bold red]No devices found. Check your network connection or try virtual mode.[/bold red]"
            )
            return

        # Count IoT devices
        iot_devices = [d for d in devices if d.get("is_iot", False)]
        console.print(
            f"[green]Found {len(devices)} devices on the network, {len(iot_devices)} identified as IoT devices[/green]"
        )

        # Filter for IoT devices if requested
        if self.args.iot_only:
            devices = iot_devices
            if not devices:
                console.print(
                    "[yellow]No IoT devices found. Try without --iot-only to scan all devices.[/yellow]"
                )
                return

        # Analyze security of devices
        console.print("\n[bold blue]Phase 2: Security Analysis[/bold blue]")
        analyzed_devices = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("[green]Analyzing devices...", total=len(devices))

            for device in devices:
                if device.get("is_iot", False) or not self.args.iot_only:
                    analyzed_device = self.security_analyzer.analyze_device(device)
                    analyzed_devices.append(analyzed_device)

                progress.update(task, advance=1)

        # Save scan results
        self._save_scan_results(analyzed_devices)

        # Display results
        self._display_results(analyzed_devices)

    def _save_scan_results(self, devices: List[Dict]):
        """Save scan results to a JSON file."""
        try:
            # Add scan metadata
            scan_data = {
                "timestamp": self.scan_timestamp,
                "network": self.network_scanner.get_network_range(),
                "interface": self.network_scanner.interface,
                "virtual_mode": self.virtual_mode,
                "aggressive_mode": self.aggressive,
                "devices": devices,
            }

            # Create the directory if it doesn't exist
            os.makedirs(os.path.dirname(self.scan_results_file), exist_ok=True)

            with open(self.scan_results_file, "w") as f:
                json.dump(scan_data, f, indent=2)

            console.print(
                f"\n[green]Scan results saved to: {self.scan_results_file}[/green]"
            )

        except Exception as e:
            console.print(f"[bold red]Error saving scan results: {e}[/bold red]")

    def _print_header(self):
        """Print the application header with adaptive size based on terminal width."""
        # Get terminal width
        terminal_width = (
            os.get_terminal_size().columns if hasattr(os, "get_terminal_size") else 80
        )

        # Create a scaled header based on terminal width
        if terminal_width >= 80:
            # Full header for wide terminals
            header_text = """
    ██╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
    ██║██╔═══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
    ██║██║   ██║   ██║       ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
    ██║██║   ██║   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
    ██║╚██████╔╝   ██║       ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
    ╚═╝ ╚═════╝    ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
    """
        elif terminal_width >= 60:
            # Medium-sized header
            header_text = """
    ██╗ ██████╗ ████████╗
    ██║██╔═══██╗╚══██╔══╝  ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
    ██║██║   ██║   ██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
    ██║██║   ██║   ██║     ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
    ██║╚██████╔╝   ██║     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
    ╚═╝ ╚═════╝    ╚═╝     
    """
        else:
            # Simple text header for narrow terminals
            header_text = "IoT SCANNER"

        # Create a panel with adaptive width
        width = min(terminal_width - 4, 100)  # Subtract some padding, max width of 100
        panel = Panel(
            Text(header_text, style="bold cyan"), width=width, border_style="cyan"
        )
        console.print(panel)

        # Add version number and scanner mode
        version = "v0.2"
        mode_text = "VIRTUAL MODE" if self.virtual_mode else "REAL SCAN MODE"
        scan_type = "AGGRESSIVE" if self.aggressive else "STANDARD"
        target_text = f"Target: {self.target}" if self.target else "Target: Auto-detect"

        subtitle = f"IoT Device Security Scanner {version} - Proof of Concept"
        subtitle_panel = Panel(
            Text(subtitle, style="bold green"),
            width=width,
            border_style="green",
        )
        console.print(subtitle_panel)

        # Print scan mode information
        mode_panel = Panel(
            Text(
                f"Mode: {mode_text} | Scan Type: {scan_type} | {target_text}",
                style="yellow",
            ),
            width=width,
            border_style="yellow",
        )
        console.print(mode_panel)

        # Show current time
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        console.print(f"[dim]Scan started at: {current_time}[/dim]")
        console.print("")

    def _display_results(self, devices: List[Dict]):
        """Display the scan results in a beautiful console output."""
        if not devices:
            console.print("[yellow]No devices found to display.[/yellow]")
            return

        # First, show summary
        total_devices = len(devices)
        iot_devices = sum(1 for d in devices if d.get("is_iot", False))
        vulnerable_devices = sum(
            1
            for d in devices
            if d.get("is_iot", False) and len(d.get("security_issues", []))
        )

        # Count total issues by severity
        total_issues = 0
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for device in devices:
            if device.get("is_iot", False):
                issues = device.get("security_issues", [])
                total_issues += len(issues)

                for issue in issues:
                    severity = issue.get("severity", "medium").lower()
                    if severity in severity_counts:
                        severity_counts[severity] += 1

        console.print("\n[bold cyan]Scan Summary[/bold cyan]")
        summary_table = Table(show_header=False, box=None)
        summary_table.add_column("Key", style="bold green")
        summary_table.add_column("Value")

        summary_table.add_row("Total Devices", str(total_devices))
        summary_table.add_row("IoT Devices", str(iot_devices))
        summary_table.add_row("Vulnerable IoT Devices", str(vulnerable_devices))
        summary_table.add_row("Total Security Issues", str(total_issues))
        summary_table.add_row(
            "Critical Issues", f"[bold red]{severity_counts['critical']}[/bold red]"
        )
        summary_table.add_row("High Issues", f"[red]{severity_counts['high']}[/red]")
        summary_table.add_row(
            "Medium Issues", f"[yellow]{severity_counts['medium']}[/yellow]"
        )
        summary_table.add_row("Low Issues", f"[green]{severity_counts['low']}[/green]")
        summary_table.add_row("Scan Time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        summary_table.add_row("Network", self.network_scanner.get_network_range())
        summary_table.add_row("Results File", self.scan_results_file)

        console.print(summary_table)
        console.print("")

        # Then, show devices table
        console.print("[bold cyan]Discovered Devices[/bold cyan]")

        devices_table = Table(show_header=True)
        devices_table.add_column("IP", style="dim")
        devices_table.add_column("Name", style="cyan")
        devices_table.add_column("Type", style="green")
        devices_table.add_column("Manufacturer", style="blue")
        devices_table.add_column("OS/Firmware", style="magenta")
        devices_table.add_column("Open Ports", style="cyan")
        devices_table.add_column("Security Score", style="yellow")
        devices_table.add_column("Issues", style="red")

        # Sort devices - IoT devices first, then by security score (lowest first)
        sorted_devices = sorted(
            devices,
            key=lambda d: (
                not d.get("is_iot", False),  # IoT devices first
                d.get("security_score", 100),  # Lower scores first
            ),
        )

        for device in sorted_devices:
            is_iot = device.get("is_iot", False)
            name = device.get("name", "Unknown")

            # Format device type
            device_type = device.get("type", "unknown")
            if device_type == "unknown":
                type_str = "Unknown"
            else:
                type_str = " ".join(
                    word.capitalize() for word in device_type.split("_")
                )

            # Format OS/Firmware
            os_info = device.get("os", "")
            firmware = device.get("firmware", "")
            if firmware:
                os_str = (
                    f"{os_info} (v{firmware})" if os_info else f"Firmware v{firmware}"
                )
            else:
                os_str = os_info or "Unknown"

            # Format open ports
            open_ports = device.get("open_ports", [])
            if open_ports:
                port_str = ", ".join(str(p.get("port", "?")) for p in open_ports[:3])
                if len(open_ports) > 3:
                    port_str += f" +{len(open_ports) - 3} more"
            else:
                port_str = "None"

            # Format security score with color
            security_score = device.get("security_score", 100)
            if security_score >= 90:
                score_str = f"[green]{security_score}[/green]"
            elif security_score >= 70:
                score_str = f"[yellow]{security_score}[/yellow]"
            else:
                score_str = f"[red]{security_score}[/red]"

            # Format issues count
            issues = device.get("security_issues", [])
            if issues:
                # Highlight critical/high issues
                critical_high_count = sum(
                    1
                    for i in issues
                    if i.get("severity", "").lower() in ["critical", "high"]
                )
                if critical_high_count > 0:
                    issues_str = f"[bold red]{len(issues)} ({critical_high_count} critical/high)[/bold red]"
                else:
                    issues_str = f"[red]{len(issues)}[/red]"
            else:
                issues_str = "[green]0[/green]"

            # Add row with appropriate styling
            row_style = ""
            if is_iot:
                name_styled = name
            else:
                name_styled = Text(name, style="dim")
                row_style = "dim"

            devices_table.add_row(
                device.get("ip", "Unknown"),
                name_styled,
                type_str,
                device.get("manufacturer", "Unknown"),
                os_str,
                port_str,
                score_str,
                issues_str,
                style=row_style,
            )

        console.print(devices_table)

        # Show detailed security information for vulnerable IoT devices
        if vulnerable_devices > 0:
            console.print("\n[bold cyan]Security Issues[/bold cyan]")

            for device in sorted_devices:
                issues = device.get("security_issues", [])
                if device.get("is_iot", False) and issues:
                    console.print(
                        f"\n[bold]{device.get('name', 'Unknown Device')} ({device.get('ip', 'Unknown IP')})[/bold]"
                    )

                    issues_table = Table(show_header=True)
                    issues_table.add_column("Type", style="yellow")
                    issues_table.add_column("Severity", style="red")
                    issues_table.add_column("Description")
                    issues_table.add_column("Recommendation", style="green")

                    # Sort issues by severity (critical first)
                    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                    sorted_issues = sorted(
                        issues,
                        key=lambda i: severity_order.get(
                            i.get("severity", "medium").lower(), 99
                        ),
                    )

                    for issue in sorted_issues:
                        severity = issue.get("severity", "medium")
                        severity_style = {
                            "critical": "bold red",
                            "high": "red",
                            "medium": "yellow",
                            "low": "green",
                        }.get(severity.lower(), "yellow")

                        issue_type = issue.get("type", "Unknown")
                        if issue_type == "known_vulnerability" and issue.get("cve"):
                            issue_type = f"{issue_type} ({issue.get('cve')})"
                        elif issue_type == "weak_credentials" and issue.get(
                            "credentials"
                        ):
                            creds = issue.get("credentials", {})
                            if creds:
                                creds_str = f"user: {creds.get('username', '')}, pass: {creds.get('password', '')}"
                                issue_type = f"{issue_type} ({creds_str})"

                        issues_table.add_row(
                            issue_type,
                            Text(severity.upper(), style=severity_style),
                            issue.get("description", "No description"),
                            issue.get("recommendation", "No recommendation"),
                        )

                    console.print(issues_table)

        # Show port information
        if self.args.show_ports:
            console.print("\n[bold cyan]Open Ports[/bold cyan]")

            for device in sorted_devices:
                open_ports = device.get("open_ports", [])
                if open_ports:
                    console.print(
                        f"\n[bold]{device.get('name', 'Unknown Device')} ({device.get('ip', 'Unknown IP')})[/bold]"
                    )

                    ports_table = Table(show_header=True)
                    ports_table.add_column("Port", style="cyan")
                    ports_table.add_column("Service", style="green")
                    ports_table.add_column("Product", style="blue")
                    ports_table.add_column("Version", style="yellow")
                    ports_table.add_column("State", style="red")

                    for port_info in open_ports:
                        ports_table.add_row(
                            str(port_info.get("port", "Unknown")),
                            port_info.get("service", "Unknown"),
                            port_info.get("product", ""),
                            port_info.get("version", ""),
                            port_info.get("state", "Unknown"),
                        )

                    console.print(ports_table)

        # Final notes and recommendations
        console.print("\n[bold green]Scan Complete![/bold green]")
        if self.virtual_mode:
            console.print(
                "[italic yellow]Note: This scan was performed in virtual mode with simulated devices.[/italic yellow]"
            )

        console.print("\n[bold cyan]Key Recommendations:[/bold cyan]")

        try:
            recommendations_table = Table(show_header=True, box=box.SIMPLE)
            recommendations_table.add_column("#", style="cyan", justify="right")
            recommendations_table.add_column("Recommendation", style="green")
            recommendations_table.add_column("Priority", style="yellow")

            recommendations = [
                (
                    "Update firmware on all IoT devices to ensure they have the latest security patches",
                    "High",
                ),
                ("Change default passwords on all devices", "Critical"),
                ("Isolate IoT devices on a separate network segment/VLAN", "High"),
                ("Disable unnecessary services (especially Telnet, UPnP)", "High"),
                ("Enable encryption where available (HTTPS, SSH, TLS)", "Medium"),
                (
                    "Implement network-level protection (firewall rules for IoT devices)",
                    "Medium",
                ),
                ("Consider using a dedicated IoT security gateway/hub", "Medium"),
                ("Perform regular security scans of your IoT network", "Medium"),
                ("Monitor device behavior for unusual activity", "Medium"),
                ("Check manufacturer websites for security bulletins", "Low"),
            ]

            for i, (recommendation, priority) in enumerate(recommendations, 1):
                priority_style = {
                    "Critical": "bold red",
                    "High": "red",
                    "Medium": "yellow",
                    "Low": "green",
                }.get(priority, "default")

                recommendations_table.add_row(
                    str(i), recommendation, Text(priority, style=priority_style)
                )

            console.print(recommendations_table)
        except Exception as e:
            console.print(
                f"[bold red]Error displaying recommendations table: {e}[/bold red]"
            )
            # Fallback to simple list if table formatting fails
            console.print("1. Update firmware on all IoT devices")
            console.print("2. Change default passwords on all devices")
            console.print("3. Isolate IoT devices on a separate network segment")
            console.print("4. Disable unnecessary services")
            console.print("5. Enable encryption where available")

        # Add additional detailed notes
        try:
            console.print("\n[bold cyan]Additional Notes:[/bold cyan]")
            console.print(
                "1. [bold]Default Credentials[/bold]: Many IoT devices ship with default credentials that are easily guessable or available in online databases."
            )
            console.print(
                "2. [bold]Unpatched Vulnerabilities[/bold]: Manufacturers may stop releasing updates for older models, leaving them vulnerable."
            )
            console.print(
                "3. [bold]Network Segmentation[/bold]: Consider creating a separate network (VLAN) for IoT devices to contain potential breaches."
            )
            console.print(
                "4. [bold]Encryption[/bold]: When possible, use encrypted protocols (HTTPS, SSH) instead of unencrypted alternatives (HTTP, Telnet)."
            )
            console.print(
                "5. [bold]Documentation[/bold]: Document your IoT devices, their firmware versions, and security settings for future reference."
            )
        except Exception as e:
            console.print(
                f"[bold red]Error displaying additional notes: {e}[/bold red]"
            )

        # Add reference to saved results
        console.print(
            f"\n[dim]Complete scan results saved to: {self.scan_results_file}[/dim]"
        )


def main():
    """Main entry point for the application."""
    parser = argparse.ArgumentParser(description="IoT Device Security Scanner")

    parser.add_argument(
        "-i", "--interface", type=str, help="Network interface to use for scanning"
    )
    parser.add_argument(
        "-v",
        "--virtual",
        action="store_true",
        help="Run in virtual mode with simulated devices",
    )
    parser.add_argument(
        "-a",
        "--aggressive",
        action="store_true",
        help="Use aggressive scanning (more thorough but slower and more detectable)",
    )
    parser.add_argument("--iot-only", action="store_true", help="Show only IoT devices")
    parser.add_argument(
        "--show-ports",
        action="store_true",
        help="Show detailed port information for each device",
    )
    parser.add_argument(
        "--target",
        type=str,
        help="Specify a target IP address or range (e.g., 192.168.1.100 or 192.168.1.0/24)",
    )
    parser.add_argument(
        "--credential-check",
        action="store_true",
        help="Attempt to check for default credentials (use with caution)",
    )
    parser.add_argument(
        "--output",
        type=str,
        help="Output file for scan results (defaults to automatic timestamp-based filename)",
    )
    parser.add_argument("--version", action="version", version="IoT Scanner v0.2 (PoC)")

    args = parser.parse_args()

    scanner = IoTScanner(args)

    try:
        scanner.scan()
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan interrupted by user[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Error: {e}[/bold red]")
        if "--debug" in sys.argv:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
