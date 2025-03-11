#!/usr/bin/env python3
"""
Network scanner module for discovering devices on the network.
Uses nmap for scanning when available.
"""

import ipaddress
import os
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple, Union

import netifaces

from rich.progress import Progress, SpinnerColumn, TextColumn

from scanner_modules.constants import NMAP_IOT_SCRIPTS, SCAN_RESULTS_PATH
from scanner_modules.utils import (
    console,
    is_likely_iot,
    guess_device_type,
    guess_service,
)
from scanner_modules.virtual_device_manager import VirtualDeviceManager


class NetworkScanner:
    """Network scanner for discovering devices on the local network using nmap."""

    def __init__(
        self, interface=None, virtual_mode=False, aggressive=False, target=None
    ):
        """Initialize the network scanner."""
        self.interface = interface
        self.virtual_mode = virtual_mode
        self.aggressive = aggressive
        self.target = target
        self.virtual_device_manager = VirtualDeviceManager()

    def get_interface(self) -> str:
        """Get the network interface to use for scanning."""
        if self.interface:
            return self.interface

        # Try to determine default interface
        gateways = netifaces.gateways()
        if "default" in gateways and netifaces.AF_INET in gateways["default"]:
            self.interface = gateways["default"][netifaces.AF_INET][1]
            return self.interface

        # If no default interface found, list available interfaces and ask user
        interfaces = netifaces.interfaces()
        # Filter out loopback
        interfaces = [i for i in interfaces if i != "lo" and not i.startswith("vir")]

        if not interfaces:
            console.print("[bold red]No suitable network interfaces found[/bold red]")
            sys.exit(1)

        if len(interfaces) == 1:
            self.interface = interfaces[0]
            return self.interface

        # Let user choose
        console.print("[bold]Available network interfaces:[/bold]")
        for i, interface in enumerate(interfaces, 1):
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                ip = addrs[netifaces.AF_INET][0]["addr"]
                console.print(f"{i}. {interface} ({ip})")
            else:
                console.print(f"{i}. {interface}")

        while True:
            choice = console.input("[bold]Enter interface number: [/bold]")
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(interfaces):
                    self.interface = interfaces[idx]
                    return self.interface
            except ValueError:
                pass
            console.print("[bold red]Invalid choice. Try again.[/bold red]")

    def get_network_range(self) -> str:
        """Get the network range to scan based on the interface's IP and subnet mask or target."""
        # If target is specified, use it
        if self.target:
            # Check if target is valid IP or network range
            try:
                # Check if it's a CIDR range
                if "/" in self.target:
                    network = ipaddress.IPv4Network(self.target, strict=False)
                    return str(network)
                # Check if it's a single IP
                else:
                    ip = ipaddress.IPv4Address(self.target)
                    return f"{ip}/32"  # Single IP CIDR notation
            except ValueError:
                console.print(f"[bold red]Invalid target: {self.target}[/bold red]")
                sys.exit(1)

        # For virtual mode, use a default range
        if self.virtual_mode:
            return "192.168.1.0/24"  # Default for virtual mode

        # Otherwise, determine from interface
        interface = self.get_interface()
        addrs = netifaces.ifaddresses(interface)

        if netifaces.AF_INET not in addrs:
            console.print(
                f"[bold red]Interface {interface} has no IPv4 address[/bold red]"
            )
            sys.exit(1)

        ip = addrs[netifaces.AF_INET][0]["addr"]
        netmask = addrs[netifaces.AF_INET][0]["netmask"]

        # Convert IP and netmask to network address with CIDR
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        return str(network)

    def scan_network(self) -> List[Dict]:
        """Scan the network and return found devices."""
        if self.virtual_mode:
            return self._scan_virtual_network()

        # Try nmap first, fallback to basic scanning if not available
        try:
            return self._scan_with_nmap()
        except Exception as e:
            console.print(f"[bold yellow]Error during nmap scan: {e}[/bold yellow]")
            console.print("[yellow]Falling back to basic scanning method...[/yellow]")
            return self._scan_fallback()

    def _scan_with_nmap(self) -> List[Dict]:
        """Scan the network using nmap for better device fingerprinting."""
        network_range = self.get_network_range()
        console.print(f"[bold]Scanning network: {network_range}[/bold]")

        # Create unique output file for this scan
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(SCAN_RESULTS_PATH, f"nmap_scan_{timestamp}")

        # Ensure the directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        # Build nmap command
        nmap_cmd = ["nmap", "-sS"]  # SYN scan

        # Add device discovery options
        nmap_cmd.extend(["-PS22,80,443,8080", "-PA21,23,80,443,8080"])

        # Add OS detection and service version detection
        if self.aggressive:
            nmap_cmd.extend(["-A", "-T4"])
        else:
            nmap_cmd.extend(["-sV", "-O", "--osscan-limit", "-T3"])

        # Add output formatting
        nmap_cmd.extend(["-oX", f"{output_file}.xml", "-oN", f"{output_file}.txt"])

        # Add common IoT ports
        nmap_cmd.append("--top-ports")
        nmap_cmd.append("100" if self.aggressive else "30")

        # Add scripts for IoT device detection
        if self.aggressive:
            scripts = ",".join(NMAP_IOT_SCRIPTS)
            nmap_cmd.extend(["--script", scripts])
        else:
            # Use a more limited set of scripts for faster scanning
            basic_scripts = ",".join(["banner", "http-title", "upnp-info", "hnap-info"])
            nmap_cmd.extend(["--script", basic_scripts])

        # Add target
        nmap_cmd.append(network_range)

        console.print(f"[dim]Running: {' '.join(nmap_cmd)}[/dim]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("[green]Scanning network with nmap...", total=None)

            try:
                # Run nmap
                process = subprocess.Popen(
                    nmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )

                # Wait for nmap to complete
                while process.poll() is None:
                    time.sleep(1)

                # Check if nmap completed successfully
                if process.returncode != 0:
                    stderr = process.stderr.read()
                    console.print(f"[bold red]Nmap error: {stderr}[/bold red]")
                    progress.update(
                        task, description="[red]Scan failed", completed=True
                    )
                    return self._scan_fallback()

                progress.update(
                    task,
                    description="[green]Processing nmap results...",
                    completed=False,
                )

                # Parse nmap XML output
                devices = self._parse_nmap_output(f"{output_file}.xml")

                progress.update(
                    task, description="[green]Scan complete", completed=True
                )

                console.print(
                    f"[green]Scan results saved to: {output_file}.xml and {output_file}.txt[/green]"
                )
                return devices

            except Exception as e:
                console.print(f"[bold red]Error during nmap scan: {e}[/bold red]")
                progress.update(task, description="[red]Scan failed", completed=True)
                return self._scan_fallback()

    def _parse_nmap_output(self, xml_file: str) -> List[Dict]:
        """Parse nmap XML output and extract device information."""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            devices = []

            # Process each host in the nmap output
            for host in root.findall(".//host"):
                # Skip hosts that are not up
                status = host.find("status")
                if status is None or status.get("state") != "up":
                    continue

                device = {
                    "ip": "",
                    "mac": "",
                    "name": "Unknown",
                    "manufacturer": "Unknown",
                    "type": "unknown",
                    "is_iot": False,
                    "os": "",
                    "open_ports": [],
                    "services": [],
                }

                # Get IP address
                for addr in host.findall(".//address"):
                    if addr.get("addrtype") == "ipv4":
                        device["ip"] = addr.get("addr")
                    elif addr.get("addrtype") == "mac":
                        device["mac"] = addr.get("addr")
                        # Get vendor if available
                        if addr.get("vendor"):
                            device["manufacturer"] = addr.get("vendor")

                # Get hostname
                hostnames = host.findall(".//hostname")
                if hostnames:
                    for hostname in hostnames:
                        if hostname.get("type") == "PTR":
                            device["name"] = hostname.get("name")
                            break

                # Get OS information
                os_elements = host.findall(".//osclass")
                if os_elements:
                    os_match = max(
                        os_elements, key=lambda x: float(x.get("accuracy", "0"))
                    )
                    device["os"] = (
                        f"{os_match.get('vendor', '')} {os_match.get('osfamily', '')} {os_match.get('osgen', '')}"
                    )
                    device["os"] = device["os"].strip()

                # Get open ports and services
                for port in host.findall(".//port"):
                    if port.find("state").get("state") == "open":
                        port_num = int(port.get("portid"))
                        service_elem = port.find("service")

                        service = {
                            "port": port_num,
                            "service": "unknown",
                            "state": "open",
                        }

                        if service_elem is not None:
                            service["service"] = service_elem.get("name", "unknown")
                            service["product"] = service_elem.get("product", "")
                            service["version"] = service_elem.get("version", "")

                            # Look for script output for this port
                            script_outputs = []
                            for script in port.findall(".//script"):
                                script_outputs.append(
                                    {
                                        "name": script.get("id"),
                                        "output": script.get("output"),
                                    }
                                )

                            if script_outputs:
                                service["script_output"] = script_outputs

                        device["open_ports"].append(service)
                        device["services"].append(service["service"])

                # Determine if it's an IoT device based on ports, services, and hostname
                device["is_iot"] = is_likely_iot(device)
                if device["is_iot"]:
                    device["type"] = guess_device_type(device)

                devices.append(device)

            return devices

        except Exception as e:
            console.print(f"[bold red]Error parsing nmap output: {e}[/bold red]")
            return []

    def _scan_fallback(self) -> List[Dict]:
        """Fallback scanning method when nmap is not available or fails."""
        network_range = self.get_network_range()
        console.print(
            f"[bold]Scanning network using fallback method: {network_range}[/bold]"
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("[green]Scanning network...", total=None)

            # Use ping sweep to discover devices
            devices = []

            try:
                # Get all hosts in the network
                network = ipaddress.IPv4Network(network_range)

                # For a /24 network or smaller, scan all hosts
                if network.prefixlen >= 24:
                    hosts = list(network.hosts())
                else:
                    # For larger networks, limit to first 256 hosts
                    hosts = list(network.hosts())[:256]
                    console.print(
                        "[yellow]Network is large, limiting scan to first 256 hosts[/yellow]"
                    )

                progress.update(task, total=len(hosts))

                for i, host in enumerate(hosts):
                    ip = str(host)

                    # Try to ping the host
                    try:
                        response = subprocess.run(
                            ["ping", "-c", "1", "-W", "1", ip],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=1,
                        )

                        if response.returncode == 0:
                            # Host is up, try to get hostname
                            try:
                                hostname = socket.getfqdn(ip)
                                if hostname == ip:  # No hostname resolved
                                    hostname = "Unknown"
                            except socket.error:
                                hostname = "Unknown"

                            # Try to get MAC address (Linux only)
                            mac = "Unknown"
                            manufacturer = "Unknown"

                            try:
                                # Try using arp command
                                arp_output = subprocess.check_output(
                                    ["arp", "-n", ip],
                                    stderr=subprocess.DEVNULL,
                                    text=True,
                                )

                                # Parse arp output for MAC address
                                for line in arp_output.splitlines():
                                    if ip in line:
                                        parts = line.split()
                                        if len(parts) >= 3:
                                            mac = parts[2]
                                            break
                            except (subprocess.SubprocessError, IndexError):
                                pass

                            # Check common ports to guess if it's an IoT device
                            open_ports = []
                            for port in [80, 443, 8080, 23, 22]:
                                try:
                                    sock = socket.socket(
                                        socket.AF_INET, socket.SOCK_STREAM
                                    )
                                    sock.settimeout(0.5)
                                    result = sock.connect_ex((ip, port))
                                    if result == 0:
                                        service = guess_service(port)
                                        open_ports.append(
                                            {
                                                "port": port,
                                                "service": service,
                                                "state": "open",
                                            }
                                        )
                                    sock.close()
                                except socket.error:
                                    pass

                            device = {
                                "ip": ip,
                                "mac": mac,
                                "name": hostname,
                                "manufacturer": manufacturer,
                                "open_ports": open_ports,
                                "services": [p["service"] for p in open_ports],
                            }

                            # Determine if it's likely an IoT device
                            device["is_iot"] = is_likely_iot(device)
                            if device["is_iot"]:
                                device["type"] = guess_device_type(device)
                            else:
                                device["type"] = "unknown"

                            devices.append(device)

                    except (subprocess.SubprocessError, subprocess.TimeoutExpired):
                        pass

                    progress.update(task, advance=1)

                progress.update(
                    task, description="[green]Scan complete", completed=True
                )

            except Exception as e:
                console.print(f"[bold red]Error during fallback scan: {e}[/bold red]")
                progress.update(task, description="[red]Scan failed", completed=True)

            return devices

    def _scan_virtual_network(self) -> List[Dict]:
        """Simulate scanning a network with virtual devices."""
        network_range = self.get_network_range()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("[green]Simulating network scan...", total=None)

            # Simulate network latency
            time.sleep(2)

            # Generate virtual network
            devices = self.virtual_device_manager.simulate_network(network_range)

            progress.update(
                task, description="[green]Simulation complete", completed=True
            )

        return devices


# Add datetime import which was missing
from datetime import datetime
