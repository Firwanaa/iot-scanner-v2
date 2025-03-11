#!/usr/bin/env python3
"""
Virtual device manager for the IoT scanner.
Manages simulated IoT devices for testing without scanning a real network.
"""

import json
import os
import random
import ipaddress
from typing import Dict, List, Optional

from scanner_modules.constants import VIRTUAL_DEVICES_PATH, COMMON_IOT_PORTS
from scanner_modules.utils import console, guess_service


class VirtualDeviceManager:
    """Manages virtual IoT devices for testing."""

    def __init__(self):
        """Initialize the virtual device manager."""
        self.virtual_devices = []
        self.load_devices()

    def load_devices(self) -> None:
        """Load virtual devices from configuration file."""
        try:
            if os.path.exists(VIRTUAL_DEVICES_PATH):
                with open(VIRTUAL_DEVICES_PATH, "r") as f:
                    self.virtual_devices = json.load(f)
                    console.print(
                        f"[green]Loaded {len(self.virtual_devices)} virtual devices[/green]"
                    )
            else:
                console.print(
                    "[yellow]Virtual devices configuration not found. Using default devices.[/yellow]"
                )
                self._create_default_devices()
        except (FileNotFoundError, json.JSONDecodeError) as e:
            console.print(f"[bold red]Error loading virtual devices: {e}[/bold red]")
            self._create_default_devices()

    def get_devices(self) -> List[Dict]:
        """Return the list of virtual devices."""
        return self.virtual_devices

    def get_device_by_mac(self, mac: str) -> Optional[Dict]:
        """Return a virtual device by MAC address."""
        if not mac:
            return None

        for device in self.virtual_devices:
            if device.get("mac", "").lower() == mac.lower():
                return device
        return None

    def update_device_ip(self, mac: str, ip: str) -> bool:
        """Update IP address of a virtual device."""
        if not mac:
            return False

        for device in self.virtual_devices:
            if device.get("mac", "").lower() == mac.lower():
                device["ip"] = ip
                return True
        return False

    def _create_default_devices(self) -> None:
        """Create default virtual devices if none exist."""
        self.virtual_devices = [
            {
                "name": "Virtual Smart Bulb",
                "type": "smart_light",
                "manufacturer": "Philips",
                "model": "Hue White",
                "mac": "AA:BB:CC:00:11:22",
                "port": 8001,
                "os": "Linux-based Philips Firmware",
                "services": ["http", "mdns", "ssdp"],
                "vulnerabilities": [
                    "weak_password",
                    "telnet_enabled",
                    "CVE-2022-67890",
                ],
                "firmware": "1.2.3",
                "web_interface": True,
                "login_path": "/login.html",
                "default_credentials": {"username": "admin", "password": "admin"},
            },
            {
                "name": "Virtual Security Camera",
                "type": "smart_camera",
                "manufacturer": "Wyze",
                "model": "Cam v3",
                "mac": "AA:BB:CC:00:11:33",
                "port": 8002,
                "os": "Linux-based RTSP Server",
                "services": ["rtsp", "http", "upnp"],
                "vulnerabilities": [
                    "default_password",
                    "CVE-2021-12345",
                    "CVE-2019-12780",
                ],
                "firmware": "4.5.6",
                "web_interface": True,
                "login_path": "/cgi-bin/login.cgi",
                "default_credentials": {"username": "admin", "password": "admin1234"},
            },
            {
                "name": "Virtual Smart Speaker",
                "type": "smart_speaker",
                "manufacturer": "Amazon",
                "model": "Echo Dot",
                "mac": "AA:BB:CC:00:11:44",
                "port": 8003,
                "os": "Fire OS",
                "services": ["http", "bluetooth", "upnp", "mdns"],
                "vulnerabilities": ["CVE-2019-15361"],
                "firmware": "7.8.9",
                "web_interface": False,
                "login_path": "",
                "default_credentials": {},
            },
            {
                "name": "Virtual Smart Thermostat",
                "type": "smart_thermostat",
                "manufacturer": "Nest",
                "model": "Learning Thermostat",
                "mac": "AA:BB:CC:00:11:55",
                "port": 8004,
                "os": "Linux-based Nest OS",
                "services": ["http", "mqtt", "mdns"],
                "vulnerabilities": ["weak_encryption", "CVE-2022-11111"],
                "firmware": "2.3.4",
                "web_interface": True,
                "login_path": "/",
                "default_credentials": {"username": "user", "password": "nest123"},
            },
            {
                "name": "Virtual Smart Lock",
                "type": "smart_lock",
                "manufacturer": "Yale",
                "model": "Assure Lock",
                "mac": "AA:BB:CC:00:11:66",
                "port": 8005,
                "os": "Proprietary Embedded OS",
                "services": ["bluetooth", "zigbee"],
                "vulnerabilities": [],
                "firmware": "5.6.7",
                "web_interface": False,
                "login_path": "",
                "default_credentials": {},
            },
            {
                "name": "Virtual Router",
                "type": "router",
                "manufacturer": "D-Link",
                "model": "DIR-865L",
                "mac": "AA:BB:CC:00:11:77",
                "port": 8006,
                "os": "Linux-based Router OS",
                "services": ["http", "https", "dns", "dhcp", "telnet", "ssh"],
                "vulnerabilities": [
                    "default_password",
                    "telnet_enabled",
                    "CVE-2020-28347",
                ],
                "firmware": "1.0.8",
                "web_interface": True,
                "login_path": "/login.html",
                "default_credentials": {"username": "admin", "password": "password"},
            },
        ]

        console.print(
            f"[green]Created {len(self.virtual_devices)} virtual devices[/green]"
        )

        # Save the devices to file
        try:
            os.makedirs(os.path.dirname(VIRTUAL_DEVICES_PATH), exist_ok=True)
            with open(VIRTUAL_DEVICES_PATH, "w") as f:
                json.dump(self.virtual_devices, f, indent=4)
            console.print(
                f"[green]Saved virtual devices to {VIRTUAL_DEVICES_PATH}[/green]"
            )
        except Exception as e:
            console.print(f"[bold red]Error saving virtual devices: {e}[/bold red]")

    def simulate_network(self, network_range: str) -> List[Dict]:
        """Simulate a network with virtual IoT devices and non-IoT devices."""
        # Create network range and assign IPs
        network = ipaddress.IPv4Network(network_range)

        # Start from .100 to avoid conflicts with real devices
        start_ip = 100
        devices = []

        # Add non-IoT devices for realism
        non_iot_count = random.randint(2, 5)
        for i in range(non_iot_count):
            ip = str(network.network_address + start_ip + i)
            mac = "".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
            mac = ":".join([mac[i : i + 2] for i in range(0, 12, 2)])

            device_type = random.choice(["pc", "smartphone", "laptop"])
            manufacturer = random.choice(
                ["Dell", "HP", "Apple", "Lenovo", "Samsung", "Asus"]
            )

            # Add simulated OS info
            os_info = {
                "pc": ["Windows 10", "Windows 11", "Ubuntu 22.04", "macOS 13"],
                "smartphone": ["Android 13", "iOS 16", "iOS 17"],
                "laptop": ["Windows 11", "macOS 14", "Ubuntu 22.04"],
            }

            os_name = random.choice(os_info.get(device_type, ["Unknown"]))

            # Add some simulated open ports
            open_ports = []
            if device_type == "pc":
                # PCs often have file sharing, remote access
                possible_ports = [135, 139, 445, 3389]
                num_ports = random.randint(1, len(possible_ports))
                for port in random.sample(possible_ports, num_ports):
                    service = guess_service(port)
                    open_ports.append(
                        {"port": port, "service": service, "state": "open"}
                    )
            elif device_type == "smartphone":
                # Smartphones usually have fewer open ports
                if random.random() < 0.3:  # 30% chance to have any open ports
                    port = random.choice([5000, 8080])
                    service = guess_service(port)
                    open_ports.append(
                        {"port": port, "service": service, "state": "open"}
                    )
            elif device_type == "laptop":
                # Laptops similar to PCs
                possible_ports = [22, 445, 3389]
                num_ports = random.randint(0, len(possible_ports))
                for port in random.sample(possible_ports, num_ports):
                    service = guess_service(port)
                    open_ports.append(
                        {"port": port, "service": service, "state": "open"}
                    )

            devices.append(
                {
                    "ip": ip,
                    "mac": mac.lower(),
                    "name": f"{manufacturer} {device_type.capitalize()}",
                    "manufacturer": manufacturer,
                    "type": device_type,
                    "is_iot": False,
                    "os": os_name,
                    "open_ports": open_ports,
                    "services": [p["service"] for p in open_ports],
                }
            )

        # Add virtual IoT devices
        for i, device in enumerate(self.virtual_devices):
            ip = str(network.network_address + start_ip + non_iot_count + i)

            # Update the device with an IP address
            device_copy = device.copy()
            device_copy["ip"] = ip
            device_copy["is_iot"] = True

            # Simulate nmap port scan results
            open_ports = []

            if "services" in device:
                for service in device["services"]:
                    port = None

                    # Try to assign realistic ports to common services
                    if service in ["http", "https", "ssh", "telnet", "rtsp", "mqtt"]:
                        for p, s in COMMON_IOT_PORTS.items():
                            if s == service:
                                port = p
                                break

                    # If no standard port, assign one from common ranges
                    if port is None:
                        if service == "http":
                            port = random.choice([80, 8080, 8081])
                        elif service == "https":
                            port = random.choice([443, 8443])
                        else:
                            # Assign a random port from common ranges
                            port = random.randint(7000, 9000)

                    open_ports.append(
                        {
                            "port": port,
                            "service": service,
                            "state": "open",
                            "product": f"{device['manufacturer']} {device.get('model', 'Unknown')}",
                            "version": device.get("firmware", ""),
                        }
                    )
            else:
                # Default to HTTP service if none specified
                open_ports.append(
                    {
                        "port": 80,
                        "service": "http",
                        "state": "open",
                        "product": f"{device['manufacturer']} Web Interface",
                        "version": "",
                    }
                )

            device_copy["open_ports"] = open_ports
            device_copy["services"] = [p["service"] for p in open_ports]

            devices.append(device_copy)

            # Update the IP in the virtual device manager
            self.update_device_ip(device["mac"], ip)

        return devices
