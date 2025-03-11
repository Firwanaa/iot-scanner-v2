#!/usr/bin/env python3
"""
Utility functions for the IoT scanner.
"""

import os
import json
import subprocess
import sys
from typing import Dict, List

from rich.console import Console

from scanner_modules.constants import (
    DATA_DIR,
    SCAN_RESULTS_PATH,
    VULNERABILITY_DB_PATH,
    DEFAULT_CREDS_PATH,
    VIRTUAL_DEVICES_PATH,
)

# Create rich console globally
console = Console()


def ensure_data_dirs():
    """Ensure the data directories exist and create them if they don't."""
    dirs_to_check = [DATA_DIR, SCAN_RESULTS_PATH]

    for directory in dirs_to_check:
        if not os.path.exists(directory):
            try:
                os.makedirs(directory)
                console.print(
                    f"[bold green]Created directory: {directory}[/bold green]"
                )
            except Exception as e:
                console.print(
                    f"[bold red]Error creating directory {directory}: {e}[/bold red]"
                )
                sys.exit(1)


def check_nmap_installation():
    """Verify that nmap is installed and accessible."""
    try:
        subprocess.run(
            ["nmap", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        console.print(
            "[bold red]Error: nmap is not installed or not found in PATH.[/bold red]\n"
            "Please install nmap before using this tool:\n"
            "- For Ubuntu/Debian: sudo apt-get install nmap\n"
            "- For CentOS/RHEL: sudo yum install nmap\n"
            "- For macOS: brew install nmap\n"
            "- For Windows: Download from https://nmap.org/download.html"
        )
        return False


def check_python_modules():
    """Check if all required Python modules are installed."""
    required_modules = ["netifaces", "requests", "bs4", "rich"]

    missing_modules = []
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)

    if missing_modules:
        console.print(
            f"[bold red]Error: Missing required Python modules: {', '.join(missing_modules)}[/bold red]\n"
            "Please install them using pip:\n"
            f"pip install {' '.join(missing_modules)}"
        )
        return False

    return True


def create_default_files():
    """Create default data files if they don't exist."""
    # Create vulnerability database
    if not os.path.exists(VULNERABILITY_DB_PATH):
        vulnerabilities = {
            "CVE-2021-12345": {
                "device_type": "smart_camera",
                "manufacturer": "Generic",
                "models": ["Generic Smart Camera"],
                "description": "Remote code execution vulnerability",
                "severity": "high",
                "remediation": "Update firmware to latest version",
            },
            "CVE-2022-67890": {
                "device_type": "smart_light",
                "manufacturer": "Philips",
                "models": ["Hue Bridge v1"],
                "description": "Authentication bypass vulnerability",
                "severity": "medium",
                "remediation": "Update to latest firmware",
            },
            "CVE-2022-11111": {
                "device_type": "smart_speaker",
                "manufacturer": "Generic",
                "models": ["Generic Smart Speaker"],
                "description": "Insecure data storage vulnerability",
                "severity": "low",
                "remediation": "Update to latest firmware",
            },
            "CVE-2020-28347": {
                "device_type": "router",
                "manufacturer": "D-Link",
                "models": ["DIR-865L", "DIR-645"],
                "description": "Command injection vulnerability in the web interface",
                "severity": "critical",
                "remediation": "Update firmware to latest version or replace device",
            },
            "CVE-2019-12780": {
                "device_type": "smart_camera",
                "manufacturer": "Wyze",
                "models": ["Cam v1", "Cam v2"],
                "description": "Improper authentication allows unauthenticated access to video stream",
                "severity": "high",
                "remediation": "Update firmware to version 4.9.6.218 or later",
            },
            "CVE-2020-25767": {
                "device_type": "smart_plug",
                "manufacturer": "TP-Link",
                "models": ["HS110", "KP115"],
                "description": "Communications are not encrypted allowing traffic interception",
                "severity": "medium",
                "remediation": "Update to latest firmware and isolate on separate network",
            },
            "CVE-2019-15361": {
                "device_type": "smart_speaker",
                "manufacturer": "Amazon",
                "models": ["Echo Dot (3rd Gen)"],
                "description": "Voice command injection vulnerability",
                "severity": "medium",
                "remediation": "Update firmware to latest version",
            },
            "CVE-2020-13266": {
                "device_type": "hub",
                "manufacturer": "Samsung",
                "models": ["SmartThings Hub v2"],
                "description": "Remote code execution via unvalidated update mechanism",
                "severity": "critical",
                "remediation": "Update to firmware version 0.34.0 or later",
            },
        }
        try:
            with open(VULNERABILITY_DB_PATH, "w") as f:
                json.dump(vulnerabilities, f, indent=4)
            console.print(
                f"[bold green]Created vulnerability database at {VULNERABILITY_DB_PATH}[/bold green]"
            )
        except Exception as e:
            console.print(
                f"[bold red]Error creating vulnerability database: {e}[/bold red]"
            )

    # Create default credentials database
    if not os.path.exists(DEFAULT_CREDS_PATH):
        default_creds = {
            "Generic": [
                {"username": "admin", "password": "admin"},
                {"username": "admin", "password": "password"},
                {"username": "admin", "password": ""},
                {"username": "root", "password": "root"},
                {"username": "user", "password": "user"},
            ],
            "D-Link": [
                {"username": "admin", "password": "password"},
                {"username": "admin", "password": "admin"},
                {"username": "Admin", "password": ""},
            ],
            "TP-Link": [
                {"username": "admin", "password": "admin"},
                {"username": "admin", "password": "password"},
                {"username": "tp-link", "password": "tp-link"},
            ],
            "Nest": [
                {"username": "user", "password": "nest123"},
                {"username": "admin", "password": "nest123"},
            ],
            "Hikvision": [
                {"username": "admin", "password": "12345"},
                {"username": "admin", "password": "admin"},
            ],
            "Dahua": [
                {"username": "admin", "password": "admin"},
                {"username": "888888", "password": "888888"},
            ],
            "Wyze": [
                {"username": "admin", "password": "admin1234"},
                {"username": "admin", "password": ""},
            ],
            "Belkin": [
                {"username": "admin", "password": "password"},
                {"username": "admin", "password": "belkin"},
            ],
            "Asus": [
                {"username": "admin", "password": "admin"},
                {"username": "admin", "password": "password"},
            ],
            "Netgear": [
                {"username": "admin", "password": "password"},
                {"username": "admin", "password": "admin"},
            ],
        }
        try:
            with open(DEFAULT_CREDS_PATH, "w") as f:
                json.dump(default_creds, f, indent=4)
            console.print(
                f"[bold green]Created default credentials database at {DEFAULT_CREDS_PATH}[/bold green]"
            )
        except Exception as e:
            console.print(
                f"[bold red]Error creating default credentials database: {e}[/bold red]"
            )


def calculate_security_score(security_issues: List[Dict]) -> int:
    """Calculate a security score based on issues (0-100, higher is more secure)."""
    if not security_issues:
        return 100

    # Start with a perfect score
    score = 100

    # Deduct points based on severity and type
    for issue in security_issues:
        severity = issue.get("severity", "medium").lower()
        issue_type = issue.get("type", "").lower()

        # Base deductions by severity
        if severity == "critical":
            deduction = 25
        elif severity == "high":
            deduction = 15
        elif severity == "medium":
            deduction = 10
        elif severity == "low":
            deduction = 5
        else:
            deduction = 8  # Default for unknown severity

        # Additional deductions for certain high-risk issues
        if issue_type == "weak_credentials" or issue_type == "default_password":
            deduction += 5  # Extra penalty for credential issues
        elif issue_type == "no_authentication":
            deduction += 10  # Severe penalty for no authentication
        elif issue_type == "known_vulnerability" and "cve" in issue:
            deduction += 3  # Extra penalty for known CVEs
        elif issue_type == "insecure_service" and issue.get("service") == "telnet":
            deduction += 5  # Extra penalty for telnet

        score -= deduction

    # Ensure score doesn't go below 0
    return max(0, score)


def guess_service(port: int) -> str:
    """Guess service based on port number."""
    from scanner_modules.constants import COMMON_IOT_PORTS

    # Check our dictionary of common IoT ports
    if port in COMMON_IOT_PORTS:
        return COMMON_IOT_PORTS[port]

    # Common non-IoT ports
    common_ports = {
        21: "ftp",
        22: "ssh",
        25: "smtp",
        53: "dns",
        135: "msrpc",
        139: "netbios-ssn",
        445: "microsoft-ds",
        3389: "ms-wbt-server",
        5900: "vnc",
        8291: "unknown",
    }

    return common_ports.get(port, "unknown")


def is_likely_iot(device: Dict) -> bool:
    """Determine if a device is likely an IoT device based on various factors."""
    from scanner_modules.constants import IOT_MANUFACTURERS

    hostname = device.get("name", "").lower()
    manufacturer = device.get("manufacturer", "").lower()
    services = device.get("services", [])
    open_ports = device.get("open_ports", [])

    # Check for common IoT manufacturers
    if any(m.lower() in manufacturer for m in IOT_MANUFACTURERS):
        return True

    # Check for common IoT services/protocols
    iot_services = [
        "rtsp",
        "upnp",
        "ssdp",
        "mdns",
        "mqtt",
        "coap",
        "onvif",
        "hue",
        "wemo",
        "tuya",
        "z-wave",
        "zigbee",
    ]
    if any(s in services for s in iot_services):
        return True

    # Check for common IoT ports in specific combinations
    if "http" in services and len(open_ports) <= 5:
        # Many IoT devices have a web interface but few other services
        return True

    # Check hostname for common IoT indicators
    iot_indicators = [
        "cam",
        "camera",
        "doorbell",
        "thermostat",
        "speaker",
        "echo",
        "dot",
        "home",
        "bulb",
        "light",
        "plug",
        "switch",
        "lock",
        "hub",
        "nest",
        "hue",
        "ring",
        "arlo",
        "wyze",
        "lifx",
        "sonos",
        "wemo",
        "tv",
        "roku",
        "firetv",
        "chromecast",
    ]
    if any(indicator in hostname for indicator in iot_indicators):
        return True

    # Default to False - not enough evidence it's an IoT device
    return False


def guess_device_type(device: Dict) -> str:
    """Guess the device type based on hostname, manufacturer, and open ports/services."""
    from scanner_modules.constants import IOT_DEVICE_TYPES

    # Start with a more sophisticated check based on detected services
    services = device.get("services", [])
    hostname = device.get("name", "").lower()
    manufacturer = device.get("manufacturer", "").lower()

    # Check for camera devices
    if any(s in services for s in ["rtsp", "onvif", "axis-video"]):
        return "smart_camera"

    # Check for voice assistants/speakers
    if "avahi" in services and any(
        m in manufacturer for m in ["amazon", "google", "apple", "sonos"]
    ):
        return "smart_speaker"

    # Check for smart TVs
    if any(s in services for s in ["dlna", "roku"]) or "tv" in hostname:
        return "smart_tv"

    # Check for routers/network equipment
    if any(s in services for s in ["http", "https"]) and any(
        p.get("port", 0) in [80, 443, 8080, 8443] for p in device.get("open_ports", [])
    ):
        if any(
            m in manufacturer
            for m in ["tp-link", "netgear", "asus", "d-link", "linksys"]
        ):
            return "router"

    # Check for smart hubs
    if "z-wave" in services or "zigbee" in services:
        return "hub"

    # Check hostname for common IoT device indicators
    if any(word in hostname for word in ["camera", "cam", "ipcam"]):
        return "smart_camera"
    elif any(word in hostname for word in ["light", "bulb", "hue"]):
        return "smart_light"
    elif any(
        word in hostname
        for word in ["speaker", "echo", "dot", "home", "alexa", "google"]
    ):
        return "smart_speaker"
    elif any(word in hostname for word in ["thermostat", "nest", "ecobee"]):
        return "smart_thermostat"
    elif any(word in hostname for word in ["lock", "doorbell"]):
        return "smart_lock"
    elif any(word in hostname for word in ["plug", "switch", "outlet"]):
        return "smart_plug"
    elif any(word in hostname for word in ["tv", "television", "roku", "firetv"]):
        return "smart_tv"
    elif any(word in hostname for word in ["fridge", "washing", "dishwasher"]):
        return "smart_appliance"

    # Check manufacturer
    for device_type, manufacturers in IOT_DEVICE_TYPES.items():
        for brand in manufacturers:
            if brand.lower() in manufacturer:
                return device_type

    # Default to unknown for IoT devices we couldn't classify more specifically
    return "iot_device"
