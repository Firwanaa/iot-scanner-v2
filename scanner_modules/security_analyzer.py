#!/usr/bin/env python3
"""
Security analyzer module for IoT devices.
Analyzes devices for security vulnerabilities.
"""

import json
import re
import socket
import time
from typing import Dict, List, Optional, Tuple, Union

import requests
import urllib3

# from urllib3 import exceptions
from urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup

from scanner_modules.constants import (
    IOT_LOGIN_PATHS,
    COMMON_CREDENTIALS,
    VULNERABILITY_DB_PATH,
    DEFAULT_CREDS_PATH,
)
from scanner_modules.utils import console, calculate_security_score
from scanner_modules.virtual_device_manager import VirtualDeviceManager

# Suppress insecure request warnings when making HTTPS requests without verification
urllib3.disable_warnings(InsecureRequestWarning)


class SecurityAnalyzer:
    """Performs security analysis on discovered IoT devices."""

    def __init__(self, virtual_mode=False, aggressive=False, credential_check=False):
        """Initialize the security analyzer."""
        self.virtual_mode = virtual_mode
        self.aggressive = aggressive
        self.credential_check = credential_check
        self.virtual_device_manager = VirtualDeviceManager()
        self.vulnerabilities = self._load_vulnerabilities()
        self.default_credentials = self._load_default_credentials()

    def _load_vulnerabilities(self) -> Dict:
        """Load vulnerability database from file."""
        try:
            with open(VULNERABILITY_DB_PATH, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            console.print(
                f"[bold red]Error loading vulnerability database: {e}[/bold red]"
            )
            return {}

    def _load_default_credentials(self) -> Dict:
        """Load default credentials database from file."""
        try:
            with open(DEFAULT_CREDS_PATH, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            console.print(
                f"[bold red]Error loading default credentials database: {e}[/bold red]"
            )
            return {}

    def analyze_device(self, device: Dict) -> Dict:
        """Analyze a device for security issues."""
        if not device.get("is_iot", False):
            # Skip non-IoT devices or add minimal analysis
            device["security_issues"] = []
            device["security_score"] = 100
            return device

        if self.virtual_mode:
            return self._analyze_virtual_device(device)
        else:
            return self._analyze_real_device(device)

    def _analyze_real_device(self, device: Dict) -> Dict:
        """Analyze a real device for security issues."""
        security_issues = []

        # Get device info we need for analysis
        ip = device.get("ip", "")
        open_ports = device.get("open_ports", [])

        # Check for open telnet
        if any(p.get("service") == "telnet" for p in open_ports):
            security_issues.append(
                {
                    "type": "insecure_service",
                    "service": "telnet",
                    "severity": "high",
                    "description": "Telnet service is enabled. Telnet transmits data in cleartext.",
                    "recommendation": "Disable Telnet and use SSH if remote access is needed.",
                }
            )

        # Check for open web interfaces on common ports
        web_ports = [
            p
            for p in open_ports
            if p.get("service", "") in ["http", "http-alt"]
            and p.get("state", "") == "open"
        ]

        # Only check a few ports to avoid excessive requests
        for port_info in web_ports[:3]:
            port = port_info.get("port", 0)
            if port == 0:
                continue

            protocol = "https" if port == 443 or port == 8443 else "http"

            # Check for default credentials on open web interfaces
            if self.credential_check and self._check_web_interface_for_login(
                device, protocol, port
            ):
                creds_found = self._check_default_credentials(device, protocol, port)
                if creds_found:
                    security_issues.append(
                        {
                            "type": "weak_credentials",
                            "severity": "high",
                            "description": f"Device is using default or weak credentials on {protocol}://{ip}:{port}",
                            "recommendation": "Change default credentials immediately.",
                            "credentials": creds_found,
                        }
                    )

        # Check for unencrypted traffic
        has_http = any(p.get("service", "") == "http" for p in open_ports)
        has_https = any(p.get("service", "") == "https" for p in open_ports)

        if has_http and not has_https:
            security_issues.append(
                {
                    "type": "unencrypted_communication",
                    "severity": "medium",
                    "description": "Device uses HTTP without HTTPS support, potentially exposing sensitive data.",
                    "recommendation": "If available, enable HTTPS/TLS in the device settings.",
                }
            )

        # Check for weak SSH
        ssh_ports = [
            p
            for p in open_ports
            if p.get("service", "") == "ssh" and p.get("state", "") == "open"
        ]
        if ssh_ports and self.aggressive:
            # In aggressive mode, attempt to identify weak SSH configurations
            for port_info in ssh_ports:
                port = port_info.get("port", 0)
                if port == 0:
                    continue

                ssh_version = port_info.get("version", "")

                if ssh_version and ("1.0" in ssh_version or "2.0" in ssh_version):
                    security_issues.append(
                        {
                            "type": "outdated_service",
                            "service": "ssh",
                            "severity": "medium",
                            "description": f"Device is running an old SSH version ({ssh_version}).",
                            "recommendation": "Update the SSH server to the latest version.",
                        }
                    )

        # Check if device has open ports with known vulnerabilities
        for port_info in open_ports:
            service = port_info.get("service", "")
            product = port_info.get("product", "")
            version = port_info.get("version", "")

            # Check for scripts output for vulnerabilities
            script_output = port_info.get("script_output", [])
            for script in script_output:
                # Check if any vulnerability scripts found issues
                if "VULNERABLE" in script.get("output", "") or "CVE-" in script.get(
                    "output", ""
                ):
                    # Extract CVE ID if present
                    cve_match = re.search(
                        r"(CVE-\d{4}-\d{4,})", script.get("output", "")
                    )
                    cve_id = cve_match.group(1) if cve_match else "Unknown"

                    security_issues.append(
                        {
                            "type": "known_vulnerability",
                            "cve": cve_id,
                            "severity": "high"
                            if "VULNERABLE" in script.get("output", "").upper()
                            else "medium",
                            "description": f"Vulnerability detected by nmap script {script.get('name', '')}: {script.get('output', '')[:100]}...",
                            "recommendation": "Update firmware/software to latest version.",
                        }
                    )

        # Check for known CVEs based on service, product and version information
        for port_info in open_ports:
            product = port_info.get("product", "").lower()
            version = port_info.get("version", "")

            if product and version:
                # Check our vulnerability database for matches
                for cve_id, vuln_info in self.vulnerabilities.items():
                    models = [model.lower() for model in vuln_info.get("models", [])]
                    manufacturer = vuln_info.get("manufacturer", "").lower()

                    if (
                        manufacturer in product
                        or any(model in product for model in models)
                    ) and version:
                        # This is a simplified check - in a real scanner, we would use
                        # version comparison to check if the version is vulnerable
                        security_issues.append(
                            {
                                "type": "potential_vulnerability",
                                "cve": cve_id,
                                "severity": vuln_info.get("severity", "medium"),
                                "description": vuln_info.get(
                                    "description", "Unknown vulnerability"
                                ),
                                "recommendation": vuln_info.get(
                                    "remediation", "Update firmware to latest version."
                                ),
                            }
                        )

        # Add security info to device
        device["security_issues"] = security_issues
        device["security_score"] = calculate_security_score(security_issues)

        return device

    def _analyze_virtual_device(self, device: Dict) -> Dict:
        """Analyze a virtual device using predefined vulnerabilities."""
        security_issues = []

        # For virtual devices, get the vulnerabilities from the device config
        virtual_device = self.virtual_device_manager.get_device_by_mac(
            device.get("mac", "")
        )

        if virtual_device and "vulnerabilities" in virtual_device:
            # Process each vulnerability
            for vuln in virtual_device.get("vulnerabilities", []):
                if vuln == "weak_password" or vuln == "default_password":
                    security_issues.append(
                        {
                            "type": "weak_credentials",
                            "severity": "high",
                            "description": "Device is using default or weak credentials",
                            "recommendation": "Change default credentials immediately",
                            "credentials": virtual_device.get(
                                "default_credentials", {}
                            ),
                        }
                    )
                elif vuln == "weak_encryption":
                    security_issues.append(
                        {
                            "type": "weak_encryption",
                            "severity": "medium",
                            "description": "Device is using weak encryption or unencrypted communications",
                            "recommendation": "Update firmware and enable stronger encryption if available",
                        }
                    )
                elif vuln == "telnet_enabled":
                    security_issues.append(
                        {
                            "type": "insecure_service",
                            "service": "telnet",
                            "severity": "high",
                            "description": "Device has Telnet service enabled",
                            "recommendation": "Disable Telnet and use SSH if remote access is needed",
                        }
                    )
                elif vuln == "no_password":
                    security_issues.append(
                        {
                            "type": "no_authentication",
                            "severity": "critical",
                            "description": "Device has no password protection",
                            "recommendation": "Configure a strong password immediately",
                        }
                    )
                elif vuln.startswith("CVE-"):
                    # Look up in vulnerability database
                    if vuln in self.vulnerabilities:
                        cve_info = self.vulnerabilities.get(vuln, {})
                        security_issues.append(
                            {
                                "type": "known_vulnerability",
                                "cve": vuln,
                                "severity": cve_info.get("severity", "medium"),
                                "description": cve_info.get(
                                    "description", "Unknown vulnerability"
                                ),
                                "recommendation": cve_info.get(
                                    "remediation", "Update firmware to latest version"
                                ),
                            }
                        )

        # Add security info to device
        device["security_issues"] = security_issues
        device["security_score"] = calculate_security_score(security_issues)

        return device

    def _check_web_interface_for_login(
        self, device: Dict, protocol: str, port: int
    ) -> bool:
        """Check if device has a web interface with a login page."""
        if self.virtual_mode:
            # For virtual mode, check if device has web_interface set to True
            virtual_device = self.virtual_device_manager.get_device_by_mac(
                device.get("mac", "")
            )
            return (
                virtual_device.get("web_interface", False) if virtual_device else False
            )

        # For real devices, check common login paths
        ip = device.get("ip", "")
        if not ip:
            return False

        for path in IOT_LOGIN_PATHS:
            url = f"{protocol}://{ip}:{port}{path}"
            try:
                # Set a short timeout
                response = requests.get(url, timeout=3, verify=False)

                # Check if it looks like a login page
                if response.status_code == 200:
                    html = response.text.lower()
                    if any(
                        term in html
                        for term in [
                            "login",
                            "password",
                            "username",
                            "user name",
                            "signin",
                        ]
                    ):
                        # Found a potential login page
                        return True
            except (requests.RequestException, ConnectionError):
                continue

        return False

    def _check_default_credentials(
        self, device: Dict, protocol: str, port: int
    ) -> Optional[Dict]:
        """Check if device is using default credentials by trying to log in."""
        if self.virtual_mode:
            # For virtual mode, return the predefined default credentials if they exist
            virtual_device = self.virtual_device_manager.get_device_by_mac(
                device.get("mac", "")
            )
            if (
                virtual_device
                and virtual_device.get("default_credentials")
                and virtual_device.get("web_interface", False)
            ):
                return virtual_device.get("default_credentials")
            return None

        # For real devices, we'll try common credentials
        ip = device.get("ip", "")
        if not ip:
            return None

        manufacturer = device.get("manufacturer", "Unknown")

        # Start with manufacturer-specific credentials if available
        credentials_to_try = []
        for mfg in self.default_credentials:
            if mfg.lower() in manufacturer.lower():
                credentials_to_try.extend(self.default_credentials.get(mfg, []))

        # Add generic credentials
        if "Generic" in self.default_credentials:
            credentials_to_try.extend(self.default_credentials.get("Generic", []))

        # If no manufacturer-specific or generic credentials, use our built-in list
        if not credentials_to_try:
            credentials_to_try = COMMON_CREDENTIALS

        # Try common login paths
        for path in IOT_LOGIN_PATHS:
            login_url = f"{protocol}://{ip}:{port}{path}"

            try:
                # First, check if the page exists and looks like a login page
                response = requests.get(login_url, timeout=3, verify=False)

                if response.status_code == 200:
                    html = response.text.lower()

                    # Skip if it doesn't look like a login page
                    if not any(
                        term in html
                        for term in [
                            "login",
                            "password",
                            "username",
                            "user name",
                            "signin",
                        ]
                    ):
                        continue

                    # Simple heuristic to skip login pages without forms
                    if "form" not in html and "input" not in html:
                        continue

                    # Check for CSRF tokens
                    soup = BeautifulSoup(html, "html.parser")
                    csrf_token = None

                    # Look for potential CSRF tokens
                    csrf_fields = soup.find_all("input", attrs={"type": "hidden"})
                    for field in csrf_fields:
                        field_name = field.get("name", "").lower()
                        if any(
                            name in field_name
                            for name in ["csrf", "token", "_token", "nonce"]
                        ):
                            csrf_token = field.get("value", "")

                    # Try each set of credentials
                    for creds in credentials_to_try[
                        :5
                    ]:  # Try only first 5 to avoid lockouts
                        # If real security testing, we would need to handle different login flows,
                        # forms, redirects, etc. This is a simplified version for demonstration.
                        try:
                            # Build a simple form submission
                            form_data = {
                                "username": creds.get("username", ""),
                                "password": creds.get("password", ""),
                            }

                            # Add username/password with different common field names
                            username_fields = [
                                "username",
                                "user",
                                "name",
                                "login",
                                "email",
                            ]
                            password_fields = ["password", "pass", "pwd"]

                            # Find input fields and their names to better guess form structure
                            inputs = soup.find_all("input")
                            for input_field in inputs:
                                field_name = input_field.get("name", "").lower()
                                if not field_name:
                                    continue

                                field_type = input_field.get("type", "").lower()

                                # Match username fields
                                if field_type in ["text", "email"] or any(
                                    u_field in field_name for u_field in username_fields
                                ):
                                    form_data[field_name] = creds.get("username", "")

                                # Match password fields
                                elif field_type == "password" or any(
                                    p_field in field_name for p_field in password_fields
                                ):
                                    form_data[field_name] = creds.get("password", "")

                                # Add CSRF token if found
                                elif csrf_token and any(
                                    token_name in field_name
                                    for token_name in [
                                        "csrf",
                                        "token",
                                        "_token",
                                        "nonce",
                                    ]
                                ):
                                    form_data[field_name] = csrf_token

                            # Add any CSRF token as a separate field if we found one
                            if csrf_token:
                                for token_name in [
                                    "csrf_token",
                                    "_csrf",
                                    "token",
                                    "_token",
                                ]:
                                    if token_name not in form_data:
                                        form_data[token_name] = csrf_token

                            # Send the login request
                            login_response = requests.post(
                                login_url,
                                data=form_data,
                                allow_redirects=True,
                                timeout=3,
                                verify=False,
                            )

                            # Check if login was successful
                            # This is a simplified check and would need to be enhanced for real scanning
                            if login_response.status_code == 200:
                                login_html = login_response.text.lower()

                                # Check for common successful login indicators
                                success_indicators = [
                                    "welcome",
                                    "dashboard",
                                    "logout",
                                    "sign out",
                                    "successfully",
                                    "profile",
                                    "account",
                                    "setup",
                                    "configuration",
                                ]

                                # Check for common failed login indicators
                                failure_indicators = [
                                    "invalid",
                                    "failed",
                                    "incorrect",
                                    "wrong password",
                                    "try again",
                                    "error",
                                    "login",
                                ]

                                # Simplified check - in reality we'd need more sophisticated verification
                                if any(
                                    indicator in login_html
                                    for indicator in success_indicators
                                ) and not any(
                                    indicator in login_html
                                    for indicator in failure_indicators
                                ):
                                    # Found working credentials
                                    return creds

                        except requests.RequestException:
                            continue

            except (requests.RequestException, ConnectionError):
                continue

        return None
