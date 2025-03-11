#!/usr/bin/env python3
"""
Constants for the IoT scanner.
"""

import os

# File paths
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(SCRIPT_DIR, "data")
VULNERABILITY_DB_PATH = os.path.join(DATA_DIR, "vulnerability_db.json")
DEFAULT_CREDS_PATH = os.path.join(DATA_DIR, "default_credentials.json")
VIRTUAL_DEVICES_PATH = os.path.join(DATA_DIR, "virtual_devices.json")
SCAN_RESULTS_PATH = os.path.join(DATA_DIR, "scan_results")

# Constants for IoT device types
IOT_MANUFACTURERS = [
    "Amazon",
    "Apple",
    "Arlo",
    "Belkin",
    "Blink",
    "D-Link",
    "Ecobee",
    "Eufy",
    "Google",
    "Honeywell",
    "Kasa",
    "Lifx",
    "Meross",
    "Nest",
    "Philips",
    "Ring",
    "Samsung",
    "Sonos",
    "TP-Link",
    "Tuya",
    "Wemo",
    "Wyze",
    "Xiaomi",
    "Yale",
    "Zmodo",
]

IOT_DEVICE_TYPES = {
    "smart_light": ["Philips Hue", "LIFX", "TP-Link", "Sengled", "Wyze", "Tuya"],
    "smart_speaker": ["Amazon Echo", "Google Home", "Apple HomePod", "Sonos"],
    "smart_thermostat": ["Nest", "Ecobee", "Honeywell", "Emerson"],
    "smart_camera": ["Ring", "Arlo", "Wyze", "Blink", "Eufy", "Nest"],
    "smart_lock": ["August", "Yale", "Schlage", "Kwikset", "Eufy"],
    "smart_plug": ["TP-Link", "Wemo", "Amazon", "Gosund", "Kasa"],
    "smart_tv": ["Samsung", "LG", "Sony", "Vizio", "TCL", "Hisense"],
    "smart_appliance": ["Samsung", "LG", "GE", "Whirlpool", "Bosch"],
    "hub": ["Samsung SmartThings", "Amazon Echo", "Google Home", "Apple HomeKit"],
}

# Common IoT ports and services
COMMON_IOT_PORTS = {
    80: "http",
    443: "https",
    8080: "http-alt",
    8443: "https-alt",
    22: "ssh",
    23: "telnet",
    554: "rtsp",
    1883: "mqtt",
    8883: "mqtt-ssl",
    5683: "coap",
    53: "dns",
    123: "ntp",
    5000: "upnp",
    1900: "ssdp",
    9100: "printer",
    2323: "telnet-alt",
    8081: "http-proxy",
    8888: "http-alt",
    8008: "http-alt",
    8009: "http-alt",
    9000: "http-alt",
    7547: "cwmp/tr-069",
    5222: "xmpp",
    5353: "mdns",
}

# Common IoT login paths and credentials
IOT_LOGIN_PATHS = [
    "/login.html",
    "/admin.html",
    "/index.html",
    "/cgi-bin/login.cgi",
    "/cgi-bin/luci",
    "/cgi-bin/webproc",
    "/device.cgi",
    "/Main_Login.asp",
    "/",
    "/admin/",
    "/AUTH_LOGIN.HTML",
]

# Common IoT credentials
COMMON_CREDENTIALS = [
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": "password"},
    {"username": "admin", "password": "1234"},
    {"username": "admin", "password": "12345"},
    {"username": "admin", "password": ""},
    {"username": "root", "password": "root"},
    {"username": "root", "password": "password"},
    {"username": "root", "password": ""},
    {"username": "guest", "password": "guest"},
    {"username": "user", "password": "user"},
]

# Nmap scripts for IoT devices
NMAP_IOT_SCRIPTS = [
    # Authentication scripts
    "http-auth",
    "http-auth-finder",
    "http-basic-auth",
    "http-default-accounts",
    # Service detection
    "banner",
    "http-headers",
    "http-title",
    "http-methods",
    "ssl-cert",
    "ssl-enum-ciphers",
    # IoT specific
    "upnp-info",
    "sstp-discover",
    "rtsp-methods",
    "ssdp-info",
    # Vulnerabilities
    "http-slowloris-check",
    "http-vuln-cve2017-5638",  # Struts vulnerability
    "http-vuln-cve2017-1001000",  # Wordpress vulnerability
    "smb-vuln-*",
    "ssl-heartbleed",
    "ssl-poodle",
    # IoT specific vulnerabilities
    "realtek-backdoor",
    "hnap-info",
]
