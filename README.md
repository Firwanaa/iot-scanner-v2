
# IoT Scanner: Comprehensive Architecture and Setup Guide

## Overview

The IoT Scanner is a proof-of-concept tool designed to scan networks for IoT devices and analyze their security posture. It can operate in two modes:
- **Real mode**: Uses Nmap to perform actual network scanning.
- **Virtual mode**: Simulates network scanning with pre-defined virtual devices.

## System Architecture

The application follows a modular design pattern with a clear separation of concerns:

```
iot_scanner_main.py (Orchestrator)
│
├── scanner_modules/ (Core functionality)
│   ├── __init__.py
│   ├── constants.py (Configuration values)
│   ├── network_scanner.py (Device discovery)
│   ├── security_analyzer.py (Vulnerability analysis)
│   ├── utils.py (Shared utilities)
│   └── virtual_device_manager.py (Simulation)
│
└── data/ (Persistent storage)
    ├── default_credentials.json (Common IoT credentials)
    ├── virtual_devices.json (Device definitions)
    ├── vulnerability_db.json (Known vulnerabilities)
    └── scan_results/ (Output storage)
```

## Component Relationships and Data Flow

### Main Script (`iot_scanner_main.py`)

The main script serves as the entry point and orchestrator for the application. It:

1. Processes command-line arguments using `argparse`.
2. Initializes the core components with appropriate settings.
3. Coordinates the scanning and analysis workflow.
4. Presents results to the user via the Rich console interface.
5. Saves scan results to the `data/` directory.

#### Key Initialization Code:
```python
self.network_scanner = NetworkScanner(
    interface=args.interface,
    virtual_mode=self.virtual_mode, 
    aggressive=self.aggressive,
    target=self.target
)

self.security_analyzer = SecurityAnalyzer(
    virtual_mode=self.virtual_mode,
    aggressive=self.aggressive,
    credential_check=args.credential_check
)
```

#### Main Workflow in `scan()` Method:
```python
# Scan the network
devices = self.network_scanner.scan_network()

# Analyze security of devices
analyzed_devices = []
for device in devices:
    analyzed_device = self.security_analyzer.analyze_device(device)
    analyzed_devices.append(analyzed_device)

# Save scan results
self._save_scan_results(analyzed_devices)

# Display results
self._display_results(analyzed_devices)
```

---

## Scanner Modules

### 1. **Network Scanner (`network_scanner.py`)**
Responsible for discovering devices on the network.

- **Interface Selection**: Automatically finds the appropriate network interface or uses the specified one.
- **Network Range Determination**: Calculates the target network range based on interface IP and subnet mask.
- **Nmap Integration**: Uses Nmap for comprehensive device discovery and fingerprinting.
- **Fallback Mechanism**: Implements basic ping and port scanning when Nmap is unavailable.
- **Virtual Mode**: Delegates to `VirtualDeviceManager` for simulation when in virtual mode.

### 2. **Security Analyzer (`security_analyzer.py`)**
Analyzes discovered devices for security vulnerabilities.

- **Vulnerability Detection**: Checks for open insecure services, unencrypted traffic, and default credentials.
- **CVE Matching**: Maps device information to known vulnerabilities in the database.
- **Credential Testing**: Attempts to identify devices using default credentials.
- **Risk Scoring**: Calculates a security score based on the number and severity of issues.

### 3. **Virtual Device Manager (`virtual_device_manager.py`)**
Simulates IoT devices for testing without scanning a real network.

- **Device Definitions**: Loads or creates virtual device configurations.
- **Network Simulation**: Creates a simulated network with realistic IP allocation.
- **Device Variety**: Generates both IoT and non-IoT devices for realism.
- **Service Simulation**: Assigns realistic ports and services to devices.

### 4. **Constants (`constants.py`)**
Centralizes configuration values used throughout the application.

- **File Paths**: Locations for data files and results.
- **IoT Identifiers**: Lists of manufacturers, device types, and common ports.
- **Nmap Settings**: Scripts and parameters for different scan types.
- **Default Values**: Fallback configurations when user preferences aren't specified.

---

## Nmap Integration Details

The tool extensively leverages **Nmap** for network discovery and security analysis.

### 1. **Nmap Command Construction**
Located in `network_scanner.py`, the `_scan_with_nmap()` method builds an Nmap command with the following options:
```python
nmap_cmd = ["nmap", "-sS", "-PS22,80,443,8080", "-PA21,23,80,443,8080"]

if self.aggressive:
    nmap_cmd.extend(["-A", "-T4"])
    scripts = ",".join(NMAP_IOT_SCRIPTS)
    nmap_cmd.extend(["--script", scripts])
else:
    nmap_cmd.extend(["-sV", "-O", "--osscan-limit", "-T3"])
    basic_scripts = ",".join(["banner", "http-title", "upnp-info", "hnap-info"])
    nmap_cmd.extend(["--script", basic_scripts])
```

### 2. **Nmap Scripts Used**
Defined in `constants.py`:
```python
NMAP_IOT_SCRIPTS = [
    "http-auth", "http-auth-finder", "http-basic-auth", "http-default-accounts",
    "banner", "http-headers", "http-title", "ssl-cert",
    "upnp-info", "ssdp-info", "rtsp-methods",
    "http-slowloris-check", "ssl-heartbleed", "smb-vuln-*"
]
```
#### Integration with Nmap NSE Scripts
The Network Scanner's integration with Nmap's NSE (Nmap Scripting Engine) scripts is a key feature of the application:
NSE Script Categories Used
The application uses several categories of NSE scripts:
1. Discovery Scripts
These help identify devices and services:

- `banner`: Retrieves banners from services to identify software
- `http-title`: Gets webpage titles to identify web interfaces
- `upnp-info`: Discovers and queries UPnP devices
- `hnap-info`: Detects Home Network Administration Protocol devices

2. Authentication Scripts
These check for login pages and test default credentials:

- `http-auth`: Detects authentication methods
- `http-auth-finder`: Locates authentication forms
- `http-basic-auth`: Tests for HTTP Basic Auth
- `http-default-accounts`: Tests for default credentials in web applications

3. Vulnerability Scripts
These check for known security issues:

- `http-slowloris-check`: Tests for Slowloris DoS vulnerability
- `http-vuln-cve*`: Checks for specific CVE vulnerabilities
- `ssl-heartbleed`: Tests for the Heartbleed vulnerability
- `ssl-poodle`: Tests for the POODLE vulnerability
- `realtek-backdoor`: Checks for backdoors in Realtek devices

### 3. **Nmap Flags**
- `-sS`: SYN scan (faster and less intrusive).
- `-PS22,80,443,8080`: TCP SYN ping on common IoT ports.
- `-O`: OS detection.
- `-sV`: Service version detection.
- `--top-ports 30/100`: Scans the most common ports to save time.
- `-T3/-T4`: Sets timing template.
- `-oX/-oN`: Outputs results in XML and text formats.

---

## **Complete Setup Guide**
### **Prerequisites**
- Python **3.6+**
- **Nmap** (optional but recommended for real scanning)
- **Git** (for cloning the repository)

### **Platform-Specific Nmap Installation**
#### **Ubuntu/Debian**
```bash
sudo apt-get update
sudo apt-get install nmap
```
#### **macOS**
```bash
brew install nmap
```
#### **Windows**
- Download the installer from **[nmap.org](https://nmap.org)**
- Run the installer and follow the instructions.

### **Setting Up the IoT Scanner**
#### **1. Clone the repository**
```bash
git clone https://github.com/firwanaa/iot-scanner.git
cd iot-scanner
```
#### **2. Create and activate a virtual environment**
##### **Linux/macOS**
```bash
python -m venv env
source env/bin/activate
```
##### **Windows**
```bash
python -m venv env
env\Scripts\activate
```
#### **3. Install dependencies**
```bash
pip install -e .
```
#### **4. Verify installation**
```bash
python iot_scanner_main.py --version
```

---

## **Running the Scanner**
### **Virtual Mode (Safe for Testing)**
```bash
python iot_scanner_main.py -v
```
### **Real Scan Mode (Requires Nmap)**
```bash
python iot_scanner_main.py
python iot_scanner_main.py -a  # Aggressive mode
python iot_scanner_main.py --target 192.168.1.0/24
python iot_scanner_main.py --iot-only
python iot_scanner_main.py --show-ports
```

---

## **Troubleshooting**
- **Nmap not found?** Ensure Nmap is installed and in your **PATH**.
- **Permission issues?** Run as **Administrator** (Windows) or **sudo** (Linux/macOS).
- **Slow scanning?** Use `-T4` or **scan a smaller target range**.
- **Import errors?** Run:
  ```bash
  pip install -e .
  ```

---

## **Extending the Project**
- Add new virtual devices to `data/virtual_devices.json`.
- Add new vulnerabilities to `data/vulnerability_db.json`.
- Add new default credentials to `data/default_credentials.json`.
- Run in **virtual mode** to test new features before real scanning.


