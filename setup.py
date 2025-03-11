#!/usr/bin/env python3
"""
Setup script for the IoT Scanner.
"""

from setuptools import setup, find_packages

setup(
    name="iot-scanner",
    version="0.2.0",
    description="A tool to scan your home network for IoT devices and perform security analysis",
    author="Your Name",
    author_email="your.email@example.com",
    packages=find_packages(),
    install_requires=[
        "netifaces",
        "requests",
        "bs4",
        "rich",
    ],
    entry_points={
        "console_scripts": [
            "iot-scanner=iot_scanner_main:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security",
    ],
)

"""
# File Structure Guide

Here's how to organize the files for this IoT Scanner project:

```
iot_scanner/
├── data/                    # Directory for storing data files
│   ├── default_credentials.json
│   ├── vulnerability_db.json
│   ├── virtual_devices.json
│   └── scan_results/        # Directory for storing scan results
├── scanner_modules/         # Package for scanner modules
│   ├── __init__.py
│   ├── constants.py
│   ├── network_scanner.py
│   ├── security_analyzer.py
│   ├── utils.py
│   └── virtual_device_manager.py
├── iot_scanner_main.py      # Main script
├── setup.py                 # Setup script
└── README.md                # Documentation
```

# Installation Instructions

## 1. Clone the repository or create the directory structure

```bash
mkdir -p iot_scanner/data/scan_results
mkdir -p iot_scanner/scanner_modules
```

## 2. Copy the files to the appropriate locations

Place each Python file in its correct location as per the directory structure above.

## 3. Make the main script executable

```bash
chmod +x iot_scanner/iot_scanner_main.py
```

## 4. Install the package

```bash
cd iot_scanner
pip install -e .
```

## 5. Run the scanner

```bash
# Basic usage
iot-scanner

# Virtual mode
iot-scanner -v

# See all options
iot-scanner --help
```

# Dependencies

- Python 3.6+
- netifaces
- requests
- bs4 (BeautifulSoup)
- rich (for console UI)
- nmap (optional but recommended)
"""
