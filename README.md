# HikSploit

**Specialized penetration testing tool for Hikvision surveillance cameras.**

---

## Description

HikSploit is a Python-based utility designed to automate exploitation and directory accessibility checks on Hikvision network cameras (firmware version 3.1.3.150324). It downloads snapshots, compiles them into videos, retrieves device information, and downloads encrypted configuration files along with registered user credentials.

HikSploit supports two modes:  
- **Streaming Mode:** Continuously captures live snapshots and compiles them into videos in real-time.  
- **Standard Mode:** Downloads snapshots and device data in a step-by-step process.

---

## Features

- Automated directory accessibility checks  
- Snapshot downloading and video compilation  
- Device and user information retrieval  
- Encrypted configuration file downloading and decryption  
- Comprehensive CVE vulnerability checks  
- Multi-target support using a targets.txt file  
- Detailed logging with colored output  
- Interrupt handling (SIGQUIT)  
- Customizable configuration options  
- Organized output folders for snapshots, logs, and decrypted files

---

## Requirements

- Python 3.6 or higher  
- FFmpeg (for video compilation)  
- Requests library  
- PyCrypto library (for decryption, install with `pip install pycrypto`)

---

## Installation

```bash
git clone https://github.com/aresowl/HikSploit.git
cd HikSploit
pip3 install -r requirements.txt
# Install FFmpeg from its official website
```

## Usage
Create a targets.txt file listing target camera IPs and ports in the format IP:PORT.

Run the checker script:
```bash
python3 checker.py
```

## Finding Targets
Use Shodan with the query `3.1.3.150324` to find Hikvision cameras with the specified firmware version.


## My WebSite
www.xi0.ir

## License
This project is licensed under the MIT License.
