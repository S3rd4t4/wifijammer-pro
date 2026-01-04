![img alt](https://github.com/S3rd4t4/wifijammer-pro/blob/f1885b547f1bc711b8487a60008b0d3a84889667/img.png)
# WiFiJammer-PRO

A professional WiFi deauthentication tool for authorized security testing and penetration testing.

![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)
![License](https://img.shields.io/badge/license-BSD--3--Clause-green)

## ⚠️ Legal Disclaimer

**THIS TOOL IS FOR EDUCATIONAL AND AUTHORIZED SECURITY TESTING ONLY.**

Unauthorized use of this tool to disrupt WiFi networks may violate:
- Computer Fraud and Abuse Act (18 U.S.C. § 1030) in the United States
- Computer Misuse Act 1990 in the United Kingdom
- Similar legislation in other jurisdictions

**You are solely responsible for ensuring your use complies with applicable laws. The author assumes no liability for misuse of this tool.**

## Features

### Core Functionality
- **Multi-threaded attacks**: Configurable worker threads (1-8) for maximum efficiency
- **Adaptive channel hopping**: Automatic channel switching with 3-second dwell time
- **MAC spoofing**: Randomized MAC address for anonymity
- **Real-time monitoring**: Live network discovery with airodump-ng integration
- **Client targeting**: Both broadcast and directed deauthentication packets

### Attack Modes
- **Blacklist**: Jam ONLY selected targets
- **Whitelist**: Jam ALL except selected targets
- **All**: Jam everything in range

### Attack Presets
1. **Stealthy** - Low intensity, hard to detect (3 packets, 0.5s delay)
2. **Balanced** - Recommended for most scenarios (10 packets, 0.01s delay)
3. **Aggressive** - High intensity, fast disconnect (25 packets, 0.005s delay)
4. **Overwhelming** - Maximum power, total denial (50 packets, 0.001s delay)
5. **Custom** - Manual configuration

### Display Filters
Press `F` during attack to cycle through filters:
- **Jamming Only**: Show only currently attacked targets
- **All Devices**: Show all discovered APs and clients
- **APs Only**: Show access points only
- **Clients Only**: Show connected clients only

### Advanced Features
- **WPA2/WPA3 detection**: Protocol identification with color coding
- **Signal strength visualization**: Power-based color coding
- **MAC vendor lookup**: Automatic device manufacturer identification
- **Packet rate tracking**: Real-time packets/second statistics
- **Adapter health monitoring**: Automatic adapter status checks

## Requirements

### Hardware
- WiFi adapter with **monitor mode** and **packet injection** support
- Recommended: Alfa AWUS036ACH, AWUS036NH, or similar
- Chipsets: rtl8812au, ath9k_htc, rt2800usb

### Software
- Linux OS (Debian/Ubuntu, Arch, Kali Linux recommended)
- Python 3.6 or higher
- Root/sudo privileges

## Installation

### Quick Setup (Recommended)

The script includes automatic dependency installation:

```bash
# Clone repository
git clone https://github.com/s3rd4t4/wifijammer-pro.git
cd wifijammer-pro

# Run with sudo (dependencies will be installed automatically)
sudo python3 wifijammer.py
```

The script will automatically:
- Install system dependencies (aircrack-ng, iw, net-tools)
- Create a Python virtual environment
- Install Python packages (scapy, requests)
- Download MAC vendor database

### Manual Installation

If you prefer to install dependencies manually:

#### Debian/Ubuntu
```bash
sudo apt update
sudo apt install -y aircrack-ng iw net-tools python3 python3-pip python3-venv
```

#### Arch Linux
```bash
sudo pacman -Sy --noconfirm aircrack-ng iw net-tools python python-pip
```

#### Python Dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install scapy requests
```

## Usage

### Basic Usage
```bash
sudo python3 wifijammer.py
```

The script will guide you through:
1. **Interface selection**: Choose your wireless adapter
2. **MAC spoofing**: Automatic randomization
3. **TX power configuration**: Set transmission power (1-30 dBm)
4. **Attack preset**: Choose intensity level
5. **Channel selection**: 2.4GHz, 5GHz, or both
6. **Network scanning**: 30-second discovery phase
7. **Target selection**: Choose attack mode and targets

### Interactive Controls

During attack:
- **Ctrl+C**: Stop attack and restore network
- **F**: Cycle through display filters
- Real-time statistics automatically update every second

### Example Workflow

```bash
$ sudo python3 wifijammer.py

# 1. Select interface (e.g., wlan0)
# 2. MAC will be spoofed automatically
# 3. Choose TX power (default: 30 dBm)
# 4. Select attack preset (2 = Balanced recommended)
# 5. Choose channels (1 = 2.4GHz US)
# 6. Wait for 30-second scan
# 7. Select mode:
#    - [1] Blacklist: Target specific APs (e.g., 1,3,5)
#    - [2] Whitelist: Jam all except selected
#    - [3] All: Jam everything
# 8. Choose channel mode:
#    - [1] Active channels only
#    - [2] Active + New channels (dynamic)
# 9. Attack begins!
```

## Configuration

### Attack Parameters

Modify these in the script if needed:

```python
# Global defaults
tx_power = 30                  # Transmission power (dBm)
packets_per_burst = 10         # Packets per deauth burst
packet_delay = 0.01            # Delay between packets (seconds)
deauth_code = 7                # Deauth reason code
send_disas = True              # Send disassociation packets
num_workers = 3                # Worker threads
```

### Channel Configuration

```python
CHANNELS_24GHZ = [1-14]        # 2.4 GHz channels
CHANNELS_5GHZ = [36-165]       # 5 GHz channels
```

## Troubleshooting

### Adapter Not Detected
```bash
# Check if adapter supports monitor mode
iw list | grep "Supported interface modes" -A 8

# Check wireless interfaces
iw dev
```

### Monitor Mode Issues
```bash
# Manual monitor mode setup
sudo ip link set wlan0 down
sudo iw wlan0 set monitor none
sudo ip link set wlan0 up
```

### Permission Denied
```bash
# Ensure you're running with sudo
sudo python3 wifijammer.py
```

### No Packets Sent
- Verify adapter supports **packet injection**
- Check if adapter driver is loaded correctly
- Try different TX power levels
- Ensure target is on selected channels

### Virtual Environment Issues
```bash
# Recreate venv
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install scapy requests
```

## Testing Recommendations

### Controlled Environment
- Use in isolated lab environment
- Test with your own devices first
- Monitor with secondary device to verify effectiveness

### Adapter Testing
```bash
# Test packet injection capability
sudo aireplay-ng --test wlan0mon

# Should show: "Injection is working!"
```

## Technical Details

### Attack Mechanism
1. **Discovery Phase**: airodump-ng scans channels and discovers APs/clients
2. **Channel Hopping**: Cycles through selected channels every 3 seconds
3. **Packet Crafting**: Scapy creates IEEE 802.11 deauth/disassoc frames
4. **Multi-threading**: Multiple workers jam same channel simultaneously
5. **Bidirectional**: Packets sent from AP→Client and Client→AP

### Packet Types
- **Deauthentication**: 802.11 management frame (reason code configurable)
- **Disassociation**: Additional disruption frame
- **Broadcast deauth**: Sent to FF:FF:FF:FF:FF:FF (all clients)
- **Directed deauth**: Targeted to specific client MAC addresses

### Evasion Techniques
- MAC address randomization
- Configurable packet rates
- Multiple reason codes
- Adaptive channel switching

## Supported Adapters

### Confirmed Working
- Alfa AWUS036ACH (rtl8812au) - Recommended
- Alfa AWUS036NH (rtl8812au)
- Alfa AWUS036NHA (ar9271)
- TP-Link TL-WN722N v1 (ath9k_htc)
- Panda PAU09 (rtl8188eu)

### Driver Installation
```bash
# rtl8812au (Alfa AWUS036ACH)
git clone https://github.com/aircrack-ng/rtl8812au.git
cd rtl8812au
make
sudo make install

# ath9k_htc (usually included in kernel)
sudo apt install firmware-atheros
```

## Development

### Project Structure
```
wifijammer-pro/
├── wifijammer.py          # Main script
├── README.md              # This file
├── LICENSE                # BSD-3-Clause license
├── .gitignore             # Git ignore rules
└── venv/                  # Virtual environment (auto-created)
```

### Contributing
Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Test thoroughly
4. Submit a pull request

## Credits

- **Original inspiration**: [DanMcInerney/wifijammer](https://github.com/DanMcInerney/wifijammer)
- **Author**: S3rd4t4
- **Scapy**: Packet crafting library
- **aircrack-ng**: Wireless security suite

## License

This project is licensed under the **BSD-3-Clause License** - see the [LICENSE](LICENSE) file for details.

The BSD license allows:
- ✓ Commercial use
- ✓ Modification
- ✓ Distribution
- ✓ Private use

With conditions:
- Include copyright notice
- Include license text
- No trademark use

## Changelog

### Version 1.0 (2026-01-04)
- Initial public release
- Multi-threaded attack engine
- Display filters (F key)
- Channel mode selection
- Attack presets
- MAC vendor identification
- Real-time statistics
- Automatic dependency installation

## Support

For issues, questions, or feature requests:
- **GitHub Issues**: https://github.com/s3rd4t4/wifijammer-pro/issues
- **Repository**: https://github.com/s3rd4t4/wifijammer-pro

---

**Remember**: Always obtain explicit written permission before testing any network you don't own. Unauthorized access is illegal.
