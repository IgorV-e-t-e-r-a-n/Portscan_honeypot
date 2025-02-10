# Portscan + Honeypot

## Overview
Portscan Honeypot is a Python-based network security tool designed to detect and respond to unauthorized port scanning attempts. It identifies potential threats by monitoring incoming packets and responding selectively to deceive attackers.

## Features
- **Passive and Active Detection**: Monitors network traffic to identify port scans.
- **Honeypot Ports**: Mimics open services to lure attackers.
- **Response Mechanism**: Sends fake SYN-ACK or RST packets based on detected behavior.
- **IP Blacklisting**: Blocks repeated offenders dynamically.
- **IPv4 & IPv6 Support**: Handles traffic across both protocols.
- **Scapy-Based Packet Analysis**: Uses Scapy for deep packet inspection.

## Technologies Used
- **Python**: Core programming language.
- **Scapy**: For packet manipulation and network monitoring.
- **dnslib**: Resolves domain names for reverse lookup.
- **IPTables (Optional)**: Can be used for real-time blocking.

## Installation
```sh
"git clone https://github.com/IgorV-e-t-e-r-a-n/Portscan_honeypot.git"
"cd portscan-honeypot"
```

## Usage
``` sh
python honeypot.py
```
- **Start Monitoring:** The honeypot will listen for port scans.
- **Analyze Logs:** Captured scan attempts and attacker details will be displayed.
- **Blacklist Attackers:** Configure automated blocking for persistent threats.

## Roadmap

  Implement logging to a database
  Add real-time visualization using a web dashboard.
  Expand honeypot capabilities with additional fake services.

## Contribution

Feel free to submit issues, feature requests, or pull requests to improve the project
