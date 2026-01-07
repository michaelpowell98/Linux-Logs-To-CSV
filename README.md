# Log Parser Tools

A collection of scripts designed to automate the extraction of data from Linux system logs into structured CSV files for easier digital forensics and incident response (DFIR) analysis.

## Scripts Included

* **auth_parser.py**: Extracts timestamps, hostnames, and event details from `/var/log/auth.log`.
* **ufw_parser.py**: Parses Uncomplicated Firewall (UFW) logs to identify blocked/allowed IPs and ports.

## Why I Built This
Manual log analysis is time-consuming. These tools were created to bridge the gap between raw text logs and structured data analysis in tools like Timeline Explorer or ingested into a SIEM.

## How to Use
1. Place your log files in the same directory as the scripts.
2. Run the script via terminal:
   ```bash
   python3 ufw_parser.py
