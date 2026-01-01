Markdown

# 🛡️ KALI SHIELD PRO v2.0
### **Enterprise-Grade Cyberpunk Firewall & Forensic Monitor**
**Developed by:** [Sumit Sharma] 🚀



---

## 📖 Overview
**KALI SHIELD PRO** is a professional-grade Blue Team security tool designed for **SOC (Security Operations Center)** analysts and network defenders. It provides a real-time, high-visibility interface to monitor network traffic, intercept malicious packets, and maintain a persistent "blacklist" of attackers.

Built specifically for the Kali Linux ecosystem, it bridges the gap between raw `iptables` commands and a modern forensic dashboard.

---

## ✨ Features
* **Cyberpunk Aesthetics:** Pure Black and Neon Green theme optimized for low-light SOC environments.
* **Kernel Integration:** Direct communication with the Linux `netfilter` (iptables) for zero-latency packet dropping.
* **Forensic Session Isolation:** Every "Stop" action generates a new, timestamped `.log` file in the `logs/` directory.
* **Live Jail View:** A dedicated sidebar shows every IP currently blocked by the system in real-time.
* **Persistent Rules:** Blocked IPs are saved to `core/rules.json`, ensuring your protection survives a reboot.

---

## 🚀 Installation & Setup

### **1. Prerequisites**
This tool is designed for **Kali Linux**. Ensure you have Python 3 and `iptables` installed:
```bash
sudo apt update
sudo apt install python3-pip iptables -y
2. Install Dependencies
Install the required Python libraries using the following command:

Bash

pip install scapy customtkinter --break-system-packages
3. Launch the Firewall
Because this tool modifies kernel network rules, it must be run with root privileges:

Bash

sudo python3 firewall.py
🎮 How to Use (Operator Guide)
The Monitoring Workflow
▶ START SCAN: Click this to begin the overwatch. The system will start sniffing all local network traffic.

IP BAN HAMMER: If you see a suspicious IP in the logs, type it into the "Target IP" box.

BLOCK / UNBLOCK: Click BLOCK to immediately cut off that IP's access. The IP will appear in the ACTIVE DEFENSES list on the left.

⏹ STOP & SAVE: Click this to end your shift. The system will bundle all traffic data from that session into a forensic log file.

Navigating the Logs
Location: All logs are saved in the /logs folder within the project directory.

Format: firewall_YYYY-MM-DD_HH-MM-SS.log

🛠 SOC Analysis Tip
As a Blue Team Analyst, use this tool to watch for "Connection Refused" patterns. If an IP is hitting your system repeatedly on different ports, use the BLOCK button to instantly neutralize the threat before they find a vulnerability.

👤 Credits
Lead Developer: Sumit Sharma

Role: Cyber Security Researcher & Tool Developer

Project: Kali Shield Pro - Network Defense Suite

Disclaimer: This tool is for educational and authorized security testing purposes only. Ensure you have permission before monitoring networks you do not own.

Use Case: These logs are perfect for Blue Team audits. You can open them in any text editor or ingest them into a SIEM (like Splunk or ELK) to analyze attack patterns like port scanning or DDoS attempts.
