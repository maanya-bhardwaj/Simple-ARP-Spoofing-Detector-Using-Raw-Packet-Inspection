🛡️ ARP Spoofing Detector (Python + Scapy)

A simple real-time ARP Spoofing Detection tool built using Python and Scapy.
This project monitors ARP reply packets on a network and detects possible Man-in-the-Middle (MITM) attacks by identifying changes in IP-MAC address mappings.

What is ARP Spoofing?

ARP (Address Resolution Protocol) is used to map IP addresses to MAC addresses in a local network.

In an ARP spoofing attack:

An attacker sends fake ARP replies

The victim updates their ARP table with incorrect MAC mappings

Traffic gets redirected through the attacker (MITM attack)

This tool detects such malicious behavior.

Features:

Real-time ARP packet sniffing

Maintains dynamic IP → MAC mapping table

Detects MAC address changes for known IPs

Displays alert messages on spoof detection

Lightweight and easy to run

Technologies Used:

Python 3

Scapy (packet manipulation library)

Networking concepts (ARP protocol)

How It :

Sniffs ARP reply packets (op == 2)

Extracts:

Source IP address

Source MAC address

Stores IP–MAC mapping in a dictionary

If a known IP suddenly maps to a different MAC:

⚠️ Raises an ARP Spoofing alert

Installation
1️⃣ Clone the repository
git clone https://github.com/your-username/arp-spoofing-detector.git
cd arp-spoofing-detector

2️⃣ Install dependencies
pip install -r requirements.txt

▶️ How to Run

⚠️ Requires root/administrator privileges (because packet sniffing needs elevated access).

sudo python3 arp_detector.py


Press Ctrl + C to stop.

🖥️ Sample Output
🛡️  Starting ARP spoofing detector...
Press Ctrl+C to stop.

[INFO] New ARP entry: 192.168.1.1 → aa:bb:cc:dd:ee:ff

[ALERT] ARP Spoofing Detected!
 - IP: 192.168.1.1
 - MAC changed from aa:bb:cc:dd:ee:ff to 11:22:33:44:55:66

📂 Project Structure
arp-spoofing-detector/
│
├── arp_detector.py
├── README.md
├── requirements.txt
└── .gitignore

🔒 Use Cases

Educational cybersecurity projects

Network security learning

Basic intrusion detection systems

Understanding ARP protocol vulnerabilities

⚠️ Disclaimer

This project is intended for educational and defensive security purposes only.
Do not use it for unauthorized network monitoring.

📈 Future Improvements

Logging alerts to a file

Email notifications

Gateway protection mode

GUI dashboard

Packet rate anomaly detection

Maanya Bhardwaj 
Computer Networks Mini Project
