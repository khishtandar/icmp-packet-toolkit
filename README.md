# icmp-packet-toolkit
Firewall Rule Management and ICMP Packet Generation Script
This Python script allows users to manage firewall rules using iptables and ip6tables for both IPv4 and IPv6, and generate ICMP packets using Scapy.

Features
Add custom firewall rules for IPv4 and IPv6 protocols.
Reset firewall rules to default settings.
Generate ICMP packets for network troubleshooting.
Supports both IPv4 and IPv6 addressing.
Prerequisites
Python 3.x
Scapy library (pip install scapy)
Linux environment (iptables and ip6tables)
Usage
Clone the repository to your local machine.
Ensure that you have Python 3.x installed.
Install the required dependencies using pip install -r requirements.txt.
Run the script using python firewall_management.py.
Follow the on-screen prompts to add firewall rules, reset firewall settings, or generate ICMP packets.
Important Notes
Make sure to run the script with administrative privileges (sudo python firewall_management.py) to execute iptables and ip6tables commands.
Exercise caution when adding or modifying firewall rules, as it may impact network connectivity.
For generating ICMP packets, provide valid source and destination IP addresses.
Author
Pouya Khishtandar

License
This project is licensed under the GPLv2 License.

