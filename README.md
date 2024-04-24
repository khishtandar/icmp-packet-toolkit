# icmp-packet-toolkit
# Network Firewall and ICMP Packet Management Toolkit

This Python script provides a comprehensive toolkit for managing network firewall rules using iptables and ip6tables for both IPv4 and IPv6 protocols. Additionally, it offers functionalities to generate ICMP packets using the Scapy library, facilitating network troubleshooting and analysis.

## Features

- **Firewall Rule Management**: Add custom firewall rules, reset firewall settings to default, and enable/disable iptables service.
- **IPv4 and IPv6 Support**: Supports both IPv4 and IPv6 protocols for managing firewall rules.
- **ICMP Packet Generation**: Generate ICMP packets with customizable parameters for network troubleshooting.
- **User-friendly Interface**: Simple command-line interface with interactive prompts for ease of use.

## Prerequisites

- Python 3.x
- Scapy library (`pip install scapy`)
- Linux environment with iptables and ip6tables installed

## Usage

1. Clone the repository to your local machine.
2. Install the required dependencies using `pip install -r requirements.txt`.
3. Run the script using `python icmp-toolkit.py`.
4. Follow the on-screen prompts to perform firewall rule management or generate ICMP packets.

## Important Notes

- Ensure that you run the script with administrative privileges (`sudo python firewall_management.py`) to execute iptables and ip6tables commands.
- Exercise caution when adding or modifying firewall rules, as it may impact network connectivity.

## Author
## Pouya Khishtandar

License
This project is licensed under the GPLv2 License.

