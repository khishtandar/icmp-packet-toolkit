import subprocess
from scapy.all import *
import time

def create_iptables_rule_ipv4(icmp_type, change_source_ip):
    # Define the base iptables command for IPv4
    iptables_command = ['sudo', 'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '23', '-j', 'REJECT']

    # Add the --reject-with option based on the selected ICMP type
    iptables_command.extend(['--reject-with', icmp_type])

    # If change_source_ip is True, add the --reject-source option to change the source IP address of ICMP
    if change_source_ip:
        iptables_command.extend(['--reject-source', '1.2.3.4'])  # Change the IP address as needed

    # Execute the iptables command
    subprocess.run(iptables_command)

def create_iptables_rule_ipv6(icmp_type, change_source_ip):
    # Define the base ip6tables command for IPv6
    ip6tables_command = ['sudo', 'ip6tables', '-A', 'INPUT', '-p', 'tcp', '--dport', '23', '-j', 'REJECT']

    # Add the --reject-with option based on the selected ICMP type
    ip6tables_command.extend(['--reject-with', icmp_type])

    # If change_source_ip is True, add the --reject-source option to change the source IP address of ICMP
    if change_source_ip:
        ip6tables_command.extend(['--reject-source', '::1'])  # Change the IP address as needed

    # Execute the ip6tables command
    subprocess.run(ip6tables_command)

def reset_iptables_rules():
    # Flush all rules in IPv4 tables
    subprocess.run(['sudo', 'iptables', '-F'])
    subprocess.run(['sudo', 'iptables', '-X'])
    subprocess.run(['sudo', 'iptables', '-Z'])

    # Set default policy to ACCEPT for IPv4
    subprocess.run(['sudo', 'iptables', '-P', 'INPUT', 'ACCEPT'])
    subprocess.run(['sudo', 'iptables', '-P', 'FORWARD', 'ACCEPT'])
    subprocess.run(['sudo', 'iptables', '-P', 'OUTPUT', 'ACCEPT'])

    # Flush all rules in IPv6 tables
    subprocess.run(['sudo', 'ip6tables', '-F'])
    subprocess.run(['sudo', 'ip6tables', '-X'])
    subprocess.run(['sudo', 'ip6tables', '-Z'])

    # Set default policy to ACCEPT for IPv6
    subprocess.run(['sudo', 'ip6tables', '-P', 'INPUT', 'ACCEPT'])
    subprocess.run(['sudo', 'ip6tables', '-P', 'FORWARD', 'ACCEPT'])
    subprocess.run(['sudo', 'ip6tables', '-P', 'OUTPUT', 'ACCEPT'])

def enable_iptables_service():
    # Start iptables service
    subprocess.run(['sudo', 'systemctl', 'start', 'iptables'])

def get_iptables_rules():
    # Get iptables rules for IPv4
    iptables_ipv4_output = subprocess.run(['sudo', 'iptables', '-S'], capture_output=True, text=True).stdout.strip()

    # Get iptables rules for IPv6
    ip6tables_ipv6_output = subprocess.run(['sudo', 'ip6tables', '-S'], capture_output=True, text=True).stdout.strip()

    return iptables_ipv4_output, ip6tables_ipv6_output


import time

def generate_icmp_packets():
    # Ask for ICMP version
    print("ICMP Packet Generation")
    print("Choose the ICMP version:")
    print("1. ICMP (IPv4)")
    print("2. ICMPv6 (IPv6)")
    icmp_version_choice = input("Enter your choice (1-2): ")

    if icmp_version_choice == '1':
        # Create IPv4 ICMP packet
        print("\nGenerating IPv4 ICMP packet:")
        src_ip = input("Enter source IP address: ")
        dst_ip = input("Enter destination IP address: ")

        # Prompt the user to choose ICMP type with description or number
        print("\nChoose the type of ICMP message to use for IPv4:")
        print("0. Echo Reply (Ping Response)")
        print("3. Destination Unreachable: Indicates that the packet cannot be delivered to the destination.")
        print("8. Echo Request (Ping)")
        icmp_type_choice = input("Enter your choice (0, 3, 8) or type: ")

        # ICMP type and description mapping for IPv4
        icmp_types_ipv4 = {
            '0': ('Echo Reply', 'No Code - Used for Echo Reply or Echo Request messages.'),
            '3': ('Destination Unreachable', 'Indicates that the packet cannot be delivered to the destination.'),
            '8': ('Echo Request', 'No Code - Used for Echo Reply or Echo Request messages.')
        }

        if icmp_type_choice in icmp_types_ipv4:
            selected_type, type_description = icmp_types_ipv4[icmp_type_choice]
            print(f"ICMP Type {icmp_type_choice}: {selected_type} - {type_description}")
        else:
            print("Invalid ICMP type choice. Exiting.")
            return

        # Prompt the user to choose ICMP code with description or number
        if icmp_type_choice == '3':
            print("\nChoose the ICMP code for Destination Unreachable:")
            print("0. Network Unreachable: The destination network is unreachable.")
            print("1. Host Unreachable: The destination host is unreachable.")
            print("2. Protocol Unreachable: The protocol in the IP header is not supported.")
            print("3. Port Unreachable: The transport protocol (e.g., TCP, UDP) port is unreachable.")
            icmp_code_choice = input("Enter your choice (0-3) or type: ")
        else:
            icmp_code_choice = '0'  # Default code for other ICMP types

        print(f"ICMP Code: {icmp_code_choice}")

        # Create ICMP packet
        icmp_packet = IP(src=src_ip, dst=dst_ip)/ICMP(type=int(icmp_type_choice), code=int(icmp_code_choice))

        # Print information about the generated ICMP packet
        print("\nGenerated ICMP Packet Information:")
        print(f"Source IP Address: {src_ip}")
        print(f"Destination IP Address: {dst_ip}")
        print(f"ICMP Type: {icmp_type_choice} ({selected_type})")
        print(f"ICMP Code: {icmp_code_choice}")
        print(f"ICMP Description: {type_description}")

        # Send 5 IPv4 ICMP packets with an interval of 2 seconds
        for i in range(5):
            send(icmp_packet)
            print(f"IPv4 ICMP packet {i+1} sent successfully.")
            time.sleep(2)

    
    elif icmp_version_choice == '2':
        # Create IPv6 ICMPv6 packet
        print("\nGenerating IPv6 ICMPv6 packet:")
        src_ip = input("Enter source IPv6 address: ")
        dst_ip = input("Enter destination IPv6 address: ")

        # Prompt the user to choose ICMPv6 type with description or number
        print("\nChoose the type of ICMPv6 message to use for IPv6:")
        print("128. Echo Request (Ping)")
        print("129. Echo Reply (Ping Response)")
        print("133. Router Solicitation: Sent by hosts to request the IP address of routers.")
        print("134. Router Advertisement: Sent by routers in response to a Router Solicitation message.")
        print("135. Neighbor Solicitation: Used by IPv6 nodes to resolve the MAC address of another IPv6 node.")
        print("136. Neighbor Advertisement: Sent in response to a Neighbor Solicitation message.")
        print("137. Redirect Message: Used by routers to inform a host of a better first-hop IPv6 address.")
        print("1. Destination Unreachable: Indicates that the destination is unreachable.")
        print("2. Packet Too Big: Indicates that the packet is too big to be forwarded.")
        print("3. Time Exceeded: Indicates that the time to live (TTL) has expired.")
        print("4. Parameter Problem: Indicates a problem with a header field.")
        icmpv6_type_choice = input("Enter your choice (128, 129, 133, 134, 135, 136, 137, 1, 2, 3, 4) or type: ")

        # ICMPv6 type and description mapping for IPv6
        icmpv6_types_ipv6 = {
            '128': ('Echo Request', 'No Code - Used for Echo Reply or Echo Request messages.'),
            '129': ('Echo Reply', 'No Code - Used for Echo Reply or Echo Request messages.'),
            '133': ('Router Solicitation', 'Sent by hosts to request the IP address of routers.'),
            '134': ('Router Advertisement', 'Sent by routers in response to a Router Solicitation message.'),
            '135': ('Neighbor Solicitation', 'Used by IPv6 nodes to resolve the MAC address of another IPv6 node.'),
            '136': ('Neighbor Advertisement', 'Sent in response to a Neighbor Solicitation message.'),
            '137': ('Redirect Message', 'Used by routers to inform a host of a better first-hop IPv6 address.'),
            '1': ('Destination Unreachable', 'Indicates that the destination is unreachable.'),
            '2': ('Packet Too Big', 'Indicates that the packet is too big to be forwarded.'),
            '3': ('Time Exceeded', 'Indicates that the time to live (TTL) has expired.'),
            '4': ('Parameter Problem', 'Indicates a problem with a header field.')
        }

        if icmpv6_type_choice in icmpv6_types_ipv6:
            selected_type, type_description = icmpv6_types_ipv6[icmpv6_type_choice]
            print(f"ICMPv6 Type {icmpv6_type_choice}: {selected_type} - {type_description}")
        else:
            print("Invalid ICMPv6 type choice. Exiting.")
            return

        # Prompt the user to choose ICMPv6 code with description or number
        icmpv6_code_choice = '0'  # Default code for ICMPv6
        print(f"ICMPv6 Code: {icmpv6_code_choice}")

        # Create ICMPv6 packet based on type selected
        if icmpv6_type_choice == '128':  # Echo Request
            icmpv6_packet = IPv6(src=src_ip, dst=dst_ip)/ICMPv6EchoRequest()
        elif icmpv6_type_choice == '129':  # Echo Reply
            icmpv6_packet = IPv6(src=src_ip, dst=dst_ip)/ICMPv6EchoReply()
        elif icmpv6_type_choice == '1':  # Destination Unreachable
            icmpv6_packet = IPv6(src=src_ip, dst=dst_ip)/ICMPv6DestUnreach()
        elif icmpv6_type_choice == '2':  # Packet Too Big
            icmpv6_packet = IPv6(src=src_ip, dst=dst_ip)/ICMPv6PacketTooBig()
        elif icmpv6_type_choice == '3':  # Time Exceeded
            icmpv6_packet = IPv6(src=src_ip, dst=dst_ip)/ICMPv6TimeExceeded()
        elif icmpv6_type_choice == '4':  # Parameter Problem
            icmpv6_packet = IPv6(src=src_ip, dst=dst_ip)/ICMPv6ParamProblem()
        elif icmpv6_type_choice == '137':  # Redirect Message
            icmpv6_packet = IPv6(src=src_ip, dst=dst_ip)/ICMPv6ND_Redirect()
        else:
            print("Invalid ICMPv6 type choice. Exiting.")
            return

        # Print information about the generated ICMPv6 packet
        print("\nGenerated ICMPv6 Packet Information:")
        print(f"Source IPv6 Address: {src_ip}")
        print(f"Destination IPv6 Address: {dst_ip}")
        print(f"ICMPv6 Type: {icmpv6_type_choice} ({selected_type})")
        print(f"ICMPv6 Code: {icmpv6_code_choice}")
        print(f"ICMPv6 Description: {type_description}")

        # Send 5 IPv6 ICMPv6 packets with an interval of 2 seconds
        for i in range(5):
            send(icmpv6_packet)
            print(f"IPv6 ICMPv6 packet {i+1} sent successfully.")
            time.sleep(2)

    else:
        print("Invalid choice. Exiting.")

def main():
    # Prompt the user to choose whether to add a rule, reset the firewall, or generate ICMP packets
    print("Choose an action:")
    print("1. Add a rule")
    print("2. Reset firewall to default settings")
    print("3. Generate ICMP packets")
    action_choice = input("Enter your choice (1-3): ")

    if action_choice == '1':
        # Prompt the user to choose between IPv4 and IPv6
        print("Choose the protocol:")
        print("1. IPv4")
        print("2. IPv6")
        protocol_choice = input("Enter your choice (1-2): ")

        if protocol_choice == '1':
            # Prompt the user to choose the ICMP type for IPv4
            print("Choose the type of ICMP message to use for IPv4:")
            print("1. Network Unreachable")
            print("2. Host Unreachable")
            print("3. Protocol Unreachable")
            print("4. Port Unreachable")
            print("5. Communication Administratively Prohibited (Network)")
            print("6. Communication Administratively Prohibited (Host)")
            print("7. Communication Administratively Prohibited (Administrative Filtering)")
            icmp_choice = input("Enter your choice (1-7): ")

            # Map the user's choice to the corresponding ICMP type for IPv4
            icmp_types = {
                '1': 'icmp-net-unreachable',
                '2': 'icmp-host-unreachable',
                '3': 'icmp-proto-unreachable',
                '4': 'icmp-port-unreachable',
                '5': 'icmp-net-prohibited',
                '6': 'icmp-host-prohibited',
                '7': 'icmp-admin-prohibited'
            }
            selected_icmp_type = icmp_types.get(icmp_choice)
            if not selected_icmp_type:
                print("Invalid choice. Exiting.")
                return

            # Create the iptables rule for IPv4
            create_iptables_rule_ipv4(selected_icmp_type, False)  # No option to change source IP for IPv4

            # Start iptables service
            enable_iptables_service()

            print("IPv4 iptables rule created successfully.")

        elif protocol_choice == '2':
            # Prompt the user to choose the ICMP type for IPv6
            print("Choose the type of ICMP message to use for IPv6:")
            print("1. No Route to Destination")
            print("2. Communication with Destination Administratively Prohibited")
            print("3. Beyond Scope of Source Address")
            print("4. Address Unreachable")
            print("5. Port Unreachable")
            print("6. Hop Limit Exceeded in Transit")
            print("7. Fragment Reassembly Time Exceeded")
            print("8. Erroneous Header Field Encountered")
            print("9. Packet Too Big")
            print("10. Router Solicitation (Neighbor Discovery)")
            print("11. Router Advertisement (Neighbor Discovery)")
            print("12. Neighbor Solicitation (Neighbor Discovery)")
            print("13. Neighbor Advertisement (Neighbor Discovery)")
            print("14. Redirect Message (Route Redirection)")
            ipv6_icmp_choice = input("Enter your choice (1-14): ")

            # Map the user's choice to the corresponding ICMP type for IPv6
            ipv6_icmp_types = {
                '1': 'icmp6-no-route',
                '2': 'icmp6-admin-prohibited',
                '3': 'icmp6-beyond-scope',
                '4': 'icmp6-address-unreachable',
                '5': 'icmp6-port-unreachable',
                '6': 'icmp6-exceeded-hop-limit',
                '7': 'icmp6-exceeded-reassembly',
                '8': 'icmp6-param-problem',
                '9': 'icmp6-packet-too-big',
                '10': 'icmp6-router-solicitation',
                '11': 'icmp6-router-advertisement',
                '12': 'icmp6-neighbor-solicitation',
                '13': 'icmp6-neighbor-advertisement',
                '14': 'icmp6-redirect'
            }
            selected_ipv6_icmp_type = ipv6_icmp_types.get(ipv6_icmp_choice)
            if not selected_ipv6_icmp_type:
                print("Invalid choice. Exiting.")
                return

            # Create the iptables rule for IPv6
            create_iptables_rule_ipv6(selected_ipv6_icmp_type, False)  # No option to change source IP for IPv6

            print("IPv6 iptables rule created successfully.")

        else:
            print("Invalid choice. Exiting.")

    elif action_choice == '2':
        # Reset the firewall to default settings
        reset_iptables_rules()
        print("Firewall reset to default settings successfully.")

    elif action_choice == '3':
        # Generate ICMP packets using Scapy
        generate_icmp_packets()

    else:
        print("Invalid choice. Exiting.")

    # Display current iptables rules
    iptables_ipv4_rules, ip6tables_ipv6_rules = get_iptables_rules()
    print("\nCurrent IPv4 iptables rules:")
    print(iptables_ipv4_rules)
    print("\nCurrent IPv6 ip6tables rules:")
    print(ip6tables_ipv6_rules)

if __name__ == "__main__":
    main()
