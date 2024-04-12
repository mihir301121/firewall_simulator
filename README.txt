Firewall Simulator using Scapy

This Python script implements a basic firewall simulator using the Scapy library. 
The firewall can be configured with rules to allow or deny packets based on criteria such 
as source IP, destination IP, protocol, and port.

Features:

Supports both allow and deny rules.
Rules can be loaded from and saved to a file.
Logs actions taken for each packet.
Blocks IP addresses after a certain number of denied attempts (not fully implemented).

How to Run:

1.Dependencies:
Install Scapy library: pip install scapy

2.Prepare Rules File:
Create a file named firewall_rules.txt with rules in the format:

ACTION, SRC_IP, DST_IP, PROTOCOL, PORT

3.Run the Firewall Simulator:

Open a terminal and navigate to the directory containing the script.
Run the following command to start the firewall simulator:

python firewall_simulator.py

4.Usage:

Modify the firewall_rules.txt file to update rules during runtime.
Press Ctrl+C to stop the firewall simulator.

5.Customization:

Implement IP blocking logic in the packet_callback function for more advanced features.


