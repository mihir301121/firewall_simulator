from scapy.all import *
from datetime import datetime

# Define a dictionary to store the firewall rules
rules = {
    "allow": [],
    "deny": []
}

# Define a dictionary to store the number of denied attempts for each IP address
denied_attempts = {}

# Define a dictionary to store the log entries
log = []

def load_rules_from_file(filename):
    """Load firewall rules from a file."""
    global rules
    try:
        with open(filename, "r") as file:
            for line in file:
                parts = line.strip().split(",")
                action = parts[0].strip().lower()
                if action == "allow" or action == "deny":
                    rule = {
                        "action": action,
                        "src_ip": parts[1].strip(),
                        "dst_ip": parts[2].strip(),
                        "protocol": parts[3].strip().lower(),
                        "port": int(parts[4].strip()) if parts[4].strip() != "*" else None
                    }
                    rules[action].append(rule)
    except FileNotFoundError:
        print("Rules file not found.")

def save_rules_to_file(filename):
    """Save firewall rules to a file."""
    global rules
    with open(filename, "w") as file:
        for action, rule_list in rules.items():
            for rule in rule_list:
                file.write(f"{action.upper()}, {rule['src_ip']}, {rule['dst_ip']}, {rule['protocol'].upper()}, {rule['port'] if rule['port'] else '*'}\n")

def packet_callback(packet):
    """Callback function for processing packets."""
    global denied_attempts, log

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        # Check if the packet matches any rule
        for rule in rules["allow"] + rules["deny"]:
            if (rule["src_ip"] == "*" or rule["src_ip"] == src_ip) and \
               (rule["dst_ip"] == "*" or rule["dst_ip"] == dst_ip) and \
               (rule["protocol"] == "*" or rule["protocol"] == protocol) and \
               (rule["port"] is None or (TCP in packet and packet[TCP].dport == rule["port"]) or (UDP in packet and packet[UDP].dport == rule["port"])):
                if rule["action"] == "allow":
                    log.append(f"{datetime.now()} ALLOW {src_ip} -> {dst_ip} ({protocol})")
                    send(packet, verbose=0)  # Send the packet
                else:
                    log.append(f"{datetime.now()} DENY {src_ip} -> {dst_ip} ({protocol})")
                    # Increment the denied attempts counter for the source IP
                    denied_attempts[src_ip] = denied_attempts.get(src_ip, 0) + 1
                    if denied_attempts[src_ip] >= 3:
                        log.append(f"{datetime.now()} BLOCK {src_ip}")
                        # Implement IP blocking logic here (not implemented in this example)
                return

        log.append(f"{datetime.now()} ALLOW (DEFAULT) {src_ip} -> {dst_ip} ({protocol})")
        send(packet, verbose=0)  # Allow packet by default

def main():
    load_rules_from_file("firewall_rules.txt")
    sniff(prn=packet_callback, store=0)
    save_rules_to_file("firewall_rules.txt")

if __name__ == "__main__":
    main()
