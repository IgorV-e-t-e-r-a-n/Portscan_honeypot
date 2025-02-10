from scapy.all import Ether, IP, TCP, UDP, IPv6, sendp, sniff

ip = "172.26.32.1"
ports = [53, 80]
honeys = [8080, 6443]
blocked = []

def analyzePackets(p):
    global blocked

    if p.haslayer(IP):
        response = Ether(src=p[Ether].dst, dst=p[Ether].src) / \
                   IP(src=p[IP].dst, dst=p[IP].src) / \
                   TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq + 1)
        source = p[IP].src

    elif p.haslayer(IPv6):
        response = Ether(src=p[Ether].dst, dst=p[Ether].src) / \
                   IPv6(src=p[IPv6].dst, dst=p[IPv6].src) / \
                   TCP(sport=p[TCP].dport, dport=p[TCP].sport, ack=p[TCP].seq + 1)
        source = p[IPv6].src

    else:
        return  # Ignore packets without IP or IPv6

    if not p.haslayer(TCP) or p[TCP].flags != "S":
        return  # Ignore non-TCP packets or non-SYN packets

    port = p[TCP].dport

    if source in blocked:
        if port in ports:
            response[TCP].flags = "RA"  # Sending reset packet
            print("Sending reset (RA)")
    elif port in honeys:
        response[TCP].flags = "SA"  # Simulating an open port
    else:
        return

    sendp(response, verbose=False)

    if source not in blocked and port not in ports:
        blocked.append(source)
        if port in honeys:
            response[TCP].flags = "SA"
        sendp(response, verbose=False)

# Sniff incoming packets on the specified host
filter_exp = f"dst host {ip} and tcp"
sniff(filter=filter_exp, prn=analyzePackets)
