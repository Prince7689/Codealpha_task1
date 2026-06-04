from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def process_packet(packet):

    print("\n" + "=" * 60)

    # Check if packet has IP layer
    if packet.haslayer(IP):

        ip_layer = packet[IP]

        print(f"[+] Source IP        : {ip_layer.src}")
        print(f"[+] Destination IP   : {ip_layer.dst}")
        print(f"[+] Protocol         : {ip_layer.proto}")

        # TCP
        if packet.haslayer(TCP):

            tcp_layer = packet[TCP]

            print(f"[+] TCP Source Port : {tcp_layer.sport}")
            print(f"[+] TCP Dest Port   : {tcp_layer.dport}")

        # UDP
        elif packet.haslayer(UDP):

            udp_layer = packet[UDP]

            print(f"[+] UDP Source Port : {udp_layer.sport}")
            print(f"[+] UDP Dest Port   : {udp_layer.dport}")

        # ICMP
        elif packet.haslayer(ICMP):

            print("[+] ICMP Packet Detected")

        # Payload
        if packet.haslayer(Raw):

            payload = packet[Raw].load

            try:
                print(f"[+] Payload Data:\n{payload.decode(errors='ignore')}")
            except:
                print("[+] Unable to decode payload")

    print("=" * 60)


print("Starting Network Sniffer...")
print("Press CTRL + C to stop.\n")

# Start sniffing
sniff(prn=process_packet, store=False)