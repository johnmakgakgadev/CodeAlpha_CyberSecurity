#Building a Python program to capture network traffic packets.
#libraries  
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

#Analyzing captured packets to understand their structure and content.
def process_packet(packet):
    print(f"\n=== Packet Captured @ {datetime.now().strftime('%H:%M:%S')} ===")
    
    #Displaying useful information such as source/destination IPs, protocols and payloads.
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")
        print(f"Protocol       : {ip_layer.proto}")
        
        # Check for transport layer protocols
        if TCP in packet:
            tcp_layer = packet[TCP]
            print("Protocol Type  : TCP")
            print(f"Source Port    : {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print("Protocol Type  : UDP")
            print(f"Source Port    : {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
        elif ICMP in packet:
            print("Protocol Type  : ICMP")
        
        # Raw payload
        if Raw in packet:
            payload = packet[Raw].load
            print(f"Payload        : {payload[:50]}...")  # show only first 50 bytes
    else:
        print("Non-IP Packet Captured")

# Capture packets (adjust iface and count as needed)
print("Starting packet capture... (Press Ctrl+C to stop)\n")
sniff(prn=process_packet, store=False)