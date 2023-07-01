from scapy.all import *
import base64

pcap_file = 'stegano.pcap'
packets = rdpcap(pcap_file)

payload_chars = []
for packet in packets:
    if Raw in packet:
        payload_chars.append(packet[Raw].load.decode())

base64_payload = ''.join(payload_chars)
print("Reconstructed base64 payload:", base64_payload)
