from scapy.all import *
import base64

output_file = 'stegano.pcap'
packets = []

ethernet = Ether(dst='00:11:22:33:44:55', src='aa:bb:cc:dd:ee:ff')
base64_payload = "VGhpcyBpcyBzZWNyZXQgbWVzc2FnZSEhIQ=="

for i in range(len(base64_payload)):
    ip = IP(src=f'192.168.1.{i+1}', dst=f'192.168.2.{i+1}')
    char = base64_payload[i]
    if i % 4 == 0:
        tcp = TCP(sport=12345+i, dport=80+i)
        packet = ethernet / ip / tcp / char
    elif i % 4 == 1:
        udp = UDP(sport=54321+i, dport=1234+i)
        packet = ethernet / ip / udp / char
    elif i % 4 == 2:
        packet = ethernet / ip / ICMP() / char
    else:
        dns = DNS(qd=DNSQR(qname=f"example{i+1}.com"))
        packet = ethernet / ip / UDP(sport=53, dport=12345+i) / dns / char

    packets.append(packet)
wrpcap(output_file, packets)
