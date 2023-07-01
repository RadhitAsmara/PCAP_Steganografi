from scapy.all import *

output_file = 'output.pcap'
packets = []

ethernet = Ether(dst='00:11:22:33:44:55', src='aa:bb:cc:dd:ee:ff')
payload = "This is secret message!!!"

for i in range(200):
    ip = IP(src=f'192.168.1.{i+1}', dst=f'192.168.2.{i+1}')
    if i % 4 == 0:
        tcp = TCP(sport=12345+i, dport=80+i)
        packet = ethernet / ip / tcp / payload
    elif i % 4 == 1:
        udp = UDP(sport=54321+i, dport=1234+i)
        packet = ethernet / ip / udp / payload
    elif i % 4 == 2:
        packet = ethernet / ip / ICMP() / payload
    else:
        dns = DNS(qd=DNSQR(qname=f"example{i+1}.com"))
        packet = ethernet / ip / UDP(sport=53, dport=12345+i) / dns

    packets.append(packet)
wrpcap(output_file, packets)
