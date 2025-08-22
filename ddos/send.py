#!/usr/bin/env python3
from scapy.all import *
from scapy.utils import rdpcap
file1="attacks/Test_Benign_1.pcap"
file2="attacks/Test_TCP_Flood.pcap"
file3="attacks/Tes_UDP_Flood.pcap"
file4="attacks/Test_ACK_Frag.pcap"
file5="attacks/Test_PSHACK.pcap"
file6="attacks/Test_RSTFIN_Flood_2.pcap"
file7="attacks/Test_SYN.pcap"
file8="attacks/Test_UDP-Frag.pcap"
file9="attacks/Test_HTTP_Flood.pcap"
file10="attacks/Test_Slowloris_1.pcap"
'''
file11="attacks/BenignPart1_0.pcap"
file12="attacks/Benign_1MB_1.pcap"
file13="attacks/Benign_1MB_2.pcap"
file14="attacks/Test_Benign_2.pcap"
'''

pkts=rdpcap(file3)
# use 1 for udp and tcp, 2 for tcp, 3 for udp
protocol = 3;
count = 0;
iface='eth0';
large_mtu=0;

for pkt in pkts:
	if(len(pkt) > 1520):
		large_mtu = large_mtu + 1;
	else:
		if IP in pkt:
			count = count + 1;
			if ((protocol == 1 or protocol==2) and TCP in pkt):
				pkt[Ether].dst=  '08:00:00:00:01:11'
				sendp(pkt, iface=iface, verbose=False)
				if(count > 1000):
					break;
			if ((protocol == 1 or protocol==3) and UDP in pkt):
				pkt[Ether].dst=  '08:00:00:00:01:11'
				sendp(pkt, iface=iface, verbose=False)
				if(count > 1000):
					break;
print(str(count)+" packets sent, large mtu packets are: "+str(large_mtu))

