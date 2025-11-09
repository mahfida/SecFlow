#!/usr/bin/env python3
import sys
import struct, socket
import os, re, time
import pickle
#import sklearn as sk
import csv
from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, ByteField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR
import locale

packet_count =0;
filename = "delay.csv"
#------- RECIEVE PACKET -----------------------------------
class IPOption_OriginalIP(IPOption):
        name = "Telemetry"
        option = 31
        fields_desc = [ _IPOption_HDR,
                    ByteField("length",2),
                    BitField("orignal_srcIP",0,32),
		    BitField("orignal_dstIP",0,32),
                    BitField("spkts", 0, 16),
		    BitField("dpkts", 0, 16),
 		    BitField("attack_packet", 0, 16)]

def append_row_to_csv(row, filename=filename):
    """Append a single row to a CSV file."""
    with open(filename, mode='a') as file:
        writer = csv.writer(file)
        writer.writerow(row)
def handle_pkt(pkt):
	global packet_count;
	# Count number of packets recieved
	packet_count = packet_count + 1;
	# Use following code, if you want to scan the IPOptions header
	if(IP in pkt and '10.0.3.3' in pkt[IP].dst and  pkt[IP].version == 4):
	    	#pkt.show();
		telemetry = str(pkt[IP].options)
		match = re.search('spkts=(.*)dpkts', telemetry)
		if match:
			delay = match.group(1)
			print(delay+" , "+ str(packet_count))
			append_row_to_csv([delay])
	
def main():
        ifaces = list(filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/')))
        iface = ifaces[0]
        print("sniffing on %s" % iface)
        sys.stdout.flush()
        sniff(iface = iface,
                 prn = lambda x: handle_pkt(x))
	
if __name__ == '__main__':
        main()
	#STORAGE_FILE.close();
