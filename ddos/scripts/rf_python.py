#!/usr/bin/env python
import sys
import struct, socket
import os, re, time
import pickle
import sklearn as sk
import pandas as pd

import numpy as np
from sklearn import tree 
#from sklearn.tree import export_text
#from sklearn.tree import _tree
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import RandomForestRegressor

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, ByteField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

# FLAGS
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

# USED FOR FLAGS
STATE_INT=1;
STATE_FIN=2;
STATE_REQ=3;
STATE_CON=4;
STATE_ACC=5;
STATE_CLO=6;
STATE_EST=7;

# USED IN PROCESSPACKET
register_index=0;
dur=0;
is_first=0;
is_empty=0;
first_ack=0;
state=0;
ct_state_ttl=0;
malware=0;
marked_malware=0;

# Sum of TCP connection setup time: sum of synack and ackdat time
# reg_ct_srv_dst = 0;  # Number of connections that contain the same service and srcip in last 100 connections
# Note that only 8 possibilities: http, ftp, smtp, ssh, dns, ftp - data, irc
# and (-) if not much used service
# Register not needed for dsport, dttl, Dpkts, dmeansz, Dload
# will be obtained by reversing the src - dst tuple

# Store some statistics for the packets-----
counter_pkts = 0;
counter_malware = 0;
counter_true_detection = 0;
counter_false_detection = 0;
# Store some statistics for the flows--------
counter_flows = 0;
counter_malware_flows = 0;
counter_true_detection_flows = 0;
counter_false_detection_flows = 0;
counter_timeout = 0;
time_first_pkt=0.0;
dur = 0.0;
tcprtt=0.0;
# Registers as Python Lists -----------------
reg_time_first_pkt = {0:0};
reg_ttl = {0:0};
reg_dttl = {0:0};
reg_spkts = {0:0};
reg_sbytes = {0:0};
reg_dpkts = {0:0};
reg_dbytes = {0:0};
reg_syn_time = {0:0};
reg_marked_malware = {0:0}
reg_tcprtt = {0:0};
record_index_flowid = {0:0};
record_index_inverse_flowid = {0:0};
reg_first_ack = {0:0};
srcport = 0;
dstport =0;


filename = 'ML/final_rf_model_1trees.sav'
rf = pickle.load(open(filename, 'rb'))

def ProcessPacket(ipv4_ttl, packet_length, ipv4_srcAddr,ipv4_dstAddr,srcPort,dstPort, ipv4_protocol,
                  tcp_ack, tcp_syn, tcp_fin,tcp_rst, ingressTime):
	# We plan to use the following features
	# 'sttl', 'ct_state_ttl', 'dttl', 'Sload','Dpkts','dmeansz','sbytes', 'Dload','smeansz','tcprtt','dsport','dur'
	#NOW = time.time();
	global rf;
	global tcprtt;
	global dur;
	global is_first
	global register_index
	global flowid_index;
	global inverse_flow_index;
	global counter_pkts;
	global reg_srcip;
	global reg_marked_index;
	global counter_malware	
	global counter_true_detection;
	global counter_false_detection;
	# Store some statistics for the flows--------
	global counter_flows;
	global counter_malware_flows;
	global counter_true_detection_flows;
	global counter_false_detection_flows;
    	# Check the direction of packets going. For UNSW data, the emulation configuration is as follows
    	# Outside: 59.166.0.0 normal 175.45.176.0 malware, Inside: 149.171.126.0
    	# Thus, mostly track 59.166.0.0 / 175.45.176.0 - --> 149.171.126.0 packets
	is_first = 0; # Not yet know that the flow is a new one
	counter_pkts = counter_pkts + 1;
	
	#Initialize class as 'Normal'
	class_type=0;

	# Mark Malware---------
	malware = 0;  # How is this found
	if re.search('175.45.176', ipv4_dstAddr):
		malware = 1
	if re.search('175.45.176', ipv4_srcAddr):
		malware = 1
	
	# Set Direction--------
	direction = 0;
	if re.search('149.171.126', ipv4_dstAddr):
		direction = 1;
  	
	# Calculate all features
	if(ipv4_protocol == 6 or ipv4_protocol == 17): # We treat only TCP or UDP packe
		if (direction == 1):
		# Get register position for TCP and UDP Flow -----------------------------------
			flowid = str(ipv4_srcAddr) +"-"+ str(ipv4_dstAddr)+"-"+ str(srcPort)+"-"+ str(dstPort)+"-"+ str(ipv4_protocol);
			dst_sport = str(ipv4_dstAddr)+"-"+str(srcPort);
			if(flowid not in record_index_flowid):
				flow_index =  len(record_index_flowid)
				flow_index = flow_index +1;	
				# add a new key, value pair
				record_index_flowid[flowid] =  flow_index;
				is_first = 1;
				time_first_pkt = ingressTime;
				reg_time_first_pkt[flowid] = ingressTime;
				counter_flows = counter_flows + 1;
				# initialize other dictionaries
				reg_ttl[flowid]=0;
				reg_spkts[flowid] = 0; #Initially the pkts for flow is zero
				reg_sbytes[flowid] = 0; #Initially 0 byte
				reg_tcprtt[flowid]= 0;
				reg_dttl[flowid]=0;
				reg_dpkts[flowid]=0;
				reg_dbytes[flowid]=0;
				reg_first_ack[flowid] = 0; 
				reg_marked_malware[flowid] = 0;

			# Set parameters from source side
			spkts = reg_spkts.get(flowid); #increment packet counter
			spkts = spkts + 1;
			reg_spkts[flowid] = spkts;

			sttl = ipv4_ttl;
			reg_ttl[flowid] = sttl;

			sbytes = reg_sbytes.get(flowid);
			sbytes = sbytes + packet_length;
			reg_sbytes[flowid] = sbytes;

			srcport = srcPort;
                        dstport = dstPort
            		# tcprtt SYN TIME
			if(ipv4_protocol == 6):
				#print("It is tcp:"+str(tcp_syn))
				if((tcp_ack != ACK) and (tcp_syn == SYN)): # this is a SYN
					reg_syn_time[flowid] = ingressTime; #
					#print("TCP SYNC");
                		# ACK + SYN time
				elif((tcp_ack == ACK) and (tcp_syn != SYN)): #  this is an ACK
					first_ack = reg_first_ack.get(flowid); #
					if(first_ack == 0): # sum of synack(SYN to SYN_ACK time) and ackdat(SYN_ACK to ACK time)					
						syn_time = reg_syn_time.get(flowid);
						#print("TCP ACK")
						if(syn_time > 0): # There was a syn before
							tcprtt = ingressTime - syn_time;
							reg_tcprtt[flowid] =  tcprtt;
                            				# No longer a first ack
							reg_first_ack[flowid] = 1;
			# Read all reverse flow features
			dbytes = reg_dbytes.get(flowid);
			dpkts = reg_dpkts.get(flowid);
			dttl = reg_dttl.get(flowid);			
			register_index = flowid;
			# End of direction = 1---------------------
			#******************************************

		else: # when direction = 0
		#Some flows can be marked malware even after analysing return flow!
		# Get register position for the same TCP and UDP flow in another directon-------
		# just inverse the src and dst
			inverse_flowid = str(ipv4_dstAddr)+"-" + str(ipv4_srcAddr)+"-" + str(dstPort) +"-"+ str(srcPort) +"-"+ str(ipv4_protocol);
			dst_sport = str(ipv4_srcAddr)+"-"+str(dstPort);
			if (inverse_flowid not in record_index_flowid):
                                inverse_flow_index = len(record_index_flowid);
				inverse_flow_index = inverse_flow_index + 1;
				record_index_flowid[inverse_flowid] = inverse_flow_index;
				print("I am inside reverse traffic");
				time_first_pkt = ingressTime;
				reg_time_first_pkt[inverse_flowid] = time_first_pkt;
				counter_flows = counter_flows + 1;
                                reg_ttl[inverse_flowid]= 0;
                                reg_dttl[inverse_flowid]= 0;
                                reg_spkts[inverse_flowid] = 0; #Initially the pkts for flow is zero
                                reg_sbytes[inverse_flowid] = 0; #Initially 0 bytes
                                reg_dpkts[inverse_flowid]=0;
                                reg_dbytes[inverse_flowid]=0;
                                reg_first_ack[inverse_flowid] = 0; # Initially 0 
                                reg_marked_malware[inverse_flowid] = 0;
			
			# Store parameters from destination side
			dpkts = reg_dpkts.get(inverse_flowid);
			dpkts =  dpkts + 1;
			reg_dpkts[inverse_flowid] = dpkts;

			dbytes = reg_dbytes.get(inverse_flowid);
			dbytes = dbytes + packet_length;
			reg_dbytes[inverse_flowid] = dbytes;
			
			dttl =  ipv4_ttl;
			reg_dttl[inverse_flowid] = dttl;

			# Retrieve paramters from source side
			sttl = reg_ttl.get(inverse_flowid);
			sbytes = reg_sbytes.get(inverse_flowid);
			spkts = reg_spkts.get(inverse_flowid);
			srcport = dstPort;
                        dstport = srcPort
			register_index = inverse_flowid;
		# end of direction = 0----------------------------
		#*************************************************
		# Read common features
		# TODO on hash collision we are letting the flow pass
	
		# We can also do a false detection!
		tcprtt = reg_tcprtt.get(register_index); 
		time_first_pkt = reg_time_first_pkt.get(register_index); 
		#print("type dur:"+str(type(dur)))
		#print("type ingress: "+str(type(ingressTime)))
		dur = (ingressTime - time_first_pkt)/1000000; # convert into micro seconds in millisec
		
		# calc_state()--------------------------
		if ((is_first == 1) and (dttl == 0)):
			if (ipv4_protocol == 6):  # TCP
				state = STATE_REQ;
			else:
				state = STATE_INT;
		else:
			if (ipv4_protocol == 6):
				if( tcp_rst == RST):  # TCP
					state = STATE_RST;
				elif(dttl==0 and sttl==254):
					state = STATE_REQ;
				elif(dttl==0 and sttl!=254):
					state = STATE_CON;
				else:
					state = STATE_CON;
			else:
				if(dttl!=0):
					state = STATE_CON;
		# For STATE_FIN, which may not be useful as it would be last packet of transactioN
		if (ipv4_protocol == 6 and tcp_fin == FIN):
			state = STATE_FIN;

		if (ipv4_protocol == 17 and dttl== 0 and spkts <=4):
                        state = STATE_INT

		
		# calc_ct_state_ttl()-------------------
		ct_state_ttl = 0;
		if((sttl == 62 or sttl == 63 or sttl == 254 or sttl == 255) and (dttl == 252 or dttl == 253) and state == STATE_FIN):
			ct_state_ttl = 1;
		elif ((sttl == 0 or sttl == 62 or sttl == 254) and (dttl == 0) and state == STATE_INT):
			ct_state_ttl = 2;
		elif((sttl == 62 or sttl == 254) and (dttl == 60 or dttl == 252 or dttl == 253) and state == STATE_CON):
			ct_state_ttl = 3;
		elif((sttl == 254) and (dttl == 252) and state == STATE_CON):
			ct_state_ttl = 4;
		elif ((sttl == 254) and (dttl == 252) and state == STATE_CLO):
			ct_state_ttl = 5;
		elif ((sttl == 254) and (dttl == 0) and state == STATE_REQ):
			ct_state_ttl = 7;

		#if(ct_state_ttl > 0):
		#	print("calc_state :"+ str(ct_state_ttl))
		# read_ct_srv_dst()------------;
		# init_features()--------------
		# bitrate = int(smeanz) * (totalpkts - 1) * 8 / dur
    		# We will compare sbytes * (totalpkts - 1) * 8 > th * dur * spkts;
		# 'sttl', 'ct_state_ttl', 'dttl', 'Sload','Dpkts','dmeansz','sbytes', 'Dload','smeansz','tcprtt','dsport','dur'
		# Sload = (sbytes * (spkts - 1) * 8)/dur; # needed for Sload
		Sload = 0;# needed for Sload
		Dpkts = dpkts; # dpkts
		dmeansz = dbytes; # Needed for dmeansz
		smeansz = sbytes;
		# Dload = (dbytes * (dpkts - 1) * 8)/dur; # Needed for dload
		Dload = 0;
	        #print("Duration:" + str(dur)+", Now:"+str(NOW)+", first_packet: "+str(time_first_pkt));
		
		if(dur > 0):
			Sload = (sbytes * 8)/ (dur);  #Bitrate-bps
			Dload = (dbytes* 8) / (dur);  # Needed for dload
	
		if(spkts > 0):
			smeansz = sbytes/spkts; #needed for smeansz
		if(dpkts > 0):
			dmeasz = dbytes/dpkts;
	
		#Apply the model------------------
		data = [[int(sttl), int(ct_state_ttl), int(dttl), float(Sload),int(Dpkts), int(dmeansz),int(sbytes), float(Dload),int(smeansz),float(tcprtt),int(dstport),float(dur)]]
		test_instance = pd.DataFrame(data, columns = ['sttl', 'ct_state_ttl', 'dttl', 'Sload', 'Dpkts', 'dmeansz','sbytes', 'dload', 'smeansz', 'tcprtt', 'dstport', 'dur'])
		#print("Flowid: " + str(register_index))
		#print(test_instance)
		#print("sttl:" + str(sttl)+", dttl:"+ str(dttl)+", state:"+str(state))
		data_test =np.array(test_instance)
		class_type =  rf.predict(data_test)
		#print("class_type: "+str(class_type));	
	
		if(malware == 1): #malware is calculated with priori knowledge for statistics
			counter_malware =  counter_malware + 1;
			if (is_first == 1):
				counter_malware_flows = counter_malware_flows + 1;
			if (class_type == 1):
				counter_true_detection = counter_true_detection + 1;
				if(reg_marked_malware.get(register_index) == 0):
				# We detect the flow as malware first time!
					counter_true_detection_flows = counter_true_detection_flows + 1;
				reg_marked_malware[register_index] = 1;
		else:
			if(class_type == 1 and dur > 0):
				counter_false_detection = counter_false_detection + 1;
				if(reg_marked_malware.get(register_index) == 0):
					#print("FlowID:" +str(register_index))
					# We detect the flow as malware first time! even if false
					counter_false_detection_flows=counter_false_detection_flows+1;
				reg_marked_malware[register_index] = 1;

		# Display Results:
		#'''
		print("\ncounter_pkts: "+ str(counter_pkts));
		print("\ncounter_pkts_malware: "+ str(counter_malware));
		print("\ncounter_pkts_true_detection: "+ str(counter_true_detection));
		print("\ncounter_pkts_false_detection: "+ str(counter_false_detection));
		print("\ncounter_flows: "+ str(counter_flows));
		print("\ncounter_malware_flows: " +str(counter_malware_flows));
		print("\ncounter_true_detection_flows: "+str(counter_true_detection_flows));
		print("\ncounter_false_detection_flows: "+str(counter_false_detection_flows));
		print("\n*__________*****_________***");
		#'''
#----- End of the Process Packet Function -------------------
#
#
#
#
#
# ------- RECIEVE PACKET -----------------------------------
def get_if():
	ifs=get_if_list()
	iface=None
	for i in get_if_list():
		if "eth0" in i:
			iface=i
			break;
	if not iface:
		print("Cannot find eth0 interface")
		exit(1)
	return iface

class IPOption_OriginalIP(IPOption):
	name = "Telemetry"
	option = 31
	fields_desc = [ _IPOption_HDR,
                    ByteField("length",2),
                    BitField("orignal_dstIP",0,32),
		    BitField("recordTime", 0, 48)]

def handle_pkt(pkt):
	#if TCP in pkt and pkt[TCP].dport == 1234:
	#print("got a packet---------")
	pkt.show2()
	#    hexdump(pkt)
	# Takeout original IP address
	if((IP) in pkt and ('127.0.0.1' not in pkt[IP].src)):
		telemetry = str(pkt[IP].options)
		originalDstIP = re.search('orignal_dstIP=(.*)L recordTime', telemetry).group(1)
		originalDstIP = socket.inet_ntoa(struct.pack('!L',int(originalDstIP)));
		ingressTime = re.search('recordTime=(.*)L', telemetry).group(1)
		ingressTime = float(long(ingressTime));
		packetLen = pkt[IP].len -((32*pkt[IP].ihl)/8);
		if TCP in pkt:
			F = pkt['TCP'].flags;	
			ProcessPacket(pkt[IP].ttl, packetLen, pkt[IP].src,originalDstIP,pkt[TCP].sport,pkt[TCP].dport, pkt[IP].proto,F & ACK, F & SYN, F & FIN,F & RST, ingressTime)
		elif UDP in pkt:
			ProcessPacket(pkt[IP].ttl, packetLen, pkt[IP].src,originalDstIP,pkt[UDP].sport,pkt[UDP].dport, pkt[IP].proto,0,0,0,0, ingressTime)

def main():
	ifaces = list(filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/')))
	iface = ifaces[0]
	print("sniffing on %s" % iface)
	sys.stdout.flush()
	sniff(iface = iface,
		 prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
	main()
