#!/usr/bin/env python
#----------------------------------------------------------------------
# LIBRARIES
#----------------------------------------------------------------------

import sys
import struct, socket
import os, re, time
import pickle
import sklearn as sk
import pandas as pd
from scapy.all import *
import numpy as np
from sklearn import tree
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import RandomForestRegressor
from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, ByteField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw

#----------------------------------------------------------------------
# Some Variable to be used during feature extraction and storing the result
#----------------------------------------------------------------------
min_value = 100000000
max_value = 0
register_index = 0;
is_first = 0;
is_empty = 0;
first_ack = 0;
malware = 0;
marked_malware = 0;

# Store some statistics for the packets---------------------------------
counter_pkts = 0;
counter_malware = 0;
counter_detection = 0;
counter_no_detection = 0;
# Store some statistics for the flows---------------------------------
counter_flows = 0;
counter_flows_benign = 0;
counter_timeout = 0;
time_first_pkt = 0.0;
dur = 0.0;
min_iat = 1000000;
max_iat = 0;
total_dur = 0.0;
# Registers used in the script --------------------------------------
reg_time_last_pkt = {0: 0};
reg_time_first_pkt = {0: 0};
reg_spkts = {0: 0};
reg_sbytes = {0: 0};
reg_dpkts = {0: 0};
reg_dbytes = {0: 0};
reg_attack_flows = {0: 0}
reg_benign_flows ={0:0}
reg_attack_packets = {0: 0}
record_index_flowid = {0: 0};
record_index_inverse_flowid = {0: 0};
record_src_ip = {0: 0};
record_dst_ip = {0: 0};
reg_max_iat = {0: 0};
reg_min_iat = {0: 0};
first_packet_attack = 0;
first_packet_benign = 0;

# Load RF DDoS Attack Classifier---------------------------------
# Combined classifier of TCP and UDP flows, including time based feature
filename = 'final_rf_model_dos_time.sav'

# OR 
#Combined classifier of TCP and UDP flows,without time based feature
#filename = 'final_rf_model_dos.sav'

# OR
# Separate Classifier for TCP (with/without time)
filename = 'final_rf_model_dos_tcp.sav'
rf_tcp = pickle.load(open(filename, 'rb'))

# Separate Classifier for UDP (with/without time)
filename = '../generated csv/final_rf_model_dos_udp.sav'
rf_udp = pickle.load(open(filename, 'rb'))

# rf= pickle.load(open(filename, 'rb'))

#----------------------------------------------------------------------
# EXTRACTING FEATURES FROM THE PCA
#----------------------------------------------------------------------

def processPacket(ingressTime, packet_length, ipv4_srcAddr, ipv4_dstAddr,
                  srcPort, dstPort, ipv4_protocol,
                  fin_flag_number, syn_flag_number, rst_flag_number, psh_flag_number,
                  ack_flag_number, urg_flag_number, ece_flag_number,
                  cwr_flag_number, ttl):

    # Define paramters to be global
    global rf;
    global dur, total_dur, min_iat,max_iat;
    global is_first
    global register_index
    global flowid_index;
    global inverse_flow_index;
    global counter_pkts;
    global reg_srcip;
    global reg_marked_index;
    global counter_malware
    global counter_detection;
    global counter_no_detection;
    global counter_flows;
    global counter_flows_benign;
    global first_packet_benign;
    global first_packet_attack;
    global reg_attack_packets;
    global reg_attack_flows;
    global reg_benign_flows;
    global reg_max_iat;
    global reg_min_iat;

    # Initialize some variables-----------------------------------------
    is_first = 0;  # Not yet know that the flow is a new one
    class_type = 0; # Initialize class as 'Normal'
    state_con = 0;
    state_rst = 0;
    state_int = 0;
    counter_pkts = counter_pkts + 1; # Packet counter
    
    # Calculate all features-------------------------------------------
    if (ipv4_protocol == 6 or ipv4_protocol == 17):  # We only test TCP or UDP packets

        #**** Setting of Direction Of a Flow ******
        flowid = str(ipv4_srcAddr) + "-" + str(ipv4_dstAddr) + "-" + str(srcPort) + "-" + str(dstPort) + "-" + str(
            ipv4_protocol);
        inverse_flowid = str(ipv4_dstAddr) + "-" + str(ipv4_srcAddr) + "-" + str(dstPort) + "-" + str(srcPort) + "-" + str(
            ipv4_protocol);

        # If flow is already in the record_index_flowid--------------
        if(flowid in record_index_flowid):
            direction = 1;
            is_first = False;
        elif(inverse_flowid in record_index_flowid):
            direction = 0;
            is_first = False;
        else:
            direction = 1;
            is_first = True;
            # Record flow information
            flow_index = len(record_index_flowid)
            flow_index = flow_index + 1;
            # add a new key, value pair
            record_index_flowid[flowid] = flow_index;
            reg_time_first_pkt[flowid] = ingressTime;
            reg_time_last_pkt[flowid] = ingressTime;
            reg_attack_packets[flowid] =  0;
            reg_attack_flows[flowid] = 0;
            reg_benign_flows[flowid] = 0;
            counter_flows = counter_flows + 1;
            # If this srcIP is seen for the first time
            if (str(ipv4_srcAddr) not in record_src_ip):
                    record_src_ip[str(ipv4_srcAddr)] = 1;
            else:  # If this srcIP is seen again
                    record_src_ip[str(ipv4_srcAddr)] = record_src_ip.get(str(ipv4_srcAddr)) + 1;
            # If this dstIP is seen for the first time
            if (str(ipv4_dstAddr) not in record_dst_ip):
                    record_dst_ip[str(ipv4_dstAddr)] = 1;
            else:  # If this dstIP is seen again
                    record_dst_ip[str(ipv4_dstAddr)] = record_dst_ip.get(str(ipv4_dstAddr)) + 1;

            # initialize other dictionaries
            reg_spkts[flowid] = 0;  # Initially the pkts for flow is zero
            reg_sbytes[flowid] = 0;  # Initially 0 byte
            reg_dpkts[flowid] = 0;
            reg_dbytes[flowid] = 0;
            reg_max_iat[flowid] = 0;
            reg_min_iat[flowid] = 1000000;
            #reg_benign_flows[flowid] = 0;

        # ********************************************
        # Start of Direction = 1 (Source2Destination)
        # ********************************************
        if direction == 1:
            # no. of outgoing flows from a source node
            n_in_conn_ip_srcip = record_src_ip.get(str(ipv4_srcAddr));
            n_in_conn_ip_dstip = record_dst_ip.get(str(ipv4_dstAddr));

            # Set parameters from source side
            spkts = reg_spkts.get(flowid);  # increment packet counter
            spkts = spkts + 1;
            reg_spkts[flowid] = spkts;

            sbytes = reg_sbytes.get(flowid);
            sbytes = sbytes + packet_length;
            reg_sbytes[flowid] = sbytes;


            # Read all reverse flow features
            dbytes = reg_dbytes.get(flowid);
            dpkts = reg_dpkts.get(flowid);
            bytes = sbytes;
            pkts = spkts;
            register_index = flowid;
        # End of direction = 1---------------------

        # ********************************************
        # Start of Direction = 0 (Destination2Source)
        # ********************************************
        else:  # when direction = 0

            n_in_conn_ip_srcip = record_src_ip.get(str(ipv4_dstAddr));  # no. of outgoing flows from a source node
            n_in_conn_ip_dstip = record_dst_ip.get(str(ipv4_srcAddr));  # no. of incoming // to a dst node

            # Store parameters from destination side
            dpkts = reg_dpkts.get(inverse_flowid);
            dpkts = dpkts + 1;
            reg_dpkts[inverse_flowid] = dpkts;

            dbytes = reg_dbytes.get(inverse_flowid);
            dbytes = dbytes + packet_length;
            reg_dbytes[inverse_flowid] = dbytes;

            # Retrieve paramters from source side
            sbytes = reg_sbytes.get(inverse_flowid);
            spkts = reg_spkts.get(inverse_flowid);
            bytes =  dbytes;
            pkts =  dpkts;
            register_index = inverse_flowid;
        # end of direction = 0----------------------------
        # *************************************************

        # Read common features----------------------------
        time_first_pkt = reg_time_first_pkt.get(register_index);
        time_last_pkt = reg_time_last_pkt.get(register_index);
        dur = (ingressTime - time_last_pkt);  # duration is in seconds
        total_dur = ingressTime - time_first_pkt;
        reg_time_last_pkt[register_index] = ingressTime;
        min_iat = reg_min_iat.get(register_index);
        max_iat = reg_max_iat.get(register_index);

        if (dur > max_iat):
            max_iat = dur;
            reg_max_iat[register_index] = max_iat;

        if (dur < min_iat):
            min_iat = dur;
            reg_min_iat[register_index] = min_iat;

        if((spkts + dpkts) > 1 and total_dur > 0):
            srate = (spkts)/total_dur;
            drate = (dpkts)/total_dur;
        else:
            srate = 0;
            drate = 0;

        # ****** calc_state()*******************
        if (is_first == 1):
            if (ipv4_protocol == 17):
                state_int = 1;
        else:
                state_con = 1;
        if (ipv4_protocol == 6 and rst_flag_number == 1):
            state_rst = 1;
            state_con = 0;

        avg_pkt_len = bytes/pkts;
        
	#------------------------------------------------------------------------------
	#****Uncomment following part when runing Separate Models for TCP and UDP flows
	#------------------------------------------------------------------------------
	#'''
        if(ipv4_protocol == 6): # TCP flows
            data = [[
                (sbytes + dbytes), spkts, dpkts, ttl,min_iat,
                 n_in_conn_ip_srcip, n_in_conn_ip_dstip,avg_pkt_len,
                 #state_con,
                 state_rst,
                 fin_flag_number, syn_flag_number, psh_flag_number,
                 ack_flag_number]]
                 #urg_flag_number,
                 #ece_flag_number,cwr_flag_number]];

            test_instance = pd.DataFrame(data, columns=[
             'flow_bytes', 'spkts','dpkts','ttl','min_iat',
             'N_IN_Conn_P_Src_IP', 'N_IN_Conn_P_Dst_IP', 'avg_pkt_len',
             #'state_con',
             'state_rst',
             'fin_flag_number', 'syn_flag_number',
             'psh_flag_number', 'ack_flag_number'])
             #'urg_flag_number'])
             #'ece_flag_number',
             #'cwr_flag_number'])

            data_test = np.array(test_instance)
            class_type = rf_tcp.predict(data_test)

        else: # UDP flows
            data = [[
                (sbytes + dbytes), spkts, dpkts, ttl, total_dur,min_iat,
                 n_in_conn_ip_srcip, n_in_conn_ip_dstip,avg_pkt_len]];


            test_instance = pd.DataFrame(data, columns=[
            'flow_bytes','spkts', 'dpkts','ttl','total_duration', 'min_iat',
            'N_IN_Conn_P_Src_IP', 'N_IN_Conn_P_Dst_IP','avg_pkt_len'])


            data_test = np.array(test_instance)
            class_type = rf_udp.predict(data_test)
	#'''
	#------------------------------------------------------------------------------

	#------------------------------------------------------------------------------
	#****Uncomment following part when runing Combined/Single Model for TCP and UDP flows
	#------------------------------------------------------------------------------
        '''
        type = 1;
        if(ipv4_protocol==17):
            type=0;

        data = [[
            (sbytes + dbytes), srate, drate, type,
            ttl, max_iat,
            n_in_conn_ip_srcip, n_in_conn_ip_dstip, avg_pkt_len,
            state_con,state_int,state_rst,
            fin_flag_number, syn_flag_number,
            psh_flag_number, ack_flag_number]];
            #,urg_flag_number, ece_flag_number,cwr_flag_number]];


        test_instance = pd.DataFrame(data, columns=['flow_bytes','srate','drate', 'type',
        'ttl','max_iat',
        'N_IN_Conn_P_Src_IP', 'N_IN_Conn_P_Dst_IP', 'avg_pkt_len',
        'state_con','state_int', 'state_rst',
        'fin_flag_number', 'syn_flag_number',
        'psh_flag_number', 'ack_flag_number'])
        
        data_test = np.array(test_instance)
        class_type = rf.predict(data_test)
        '''
	#------------------------------------------------------------------------------
        
	# Store the Results of the classifier
	counter_malware = counter_malware + class_type;
        reg_attack_packets[register_index] = reg_attack_packets.get(register_index) + class_type;
        reg_attack_flows[register_index] = (reg_attack_packets.get(register_index)/(spkts+dpkts));


#----------------------------------------------------------------------
#----------------------------------------------------------------------
def get_if():
    ifs = get_if_list()
    iface = None
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

#----------------------------------------------------------------------
#----------------------------------------------------------------------
def handle_pkt(pkt, protocol):
    if ((IP) in pkt):
        # print(len(pkt))
        # print(pkt[IP].len)
        packetLen = pkt[IP].len + 14; # The 14 bytes is to count the ethernet frame size
        # TCP Protocol -------
        if ((protocol == 1 or protocol==2) and TCP in pkt):
            tcp_fin = 0;
            tcp_syn = 0;
            tcp_rst = 0;
            tcp_psh = 0;
            tcp_ack = 0;
            tcp_urg = 0;
            tcp_ece = 0;
            tcp_cwr = 0;

            #print(pkt[TCP].flags)
            if 'F' in str(pkt[TCP].flags):
                tcp_fin = 1;
            if 'S' in str(pkt[TCP].flags):
                tcp_syn = 1;
            if 'R' in str(pkt[TCP].flags):
                tcp_rst = 1;
            if 'P' in str(pkt[TCP].flags):
                tcp_psh = 1;
            if 'A' in str(pkt[TCP].flags):
                tcp_ack = 1;
            if 'U' in str(pkt[TCP].flags):
                tcp_urg = 1;
            if 'E' in str(pkt[TCP].flags):
                tcp_ece = 1;
            if 'C' in str(pkt[TCP].flags):
                tcp_cwr = 1;


            processPacket(pkt.time, packetLen, pkt[IP].src, pkt[IP].dst,
                            pkt[TCP].sport, pkt[TCP].dport, pkt[IP].proto,
                            tcp_fin,tcp_syn, tcp_rst, tcp_psh,tcp_ack,tcp_urg,tcp_ece,tcp_cwr, pkt[IP].ttl)
        # UDP Protocol -------
        elif ((protocol == 1 or protocol == 3) and UDP in pkt):
            processPacket(pkt.time, packetLen, pkt[IP].src, pkt[IP].dst,
                          pkt[UDP].sport, pkt[UDP].dport, pkt[IP].proto,
                          0, 0, 0, 0,0, 0, 0, 0,pkt[IP].ttl)

#----------------------------------------------------------------------
#----------------------------------------------------------------------
def main():
    csv_file_name ='Benign';
    pcap_flow = rdpcap(csv_file_name+".pcap");

    # If you are interested in both UDP and TCP flows use 1, i.e.,
    # 1:udp/tcp , 2: only tcp, 3: only udp 
    #-------------------------------------------------------------
    
    protocol = 3;
    s=0
    for pkt in pcap_flow:
        if (len(pkt) < 152000):# and TCP in pkt):
            handle_pkt(pkt, protocol);
            s=s+1;
            #if(s>5):
            #    break;
    #print("packets are:"+str(s))
    # Display Results:
    sum = 0;
    for values in reg_attack_flows.values():
        if(np.round(values)==1):
            sum = sum + 1;

        #print("Min value: " + str(min_value));
        #print("Max value: " + str(max_value));
    print("Percentage of packets with attack:" + str(counter_malware / counter_pkts));
    print("Percentage of flows with attack:"+ str(sum/counter_flows));
    #print("\n*__________*****_________***");


#----------------------------------------------------------------------
#----------------------------------------------------------------------
if __name__ == '__main__':
    main()
#----------------------------------------------------------------------
#----------------------------------------------------------------------
