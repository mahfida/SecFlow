:wq
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------
# DDoS FLOW/PKT FEATURE EXTRACTION + RF-BASED DETECTOR (SCAPY OFFLINE)
# ----------------------------------------------------------------------
# UPDATE:
# - Now accepts command-line arguments for protocol and detector.
#   * --protocol  {1,2,3}  (1=TCP+UDP, 2=TCP only, 3=UDP only)
#   * --detector  {10,20,11,21,12,22} (model/feature set selector)
# - Variable names remain UNCHANGED (as requested). Structure reorganized
#   so the model is selected/loaded after parsing CLI args.
# ----------------------------------------------------------------------

# ----------------------------------------------------------------------
# LIBRARIES
# ----------------------------------------------------------------------
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
import argparse  # for command-line interface
import warnings
warnings.filterwarnings("ignore")
# ----------------------------------------------------------------------
# GLOBAL STATE / REGISTERS
# ----------------------------------------------------------------------
min_value = 100000000
max_value = 0

register_index = 0
is_first = 0
is_empty = 0
first_ack = 0
malware = 0
marked_malware = 0

counter_pkts = 0
counter_malware = 0
counter_detection = 0
counter_no_detection = 0

counter_flows = 0
counter_flows_benign = 0
counter_timeout = 0
time_first_pkt = 0.0
dur = 0.0
min_iat = 1000000
max_iat = 0
total_dur = 0.0

reg_time_last_pkt = {0: 0}
reg_time_first_pkt = {0: 0}
reg_spkts = {0: 0}
reg_sbytes = {0: 0}
reg_dpkts = {0: 0}
reg_dbytes = {0: 0}
reg_attack_flows = {0: 0}
reg_benign_flows = {0: 0}
reg_attack_packets = {0: 0}
record_index_flowid = {0: 0}
record_index_inverse_flowid = {0: 0}
record_src_ip = {0: 0}
record_dst_ip = {0: 0}
reg_max_iat = {0: 0}
reg_min_iat = {0: 0}

first_packet_attack = 0
first_packet_benign = 0

# ----------------------------------------------------------------------
# MODEL SELECTION PLACEHOLDERS (filled after CLI parsing in setup_model)
# ----------------------------------------------------------------------
detector = 10            # default; can be overridden by --detector
filename = None          # will be set based on detector
feature_names = []       # will be set based on detector
rf = None                # will hold the loaded model

def setup_model():
    """
    Choose filename & feature_names based on global 'detector', then load 'rf'.
    Keeps original variable names intact.
    """
    global detector, filename, feature_names, rf

    if (detector == 10):
        filename = 'combined_time.sav'
        feature_names = [
            'flow_bytes', 'srate', 'drate', 'type', 'ttl', 'max_iat', 'total_duration',
            'N_IN_Conn_P_Src_IP', 'N_IN_Conn_P_Dst_IP', 'avg_pkt_len',
            'state_con', 'state_int', 'state_rst',
            'fin_flag_number', 'syn_flag_number', 'psh_flag_number', 'ack_flag_number'
        ]

    elif (detector == 20):
        filename = 'combined_notime.sav'
        feature_names = [
            'flow_bytes', 'spkts', 'dpkts', 'type', 'ttl',
            'N_IN_Conn_P_Src_IP', 'N_IN_Conn_P_Dst_IP', 'avg_pkt_len',
            'state_con', 'state_int', 'state_rst',
            'fin_flag_number', 'syn_flag_number', 'psh_flag_number', 'ack_flag_number'
        ]

    elif (detector == 11):
        filename = 'tcp_time.sav'
        feature_names = [
            'flow_bytes', 'spkts', 'dpkts', 'ttl', 'min_iat',
            'N_IN_Conn_P_Src_IP', 'N_IN_Conn_P_Dst_IP', 'avg_pkt_len',
            'state_rst', 'fin_flag_number', 'syn_flag_number', 'psh_flag_number', 'ack_flag_number'
        ]

    elif (detector == 21):
        filename = 'tcp_notime.sav'
        feature_names = [
            'flow_bytes', 'spkts', 'dpkts', 'ttl',
            'N_IN_Conn_P_Src_IP', 'N_IN_Conn_P_Dst_IP', 'avg_pkt_len',
            'state_con', 'state_rst',
            'fin_flag_number', 'syn_flag_number', 'psh_flag_number', 'ack_flag_number'
        ]

    elif (detector == 12):
        filename = 'udp_time.sav'
        feature_names = [
            'flow_bytes', 'spkts', 'dpkts', 'ttl', 'total_duration', 'min_iat',
            'N_IN_Conn_P_Src_IP', 'N_IN_Conn_P_Dst_IP', 'avg_pkt_len'
        ]

    elif (detector == 22):
        filename = 'udp_notime.sav'
        feature_names = [
            'flow_bytes', 'spkts', 'dpkts', 'ttl',
            'N_IN_Conn_P_Src_IP', 'N_IN_Conn_P_Dst_IP', 'avg_pkt_len'
        ]
    else:
        raise ValueError("Unsupported detector value. Use one of: 10,20,11,21,12,22")

    # Load the pre-trained model now that we know 'filename'
    rf = pickle.load(open(filename, 'rb'))

# ----------------------------------------------------------------------
# FEATURE EXTRACTION & CLASSIFICATION
# ----------------------------------------------------------------------
def processPacket(ingressTime, packet_length, ipv4_srcAddr, ipv4_dstAddr,
                  srcPort, dstPort, ipv4_protocol,
                  fin_flag_number, syn_flag_number, rst_flag_number, psh_flag_number,
                  ack_flag_number, urg_flag_number, ece_flag_number,
                  cwr_flag_number, ttl):
    """
    Build/maintain per-flow stats, compute per-packet/flow features, and invoke the RF model.
    Arguments mirror what we need from scapy packets and TCP flag decoding.
    """

    global rf
    global dur, total_dur, min_iat, max_iat
    global is_first
    global register_index
    global flowid_index
    global inverse_flow_index
    global counter_pkts
    global reg_srcip
    global reg_marked_index
    global counter_malware
    global counter_detection
    global counter_no_detection
    global counter_flows
    global counter_flows_benign
    global first_packet_benign
    global first_packet_attack
    global reg_attack_packets
    global reg_attack_flows
    global reg_benign_flows
    global reg_max_iat
    global reg_min_iat

    is_first = 0                    # Assume existing flow; set to 1 if new
    class_type = 0                  # Predicted label (0=benign, 1=attack)
    state_con = 0                   # continuation/connected
    state_rst = 0                   # TCP RST
    state_int = 0                   # initial (e.g., first UDP observation)
    counter_pkts = counter_pkts + 1 # packet counter

    # Only handle TCP(6) or UDP(17)
    if (ipv4_protocol == 6 or ipv4_protocol == 17):

        # Build flow keys for both directions
        flowid = f"{ipv4_srcAddr}-{ipv4_dstAddr}-{srcPort}-{dstPort}-{ipv4_protocol}"
        inverse_flowid = f"{ipv4_dstAddr}-{ipv4_srcAddr}-{dstPort}-{srcPort}-{ipv4_protocol}"

        # Flow lookup / insertion
        if (flowid in record_index_flowid):
            direction = 1
            is_first = False
        elif (inverse_flowid in record_index_flowid):
            direction = 0
            is_first = False
        else:
            direction = 1
            is_first = True

            flow_index = len(record_index_flowid) + 1
            record_index_flowid[flowid] = flow_index

            reg_time_first_pkt[flowid] = ingressTime
            reg_time_last_pkt[flowid] = ingressTime

            reg_attack_packets[flowid] = 0
            reg_attack_flows[flowid] = 0
            reg_benign_flows[flowid] = 0

            counter_flows = counter_flows + 1

            # Track counts for per-IP features
            if (str(ipv4_srcAddr) not in record_src_ip):
                record_src_ip[str(ipv4_srcAddr)] = 1
            else:
                record_src_ip[str(ipv4_srcAddr)] = record_src_ip.get(str(ipv4_srcAddr)) + 1

            if (str(ipv4_dstAddr) not in record_dst_ip):
                record_dst_ip[str(ipv4_dstAddr)] = 1
            else:
                record_dst_ip[str(ipv4_dstAddr)] = record_dst_ip.get(str(ipv4_dstAddr)) + 1

            # Initialize per-flow counters / IAT bounds
            reg_spkts[flowid] = 0
            reg_sbytes[flowid] = 0
            reg_dpkts[flowid] = 0
            reg_dbytes[flowid] = 0
            reg_max_iat[flowid] = 0
            reg_min_iat[flowid] = 1000000

        # Direction-specific updates
        if direction == 1:
            n_in_conn_ip_srcip = record_src_ip.get(str(ipv4_srcAddr))
            n_in_conn_ip_dstip = record_dst_ip.get(str(ipv4_dstAddr))

            spkts = reg_spkts.get(flowid) + 1
            reg_spkts[flowid] = spkts

            sbytes = reg_sbytes.get(flowid) + packet_length
            reg_sbytes[flowid] = sbytes

            dbytes = reg_dbytes.get(flowid)
            dpkts = reg_dpkts.get(flowid)

            bytes = sbytes
            pkts = spkts
            register_index = flowid

        else:
            n_in_conn_ip_srcip = record_src_ip.get(str(ipv4_dstAddr))
            n_in_conn_ip_dstip = record_dst_ip.get(str(ipv4_srcAddr))

            dpkts = reg_dpkts.get(inverse_flowid) + 1
            reg_dpkts[inverse_flowid] = dpkts

            dbytes = reg_dbytes.get(inverse_flowid) + packet_length
            reg_dbytes[inverse_flowid] = dbytes

            sbytes = reg_sbytes.get(inverse_flowid)
            spkts = reg_spkts.get(inverse_flowid)

            bytes = dbytes
            pkts = dpkts
            register_index = inverse_flowid

        # Common timing / rates
        time_first_pkt = reg_time_first_pkt.get(register_index)
        time_last_pkt = reg_time_last_pkt.get(register_index)

        dur = (ingressTime - time_last_pkt)
        total_dur = ingressTime - time_first_pkt

        reg_time_last_pkt[register_index] = ingressTime

        min_iat = reg_min_iat.get(register_index)
        max_iat = reg_max_iat.get(register_index)

        if (dur > max_iat):
            max_iat = dur
            reg_max_iat[register_index] = max_iat

        if (dur < min_iat):
            min_iat = dur
            reg_min_iat[register_index] = min_iat

        if ((spkts + dpkts) > 1 and total_dur > 0):
            srate = (spkts) / total_dur
            drate = (dpkts) / total_dur
        else:
            srate = 0
            drate = 0

        # Simple state flags
        if (is_first == 1):
            if (ipv4_protocol == 17):
                state_int = 1
        else:
            state_con = 1

        if (ipv4_protocol == 6 and rst_flag_number == 1):
            state_rst = 1
            state_con = 0

        avg_pkt_len = (bytes / pkts) if pkts > 0 else 0

        # Classification: assemble features according to 'detector'
        if (detector == 10 or detector == 20):
            type = 1
            if (ipv4_protocol == 17):
                type = 0

        if detector == 10:
            features = [
                (sbytes + dbytes), srate, drate, type, ttl, max_iat, total_dur,
                n_in_conn_ip_srcip, n_in_conn_ip_dstip, avg_pkt_len,
                state_con, state_int, state_rst,
                fin_flag_number, syn_flag_number, psh_flag_number, ack_flag_number
            ]
        elif detector == 20:
            features = [
                (sbytes + dbytes), spkts, dpkts, type, ttl,
                n_in_conn_ip_srcip, n_in_conn_ip_dstip, avg_pkt_len,
                state_con, state_int, state_rst,
                fin_flag_number, syn_flag_number, psh_flag_number, ack_flag_number
            ]
        elif detector == 11:
            features = [
                (sbytes + dbytes), spkts, dpkts, ttl, min_iat,
                n_in_conn_ip_srcip, n_in_conn_ip_dstip, avg_pkt_len,
                state_rst, fin_flag_number, syn_flag_number, psh_flag_number, ack_flag_number
            ]
        elif detector == 21:
            features = [
                (sbytes + dbytes), spkts, dpkts, ttl,
                n_in_conn_ip_srcip, n_in_conn_ip_dstip, avg_pkt_len,
                state_con, state_rst,
                fin_flag_number, syn_flag_number, psh_flag_number, ack_flag_number
            ]
        elif detector == 12:
            features = [
                (sbytes + dbytes), spkts, dpkts, ttl, total_dur, min_iat,
                n_in_conn_ip_srcip, n_in_conn_ip_dstip, avg_pkt_len
            ]
        elif detector == 22:
            features = [
                (sbytes + dbytes), spkts, dpkts, ttl,
                n_in_conn_ip_srcip, n_in_conn_ip_dstip, avg_pkt_len
            ]
        else:
            # Should not occur due to validation in setup_model()
            features = [
                (sbytes + dbytes), srate, drate, 1 if ipv4_protocol == 6 else 0, ttl, max_iat, total_dur,
                n_in_conn_ip_srcip, n_in_conn_ip_dstip, avg_pkt_len,
                state_con, state_int, state_rst,
                fin_flag_number, syn_flag_number, psh_flag_number, ack_flag_number
            ]

        data = [features]
        test_instance = pd.DataFrame(data, columns=feature_names)
        data_test = np.array(test_instance)

        class_type = rf.predict(data_test)

        # Accumulate results
        global counter_malware
        counter_malware = counter_malware + class_type
        reg_attack_packets[register_index] = reg_attack_packets.get(register_index) + class_type
        reg_attack_flows[register_index] = (reg_attack_packets.get(register_index) / (spkts + dpkts))

# ----------------------------------------------------------------------
# INTERFACE DISCOVERY (kept for parity; not used in offline flow)
# ----------------------------------------------------------------------
def get_if():
    ifs = get_if_list()
    iface = None
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

# ----------------------------------------------------------------------
# PACKET HANDLER (per-scapy packet)
# ----------------------------------------------------------------------
def handle_pkt(pkt, protocol):
    """
    Decode scapy pkt into the arguments required by processPacket().
    protocol switch:
      1 => both TCP & UDP
      2 => TCP only
      3 => UDP only
    """
    if (IP in pkt):
        packetLen = pkt[IP].len + 14  # approx add Ethernet header size

        # TCP
        if ((protocol == 1 or protocol == 2) and TCP in pkt):
            tcp_fin = 1 if 'F' in str(pkt[TCP].flags) else 0
            tcp_syn = 1 if 'S' in str(pkt[TCP].flags) else 0
            tcp_rst = 1 if 'R' in str(pkt[TCP].flags) else 0
            tcp_psh = 1 if 'P' in str(pkt[TCP].flags) else 0
            tcp_ack = 1 if 'A' in str(pkt[TCP].flags) else 0
            tcp_urg = 1 if 'U' in str(pkt[TCP].flags) else 0
            tcp_ece = 1 if 'E' in str(pkt[TCP].flags) else 0
            tcp_cwr = 1 if 'C' in str(pkt[TCP].flags) else 0

            processPacket(
                pkt.time, packetLen, pkt[IP].src, pkt[IP].dst,
                pkt[TCP].sport, pkt[TCP].dport, pkt[IP].proto,
                tcp_fin, tcp_syn, tcp_rst, tcp_psh, tcp_ack, tcp_urg, tcp_ece, tcp_cwr, pkt[IP].ttl
            )

        # UDP
        elif ((protocol == 1 or protocol == 3) and UDP in pkt):
            processPacket(
                pkt.time, packetLen, pkt[IP].src, pkt[IP].dst,
                pkt[UDP].sport, pkt[UDP].dport, pkt[IP].proto,
                0, 0, 0, 0, 0, 0, 0, 0, pkt[IP].ttl
            )

# ----------------------------------------------------------------------
# MAIN: CLI -> MODEL SETUP -> PCAP PROCESSING -> SUMMARY
# ----------------------------------------------------------------------
def main():
    """
    Reads a pcap file, processes packets, and prints detection ratios.
    Now accepts CLI args for protocol and detector.
    """
    # -----------------------------
    # Command-line arguments
    # -----------------------------
    parser = argparse.ArgumentParser(description="Offline DDoS detector over PCAP using Random Forest.")
    parser.add_argument(
        "--protocol", type=int, choices=[1, 2, 3], default=3,
        help="1=TCP+UDP, 2=TCP only, 3=UDP only (default: 3)"
    )
    parser.add_argument(
        "--detector", type=int, choices=[10, 20, 11, 21, 12, 22], default=10,
        help="Model selector: 10/20 combined (time/notime), 11/21 TCP (time/notime), 12/22 UDP (time/notime). Default: 10"
    )
    parser.add_argument(
        "--pcap", type=str, default='ddos/attacks/Benign_1_MB_1.pcap',
        help="Path to input pcap (default: ddos/attacks/Benign_1_MB_1.pcap)"
    )
    args = parser.parse_args()

    # -----------------------------
    # Apply CLI args to original variables
    # -----------------------------
    global detector
    detector = args.detector  # keep the same variable name

    # Initialize model selection and load RF into 'rf'
    setup_model()

    # Input pcap file name (keep original variable name usage pattern)
    csv_file_name = args.pcap[:-5] if args.pcap.endswith(".pcap") else args.pcap

    # Read pcap
    pcap_flow = rdpcap(csv_file_name + ("" if csv_file_name.endswith(".pcap") else ".pcap"))

    # Protocol selector kept in a variable named 'protocol' (unchanged)
    protocol = args.protocol

    s = 0
    for pkt in pcap_flow:
        if (len(pkt) < 152000):  # guard for extremely large frames
            handle_pkt(pkt, protocol)
            s = s + 1

    # Summarize per-flow attack ratio (round to 1 => attack)
    sum = 0
    for values in reg_attack_flows.values():
        if (np.round(values) == 1):
            sum = sum + 1

    # Final stats
    print("=======================================================")
    print("Total packets:" + str(counter_pkts))
    print("Packets predicted as malicious:" + str(counter_malware))
    print("Percentage of packets predicted as malicious:" + str((counter_malware / counter_pkts)))
    print("=======================================================")
    print("Total flows:" + str(counter_flows))
    print("Flows predicted as malicious:" + str(sum))
    print("Percentage of flows predicted as malicious:" + str(sum / counter_flows))
    print("=======================================================")

# ----------------------------------------------------------------------
# ENTRY POINT
# ----------------------------------------------------------------------
if __name__ == '__main__':
    main()
# ----------------------------------------------------------------------
#
# EXAMPLES:
#   python Py_Classier.py --protocol 1 --detector 10 --pcap dataset/Benign_1_MB_1.pcap
#   python Py_Classier.py --protocol 2 --detector 21 --pcap dataset/sample.pcap
#
