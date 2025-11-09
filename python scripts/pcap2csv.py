#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
import csv
from sklearn import tree
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import RandomForestRegressor
from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, ByteField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw, PcapReader

# ----------------------------------------------------------------------
# SOME VARIABLES
# ----------------------------------------------------------------------
min_value = 100000000
max_value = 0
register_index = 0
is_first = 0
is_empty = 0
first_ack = 0
malware = 0
marked_malware = 0

# Store some statistics for the packets----------------------------
counter_pkts = 0
counter_malware = 0
counter_detection = 0
counter_no_detection = 0

# Store some statistics for the flows-----------------------------
counter_flows = 0
counter_flows_benign = 0
counter_timeout = 0
time_first_pkt = 0.0
iat = 0.0
min_iat = 1000000
max_iat = 0.0
total_duration = 0.0

# Registers used in the script ----------------------------------
reg_time_last_pkt = {0: 0}
reg_time_first_pkt = {0: 0}
reg_spkts = {0: 0}
reg_sbytes = {0: 0}
reg_dpkts = {0: 0}
reg_dbytes = {0: 0}
reg_attack_flows = {0: 0}
reg_benign_flows = {0: 0}
reg_attack_packets = {0: 0}
reg_min_iat = {0: 0}
reg_max_iat = {0: 0}
reg_min_pktLen = {0: 0}
reg_max_pktLen = {0: 0}
record_index_flowid = {0: 0}
record_index_inverse_flowid = {0: 0}
record_src_ip = {0: 0}
record_dst_ip = {0: 0}
first_packet_attack = 0
first_packet_benign = 0
csv_file_name = ""

# Features to be Retrieved -------------------------------------
columns = ["ts", 'srcip', 'dstip', 'srcport',
           'dstport', 'proto_type',
           "sbytes", "dbytes",
           "flow_bytes",
           "rate", "srate", "drate",
           "spkts", "dpkts", "ttl", "iat", "max_iat", "min_iat",
           "total_duration",
           "N_IN_Conn_P_Src_IP", "N_IN_Conn_P_Dst_IP",
           "avg_pkt_len",
           "state_con", "state_int", "state_rst",
           "fin_flag_number", "syn_flag_number",
           "psh_flag_number", "ack_flag_number", "urg_flag_number", "ece_flag_number", "cwr_flag_number"]
GH = pd.DataFrame(columns=columns)

# ----------------------------------------------------------------------
# RESET STATE BETWEEN FILES
# ----------------------------------------------------------------------
def reset_state():
    global GH, csv_file_name
    global min_value, max_value, register_index, is_first, is_empty, first_ack
    global malware, marked_malware
    global counter_pkts, counter_malware, counter_detection, counter_no_detection
    global counter_flows, counter_flows_benign, counter_timeout
    global time_first_pkt, iat, min_iat, max_iat, total_duration
    global reg_time_last_pkt, reg_time_first_pkt
    global reg_spkts, reg_sbytes, reg_dpkts, reg_dbytes
    global reg_attack_flows, reg_benign_flows, reg_attack_packets
    global reg_min_iat, reg_max_iat, reg_min_pktLen, reg_max_pktLen
    global record_index_flowid, record_index_inverse_flowid
    global record_src_ip, record_dst_ip
    global first_packet_attack, first_packet_benign

    # Reset scalars
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
    iat = 0.0
    min_iat = 1000000
    max_iat = 0.0
    total_duration = 0.0

    # Reset dict registers
    reg_time_last_pkt = {}
    reg_time_first_pkt = {}
    reg_spkts = {}
    reg_sbytes = {}
    reg_dpkts = {}
    reg_dbytes = {}
    reg_attack_flows = {}
    reg_benign_flows = {}
    reg_attack_packets = {}
    reg_min_iat = {}
    reg_max_iat = {}
    reg_min_pktLen = {}
    reg_max_pktLen = {}
    record_index_flowid = {}
    record_index_inverse_flowid = {}
    record_src_ip = {}
    record_dst_ip = {}

    first_packet_attack = 0
    first_packet_benign = 0

    # Fresh dataframe for this PCAP
    GH = pd.DataFrame(columns=columns)

# ----------------------------------------------------------------------
# EXTRACTING FEATURES FROM THE PCAP
# ----------------------------------------------------------------------
def processPacket(ts, packet_length, ipv4_srcAddr, ipv4_dstAddr,
                  srcPort, dstPort, ipv4_protocol,
                  fin_flag_number, syn_flag_number, rst_flag_number, psh_flag_number,
                  ack_flag_number, urg_flag_number, ece_flag_number,
                  cwr_flag_number, ttl):

    # Define parameters to be global-------------------------------------
    global GH
    global csv_file_name
    global iat, total_duration, min_iat, max_iat
    global is_first
    global register_index
    global counter_pkts
    global counter_flows
    global record_index_flowid
    global record_src_ip
    global record_dst_ip
    global reg_spkts, reg_sbytes, reg_dpkts, reg_dbytes
    global reg_time_first_pkt, reg_time_last_pkt
    global reg_min_iat, reg_max_iat

    # Initialize some variables---------------------------------------
    is_first = 0  # Not yet know that the flow is a new one
    state_con = 0
    state_rst = 0
    state_int = 0

    # Calculate all features-------------------------------------------
    if (ipv4_protocol == 6 or ipv4_protocol == 17):  # Only TCP or UDP
        # Packet counter
        counter_pkts = counter_pkts + 1

        # **** Direction of Flow ****
        flowid = f"{ipv4_srcAddr}-{ipv4_dstAddr}-{srcPort}-{dstPort}-{ipv4_protocol}"
        inverse_flowid = f"{ipv4_dstAddr}-{ipv4_srcAddr}-{dstPort}-{srcPort}-{ipv4_protocol}"

        if (flowid in record_index_flowid):
            direction = 1
            is_first = False
        elif (inverse_flowid in record_index_flowid):
            direction = 0
            is_first = False
        else:
            direction = 1
            is_first = True
            # Record flow information
            flow_index = len(record_index_flowid) + 1
            record_index_flowid[flowid] = flow_index
            reg_time_first_pkt[flowid] = ts
            reg_time_last_pkt[flowid] = ts
            # initialize other dictionaries
            reg_spkts[flowid] = 0
            reg_sbytes[flowid] = 0
            reg_dpkts[flowid] = 0
            reg_dbytes[flowid] = 0
            reg_max_iat[flowid] = 0
            reg_min_iat[flowid] = 1000000
            counter_flows = counter_flows + 1

            # Track IP occurrence counts
            if (str(ipv4_srcAddr) not in record_src_ip):
                record_src_ip[str(ipv4_srcAddr)] = 1
            else:
                record_src_ip[str(ipv4_srcAddr)] = record_src_ip.get(str(ipv4_srcAddr)) + 1

            if (str(ipv4_dstAddr) not in record_dst_ip):
                record_dst_ip[str(ipv4_dstAddr)] = 1
            else:
                record_dst_ip[str(ipv4_dstAddr)] = record_dst_ip.get(str(ipv4_dstAddr)) + 1

        # ********************************************
        # Direction = 1 (Source -> Destination)
        # ********************************************
        if direction == 1:
            n_in_conn_ip_srcip = record_src_ip.get(str(ipv4_srcAddr))
            n_in_conn_ip_dstip = record_dst_ip.get(str(ipv4_dstAddr))

            spkts = reg_spkts.get(flowid, 0) + 1
            reg_spkts[flowid] = spkts

            sbytes = reg_sbytes.get(flowid, 0) + packet_length
            reg_sbytes[flowid] = sbytes

            dbytes = reg_dbytes.get(flowid, 0)
            dpkts = reg_dpkts.get(flowid, 0)
            bytes_total = sbytes
            pkts_total = spkts
            register_index = flowid

        # ********************************************
        # Direction = 0 (Destination -> Source)
        # ********************************************
        else:
            n_in_conn_ip_srcip = record_src_ip.get(str(ipv4_dstAddr))
            n_in_conn_ip_dstip = record_dst_ip.get(str(ipv4_srcAddr))

            dpkts = reg_dpkts.get(inverse_flowid, 0) + 1
            reg_dpkts[inverse_flowid] = dpkts

            dbytes = reg_dbytes.get(inverse_flowid, 0) + packet_length
            reg_dbytes[inverse_flowid] = dbytes

            sbytes = reg_sbytes.get(inverse_flowid, 0)
            spkts = reg_spkts.get(inverse_flowid, 0)
            bytes_total = dbytes
            pkts_total = dpkts
            register_index = inverse_flowid

        # Common features ----------------------------
        time_first_pkt = reg_time_first_pkt.get(register_index, ts)
        time_last_pkt = reg_time_last_pkt.get(register_index, ts)
        iat = (ts - time_last_pkt)
        total_duration = ts - time_first_pkt
        min_iat = reg_min_iat.get(register_index, 1000000)
        max_iat = reg_max_iat.get(register_index, 0)

        if (iat > max_iat):
            max_iat = iat
            reg_max_iat[register_index] = max_iat

        if (iat < min_iat):
            min_iat = iat
            reg_min_iat[register_index] = min_iat

        reg_time_last_pkt[register_index] = ts

        if ((spkts + dpkts) > 1 and total_duration > 0):
            rate = (spkts + dpkts) / total_duration
            srate = spkts / total_duration
            drate = dpkts / total_duration
        else:
            rate = 0
            srate = 0
            drate = 0

        # calc_state()
        if (is_first == 1):
            if (ipv4_protocol == 17):
                state_int = 1
        else:
            state_con = 1
        if (ipv4_protocol == 6 and rst_flag_number == 1):
            state_rst = 1
            state_con = 0

        avg_pkt_len = (bytes_total / pkts_total) if pkts_total > 0 else 0

        # Store the instance into the dataframe ------------------
        new_row = {"ts": ts,
                   'srcip': (ipv4_srcAddr),
                   'dstip': (ipv4_dstAddr),
                   'srcport': srcPort,
                   'dstport': dstPort,
                   'proto_type': ipv4_protocol,
                   "sbytes": sbytes,
                   "dbytes": dbytes,
                   "flow_bytes": (sbytes + dbytes),
                   "rate": rate,
                   "srate": srate,
                   "drate": drate,
                   "spkts": spkts,
                   "dpkts": dpkts,
                   "ttl": ttl,
                   "iat": iat,
                   "max_iat": max_iat,
                   "min_iat": min_iat,
                   "total_duration": total_duration,
                   "N_IN_Conn_P_Src_IP": n_in_conn_ip_srcip,
                   "N_IN_Conn_P_Dst_IP": n_in_conn_ip_dstip,
                   "avg_pkt_len": avg_pkt_len,
                   "state_con": state_con,
                   "state_int": state_int,
                   "state_rst": state_rst,
                   "fin_flag_number": fin_flag_number,
                   "syn_flag_number": syn_flag_number,
                   "psh_flag_number": psh_flag_number,
                   "ack_flag_number": ack_flag_number,
                   "urg_flag_number": urg_flag_number,
                   "ece_flag_number": ece_flag_number,
                   "cwr_flag_number": cwr_flag_number}

        # Fast row add without deprecated append()
        GH.loc[len(GH)] = new_row

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
def handle_pkt(pkt, protocol):
    if (IP in pkt):
        packetLen = pkt[IP].len + 14  # include ethernet frame size
        # TCP Protocol -------
        if ((protocol == 1 or protocol == 2) and TCP in pkt):
            tcp_fin = 1 if 'F' in str(pkt[TCP].flags) else 0
            tcp_syn = 1 if 'S' in str(pkt[TCP].flags) else 0
            tcp_rst = 1 if 'R' in str(pkt[TCP].flags) else 0
            tcp_psh = 1 if 'P' in str(pkt[TCP].flags) else 0
            tcp_ack = 1 if 'A' in str(pkt[TCP].flags) else 0
            tcp_urg = 1 if 'U' in str(pkt[TCP].flags) else 0
            tcp_ece = 1 if 'E' in str(pkt[TCP].flags) else 0
            tcp_cwr = 1 if 'C' in str(pkt[TCP].flags) else 0

            processPacket(pkt.time, packetLen, pkt[IP].src, pkt[IP].dst,
                          pkt[TCP].sport, pkt[TCP].dport, pkt[IP].proto,
                          tcp_fin, tcp_syn, tcp_rst, tcp_psh, tcp_ack, tcp_urg, tcp_ece, tcp_cwr, pkt[IP].ttl)

        # UDP Protocol -------
        elif ((protocol == 1 or protocol == 3) and UDP in pkt):
            processPacket(pkt.time, packetLen, pkt[IP].src, pkt[IP].dst,
                          pkt[UDP].sport, pkt[UDP].dport, pkt[IP].proto,
                          0, 0, 0, 0, 0, 0, 0, 0, pkt[IP].ttl)

# ----------------------------------------------------------------------
def main():
    """
    Usage:
        python script.py /path/to/pcap_folder [output_folder] [--recursive]
    - If output_folder is omitted, CSVs are written next to each PCAP.
    - Add --recursive to walk subfolders.
    """
    # ---- Inputs ----
    if len(sys.argv) < 2:
        print("Usage: python script.py /path/to/pcap_folder [output_folder] [--recursive]")
        sys.exit(1)

    folder = sys.argv[1]
    out_dir = None
    recursive = False
    if len(sys.argv) >= 3 and sys.argv[2] != "--recursive":
        out_dir = sys.argv[2]
    if "--recursive" in sys.argv:
        recursive = True

    if not os.path.isdir(folder):
        print(f"Provided path is not a folder: {folder}")
        sys.exit(1)

    protocol = 1  # 1: tcp/udp, 2: tcp only, 3: udp only

    pcap_exts = {".pcap", ".pcapng"}
    pcaps = []

    if recursive:
        for root, _, files in os.walk(folder):
            for f in files:
                if os.path.splitext(f)[1].lower() in pcap_exts:
                    pcaps.append(os.path.join(root, f))
    else:
        for f in os.listdir(folder):
            fpath = os.path.join(folder, f)
            if os.path.isfile(fpath) and os.path.splitext(f)[1].lower() in pcap_exts:
                pcaps.append(fpath)

    if not pcaps:
        print(f"No pcap/pcapng files found in: {folder}")
        sys.exit(0)

    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    for pcap_path in sorted(pcaps):
        reset_state()

        base = os.path.splitext(os.path.basename(pcap_path))[0]
        if out_dir:
            csv_path_no_ext = os.path.join(out_dir, base)
        else:
            csv_path_no_ext = os.path.join(os.path.dirname(pcap_path), base)

        # Keep a friendly name for logs (not used for writing inside processPacket anymore)
        global csv_file_name
        csv_file_name = csv_path_no_ext

        print(f"[+] Processing {pcap_path} -> {csv_path_no_ext}.csv")

        # Stream packets safely
        try:
            with PcapReader(pcap_path) as pr:
                for pkt in pr:
                    try:
                        handle_pkt(pkt, protocol)
                    except Exception:
                        # Skip malformed packets
                        continue
        except Exception as e:
            print(f"[!] Error reading {pcap_path}: {e}")
            continue

        # Write once per file (fast)
        try:
            GH.to_csv(csv_path_no_ext + ".csv", index=False)
        except Exception as e:
            print(f"[!] Error writing CSV for {pcap_path}: {e}")

    print("------DONE--------")

# ----------------------------------------------------------------------
if __name__ == '__main__':
    main()
# ----------------------------------------------------------------------

# Run as
# # save CSVs into a separate folder
# python script.py /path/to/pcap_folder /path/to/output_folder