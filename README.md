# SecFlow
SecFlow — Setup & Usage Guide

## 1) Prerequisites

Create a VM with P4 switches and Mininet by following the official P4 tutorials:
https://github.com/p4lang/tutorials

## 2) Initial setup (inside the VM)

### 1.  After the VM is ready:


o   cd /home/p4/tutorials

o   Replace the existing utils folder with the utils folder.

### 2.  Place the ddos repository inside:

/home/p4/tutorials/exercises

### 3. Repository layout (key folders & files)

**3.1 attacks/**

•   Test PCAP files for benign and malicious flows.

**3.2 script_no_time/ (models without time-based features)**

•   separate.p4 — separate UDP/TCP detectors.

•   single.p4 — single detector for UDP & TCP.

•   basic.p4 — plain switching, no detection.

•   combinedRules.txt — match-action rules for tree-based models loaded by single.p4.

•   TCPRules.txt — match-action rules for the TCP model in separate.p4.

•   UDPRules.txt — match-action rules for the UDP model in separate.p4.

**3.3 script_with_time/ (models with time-based features)**

•   separateTime.p4 — separate UDP/TCP detectors.

•   singleTime.p4 — single detector for UDP & TCP.

•   basic.p4 — plain switching, no detection.

•   combinedRulesTime.txt — match-action rules for tree-based models loaded by singleTime.p4.

•   TCPRulesTime.txt — match-action rules for the TCP model in separateTime.p4.

•   UDPRulesTime.txt — match-action rules for the UDP model in separateTime.p4.

**3.4 results/**

•   Store CPU and memory usage plus dequeue delay of flow packets.
latency/

•   Per-packet processing delay information. Results are recorded as UTMs and require post-processing to compute per-packet delay (e.g., UTM(next packet) – UTM(current packet)).

**3.5 Top-level helper files & scripts**

•   ddos.p4 — the active P4 program to run. 

•   send_pcap.py — sends attack packets (set the desired PCAP inside the script).

•   receive_pcap.py — receives packets.

•   run_basic_sw.sh — runs basic.p4 so none of the three switches act as detectors.

•   run_ddos_sw.sh — runs switches as detectors (uncomment the rules you want to apply).

•   run_mn.sh — launches Mininet.

•   run_scripts.sh — opens Mininet terminals: h3 as receiver, h1 as sender.

•   topology_basic.json — three switches only switch packets (use with basic.p4).

•   topology_ddos.json — switch 1 acts as the detector (use with ddos.p4).

Note: Before running, copy the required topology file to topology.json.

•   mem_used.sh — records memory usage during simulation.

•   cpu_load.sh — records CPU load during simulation.

## 3) Converting PCAP to CSV

pcap2csv.py

Converts PCAP to CSV using the same feature extraction constraints as P4. The only expected discrepancy may be the packet timestamp (Python script vs. P4 software switch).

•   In main(), set the path to the input PCAP.

•   To process only TCP, only UDP, or both, set the protocol variable accordingly.

## 4) Optional: Python-side classifier

classifier.py
Runs trained models for the combined/single detector and the separate TCP/UDP detectors. Useful for comparing P4-based execution vs. Python execution, especially for time-based models.
Takes PCAPs as input, loads the appropriate model, and mirrors the P4 script workflow.

## 5) Training notebooks

•   AnomalyDetection-DDoS-TCP.ipynb — train detector & generate rules for TCP benign/malicious flows.

•   AnomalyDetection-DDoS-UDP.ipynb — train detector & generate rules for UDP benign/malicious flows.

•   AnomalyDetection-DDoS-Combined.ipynb — train detector & generate rules for combined UDP+TCP benign/malicious flows.

## 6) Dataset
dataset/
CSV files for various attacks and benign flows.
________________________________________
# Running the Simulator

## A) Start Mininet

Plain switching (no detection):
./run_mn.sh basic
Detection with ddos.p4:

 **For singleTime.p4**
./run_ms.sh ddos time-single

**For separateTime.p4**
./run_ms.sh ddos time-separate

**For single.p4 (no time)**
./run_ms.sh ddos notime-single

**For separate.p4 (no time)**
./run_ms.sh ddos notime-separate

## B) Load match-action rules onto switches

**For basic.p4**
./run_sw.sh

**For singleTime.p4 rules**
./run_sw.sh time-single

**For separateTime.p4 rules**
./run_sw.sh time-separate

**For single.p4 rules (no time)**
./run_sw.sh notime-single

**For separate.p4 rules (no time)**
./run_sw.sh notime-separate

## C) Send and receive traffic inside Mininet

In the Mininet terminal:
h3 ./receive.py &
h1 ./send.py

## D) View detection results (separate terminal)
./run_results.sh

## E) Exit Mininet
exit
Reminder: Before running, copy the intended topology file to topology.json and ensure ddos.p4 points to the P4 script you want to execute.





