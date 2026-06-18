# SecFlow
SecFlow — Setup & Usage Guide

## 1) Prerequisites

Create a VM with P4 switches and Mininet by following the official P4 tutorials:
https://github.com/p4lang/tutorials

## 2) Initial setup (inside the VM)

### 1.  After the VM is ready:


o   cd /home/p4/tutorials

o   Replace the existing utils folder with the utils folder given in the repository.

### 2.  Place the secflow repository inside:

/home/p4/tutorials/exercises

### 3. Repository layout (key folders & files)

**3.1 attacks/**

•   It consists of Test PCAP files for benign and malicious flows. When you are using any as a flow, you need to select it inside secflow/send_pcap.py

**3.2 script_no_time/ (models without time-based features)**

•   separate.p4 — A P4 script with separate UDP/TCP detectors.

•   single.p4 —  A P4 script with single detector for UDP & TCP.

•   basic.p4 —  A P4 script with plain forwarding/switching, no detection at any of the switch.

•   single.txt — A text file with match-action rules for tree-based models loaded by single.p4.

•   tcp.txt — A text file with match-action rules for the TCP model in separate.p4.

•   udp.txt — A text file with match-action rules for the UDP model in separate.p4.

**3.3 script_with_time/ (models with time-based features)**

•   separateTime.p4 — A P4 script with separate UDP/TCP detectors, where time based features are considered in the decision.

•   singleTime.p4 — A P4 script with single detector for UDP & TCP, where time based features are considered in the decision.

•   basic.p4 — A P4 script with plain switching, no detection.

•   singleTime.txt — A text file with match-action rules for tree-based models loaded by singleTime.p4.

•   tcpTime.txt — A text file with match-action rules for the TCP model in separateTime.p4.

•   udpTime.txt — A text file with match-action rules for the UDP model in separateTime.p4.

**3.4 results/**

•   Store CPU and memory usage plus dequeue delay of flow packets.
The results of the resources used and the delay observed during switch are stored inside latency/

•   Per-packet processing delay information. Results are recorded as UTMs and require post-processing to compute per-packet delay (e.g., UTM(next packet) – UTM(current packet)).

**3.5 Switch Commands and Topologies

It contains switching commands for the Mininet switches and topologies as follows:

•  topology_basic.json — three switches only forward/switch packets (it is used with basic.p4).

•   topology_sf.json — switch 1 acts as the detector but not the other two ( Switch 1 uses secflow.p4).

**3.6 Top-level helper files & scripts**

•   secflow.p4 — It is the active P4 program to run. Whenever a particular p4 script needs to be run, it is first copied into secflow.p4 

•   send_pcap.py — It sends attack packets (set the desired PCAP inside the script).

•   receive_pcap.py — It receives packets and resides at the destination host.

•   run_basic_sw.sh — This bach script runs basic.p4 so none of the three switches act as detectors.

•   run_sw.sh — This bach script runs switche 1 as detector.
 Usage: ./run.sh [no-option] -> Runs basic.p4
 	./run.sh [option]
	Options:
	1. time-single       -> Uses singleTime.p4 with singleTime.txt
	2. time-separate     -> Uses separateTime.p4 with TCP+UDP time rules that are inside tcpTime.txt and udpTime.txt
	3. notime-single     -> Uses single.p4 with single.txt (no time based features in the decision rules)
	4. notime-separate   -> Uses separate.p4 with TCP+UDP rules (no time based features in the decision rules)

•   run_mn.sh [arg1] [arg2 option]— launches Mininet (see options within the script)
	arg1: 'basic' uses basic topology, while 'sf' uses topology for secflow.
	arg2: this is used if arg1 is 'sf', it tells p4 script is needed to be run (i.e., time-single, time-separate, notime-single, notime-separate)
•   run_scripts.sh — It opens Mininet terminals: h3 as receiver, h1 as sender.

•   run_results.sh- It retrieves classification results from the get_result.txt file


Note: Before running, copy the required topology file i.e., either topology_basic.json or topology_sf.json (from topo/) to topo/topology.json.

•   mem_used.sh — It records memory usage during simulation.

•   cpu_load.sh — It records CPU load during simulation.

## 3) Converting PCAP to CSV

PCAP2CSV.py

Converts PCAP to CSV using the same feature extraction constraints as P4. The only expected discrepancy may be the packet timestamp (Python script vs. P4 software switch).

•   In main() function of 'python scripts/pcap2csv.py', set the path to the input PCAP file. 
•   To process only TCP, only UDP, or both, set the 'protocol' variable accordingly. The 'protocol' variable can be set to 1: tcp/udp, 2: tcp only or 3: udp only

## 4) Optional: Python-side classifier

PyClassifier.py
Runs trained models for the single detector and the separate TCP/UDP detectors. Useful for comparing P4-based execution vs. Python execution, especially for time-based models.
Takes PCAPs as input, loads the appropriate model, and mirrors the P4 script workflow.
## 5) runner.py (Helps in running PyClassifier.py on different datasets and different detectors)

## 6) Training notebooks

•   AnomalyDetection-TCP-NoTime.ipynb — It trains detector & generates rules for TCP benign/malicious flows, without using time-based features.

•   AnomalyDetection-TCP-WithTime.ipynb — It trains detector & generates rules for TCP benign/malicious flows using time-based features.


•   AnomalyDetection-UDP-NoTime.ipynb — It trains detector & generates rules for UDP benign/malicious flows, without using time-based features.

•   AnomalyDetection-UDP-WithTime.ipynb — It trains detector & generates rules for UDP benign/malicious flows using time-based features.

•   AnomalyDetection-Combined-NoTime.ipynb — It trains detector & generates rules for combined UDP+TCP benign/malicious flows using no time-based features.

•   AnomalyDetection-Combined-WithTime.ipynb — It trains detector & generates rules for combined UDP+TCP benign/malicious flows using time-based features.

## 6) dataset
dataset/
CSV files for various attacks and benign flows.
________________________________________
# Running the Simulator

## 7) Rscripts-Visualization
Consists of scripts for creating comparative charts

## A) Start Mininet

Plain switching (no detection using basic switch):
./run_mn.sh basic

Detection with secflow:
 **For singleTime.p4**
./run_mn.sh sf time-single

**For separateTime.p4**
./run_mn.sh sf time-separate

**For single.p4 (no time)**
./run_mn.sh sf notime-single

**For separate.p4 (no time)**
./run_mn.sh sf notime-separate

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
h3 ./receive_pcap.py &
h1 ./send_pcap.py

## D) View detection results (separate terminal)
./run_results.sh

## E) Exit Mininet
exit
Reminder: Before running, copy the intended topology file to topology.json and ensure flowsec.p4 contains the P4 script you want to execute.





