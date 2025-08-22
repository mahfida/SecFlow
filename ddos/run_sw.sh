#!/bin/bash

# Usage:
#   ./run.sh [option]
# Options:
#   time-single       -> Use singleTime.p4 with combinedRulesTime.txt
#   time-separate     -> Use separateTime.p4 with TCP+UDP time rules
#   notime-single     -> Use single.p4 with combinedRules.txt
#   notime-separate   -> Use separate.p4 with TCP+UDP rules (no time)

# Load switch configs
simple_switch_CLI --thrift-port 9090 < topo/s1-commands.txt
simple_switch_CLI --thrift-port 9091 < topo/s2-commands.txt 
simple_switch_CLI --thrift-port 9092 < topo/s3-commands.txt 

# Check argument
if [ "$1" == "time-single" ]; then
    echo "Running: TIME-BASED SINGLE rules..."
    simple_switch_CLI --thrift-port 9090 < script_with_time/combinedRulesTime.txt

elif [ "$1" == "time-separate" ]; then
    echo "Running: TIME-BASED SEPARATE rules..."
    simple_switch_CLI --thrift-port 9090 < script_with_time/TCPRulesTime.txt
    simple_switch_CLI --thrift-port 9090 < script_with_time/UDPRulesTime.txt

elif [ "$1" == "notime-single" ]; then
    echo "Running: NO-TIME SINGLE rules..."
    simple_switch_CLI --thrift-port 9090 < script_no_time/combinedRules.txt

elif [ "$1" == "notime-separate" ]; then
    echo "Running: NO-TIME SEPARATE rules..."
    simple_switch_CLI --thrift-port 9090 < script_no_time/TCPRules.txt
    simple_switch_CLI --thrift-port 9090 < script_no_time/UDPRules.txt

else
    echo "Invalid option!"
    echo "Usage: ./run.sh [time-single | time-separate | notime-single | notime-separate]"
    exit 1
fi
