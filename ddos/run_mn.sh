#!/bin/bash

# Usage:
#   ./copy.sh option
sudo mn -c

if [ "$1" == "basic" ]; then
    echo "Use basic topology"
    cp topo/topology_basic.json topo/topology.json

elif [ "$1" == "ddos" ]; then
    echo "Use ddos topology"
    cp topo/topology_ddos.json topo/topology.json
    
    # Check argument two
    if [ "$2" == "time-single" ]; then
	echo "Running: TIME-BASED SINGLE rules..."
	cp script_with_time/singleTime.p4 ddos.p4
    elif [ "$2" == "time-separate" ]; then
	echo "Running: TIME-BASED SEPARATE rules..."
	cp script_with_time/separateTime.p4 ddos.p4
    elif [ "$2" == "notime-single" ]; then
	echo "Running: NO-TIME SINGLE rules..."
	cp script_no_time/single.p4 ddos.p4
    elif [ "$2" == "notime-separate" ]; then
	echo "Running: NO-TIME SEPARATE rules..."
	cp script_no_time/separate.p4 ddos.p4
    fi
fi

make
#./run_sw.sh $2
