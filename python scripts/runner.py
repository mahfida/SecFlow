#!/usr/bin/env python3
"""
runner.py

Usage examples:
    # run all six commands using attacks.pcap inside ../ddos/attacks/
    python runner.py --pcap-file attacks.pcap

    # run only tcp-time and udp-notime
    python runner.py --pcap-file attacks.pcap tcp-time udp-notime

    # keep running even if a script fails
    python runner.py --pcap-file attacks.pcap --continue-on-error
"""

import argparse
import subprocess
import sys
from pathlib import Path

# Map human labels -> (protocol, detector)
TASKS = [
    ("combined_time",   {"protocol": "1", "detector": "10"}),
    ("combined-notime", {"protocol": "1", "detector": "20"}),
    ("tcp-time",        {"protocol": "2", "detector": "11"}),
    ("tcp-notime",      {"protocol": "2", "detector": "21"}),
    ("udp-time",        {"protocol": "3", "detector": "12"}),
    ("udp-notime",      {"protocol": "3", "detector": "22"}),
]

LABELS = [label for label, _ in TASKS]

def build_cmd(label, pcap_path):
    # find task
    for lbl, params in TASKS:
        if lbl == label:
            cmd = [
                sys.executable,  # uses the same python interpreter running this script
                "Py_Classifier.py",
                "--protocol", params["protocol"],
                "--detector", params["detector"],
                "--pcap", str(pcap_path)
            ]
            return cmd
    raise ValueError(f"Unknown label '{label}'")

def run_label(label, pcap_path, continue_on_error=False):
    print(f"\n{label}\n{'='*40}")
    cmd = build_cmd(label, pcap_path)
    print("Running command:", " ".join(cmd))
    try:
        result = subprocess.run(cmd, check=True)
        print(f"\n✅ Finished {label} (exit {result.returncode})")
    except subprocess.CalledProcessError as e:
        print(f"\n❌ {label} failed with exit code {e.returncode}")
        if not continue_on_error:
            sys.exit(e.returncode)

def main():
    parser = argparse.ArgumentParser(description="Run Py_Classifier variants with a chosen pcap file.")
    parser.add_argument("--pcap-file", required=True,
                        help="Name of the pcap file located inside ../ddos/attacks/ (e.g. attacks.pcap)")
    parser.add_argument("labels", nargs="*", default=["all"],
                        help="Which labels to run (defaults to all). Valid values: " + ", ".join(LABELS))
    parser.add_argument("--continue-on-error", action="store_true",
                        help="If set, runner continues to next script even when one fails.")
    args = parser.parse_args()

    # Build full pcap path and validate
    #base = Path("../ddos/attacks")
    base = Path("../pcaps")
    pcap_path = base / args.pcap_file
    if not pcap_path.exists():
        print(f"❌ pcap file not found: {pcap_path}")
        sys.exit(2)

    # Decide which labels to run
    if args.labels == ["all"]:
        to_run = LABELS
    else:
        # validate labels
        unknown = [lab for lab in args.labels if lab not in LABELS]
        if unknown:
            print(f"❌ Unknown label(s): {unknown}")
            print("Valid labels:", ", ".join(LABELS))
            sys.exit(3)
        to_run = args.labels

    # Run sequentially
    for label in to_run:
        run_label(label, pcap_path, continue_on_error=args.continue_on_error)

if __name__ == "__main__":
    main()

#python runner.py --pcap-file mycapture.pcap
