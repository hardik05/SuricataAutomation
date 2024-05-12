########################################################################
# run_suricata.py
# Author: Hardik Shah
# Web: www.fuzzing.in
########################################################################

import os
import sys
import subprocess

def process_pcap_directories(directory, log_file):
    suricata_command = [
        "sudo",
        "suricata",
        "-c",
        "/etc/suricata/suricata.yaml",
        "-k",
        "none",
        "--runmode",
        "autofp",
        "-l",  # Added -l option for log file
        log_file,
        "-r"
    ]

    for root, dirs, _ in os.walk(directory):
        for d in dirs:
            pcap_dir = os.path.join(root, d)
            print("Processing Directory:", pcap_dir)
            subprocess.run(suricata_command + [pcap_dir])

if __name__ == "__main__":
    if len(sys.argv) != 3:  # Check for 3 arguments (script name, directory, log file)
        print("Usage: python suricata_recursively.py <directory> <log_file>")
        sys.exit(1)
    
    directory = sys.argv[1]
    log_file = sys.argv[2]
    
    if not os.path.isdir(directory):
        print("Error: Directory does not exist.")
        sys.exit(1)
    
    process_pcap_directories(directory, log_file)
