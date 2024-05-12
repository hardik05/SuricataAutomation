########################################################################
# Extract_Snort_Eve.py
# Author: Hardik Shah
# Web: www.fuzzing.in
########################################################################

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_address

processed_signature_ids = set()

def process_session(data):
    try:
        signature_id = data['alert']['signature_id']
        if signature_id in processed_signature_ids:
            # Skip processing if signature ID has already been processed
            return
        processed_signature_ids.add(signature_id)
        signature = data['alert']['signature'].replace('/', '_').replace(' ', '_').replace('(','_').replace(')','_').replace('.','')
        pcap_name = data['pcap_filename']
        src_ip = data['src_ip']
        src_port = data['src_port']
        dst_ip = data['dest_ip']
        dst_port = data['dest_port']
        src_ip_version = ip_address(src_ip).version
        dst_ip_version = ip_address(dst_ip).version
        folder_name = f"{signature_id}_{signature}"
        print(f"Signature ID: {signature_id}, Signature: {signature}, PCAP Name: {pcap_name}")
        folder_path = os.path.join(os.getcwd(), folder_name)
        os.makedirs(folder_path, exist_ok=True)
        # Use tshark to filter sessions based on IP and port
        tshark_pcap_path = os.path.join(folder_path, f"{signature_id}_{signature}.pcap")
        # Handle spaces in directory name
        folder_path = f'"{folder_path}"' if ' ' in folder_path else folder_path        
        if src_ip_version == 4 and dst_ip_version == 4:
            tshark_command = f"tshark -r \"{pcap_name}\" -Y \"(((ip.src == {src_ip} and ip.dst == {dst_ip} and tcp.srcport == {src_port} and tcp.dstport == {dst_port}) or (ip.src == {dst_ip} and ip.dst == {src_ip} and tcp.srcport == {dst_port} and tcp.dstport == {src_port})) or ((udp.srcport == {src_port} and udp.dstport == {dst_port}) and (ip.src == {src_ip} and ip.dst == {dst_ip})) or ((ip.src == {dst_ip} and ip.dst == {src_ip} and (udp.srcport == {dst_port} and udp.dstport == {src_port}))))\" -w {tshark_pcap_path}"
        elif src_ip_version == 6 and dst_ip_version == 6:
            tshark_command = f"tshark -r \"{pcap_name}\" -Y \"(((ipv6.src == {src_ip} and ipv6.dst == {dst_ip} and tcp.srcport == {src_port} and tcp.dstport == {dst_port}) or (ipv6.src == {dst_ip} and ipv6.dst == {src_ip} and tcp.srcport == {dst_port} and tcp.dstport == {src_port})) or ((udp.srcport == {src_port} and udp.dstport == {dst_port} and (ipv6.src == {src_ip} and ipv6.dst == {dst_ip})) or ((ipv6.src == {dst_ip} and ipv6.dst == {src_ip}) and udp.srcport == {dst_port} and udp.dstport == {src_port})))\" -w {tshark_pcap_path}"
        else:
            print("Mixed IPv4 and IPv6 addresses are not supported.")
            return
        subprocess.run(tshark_command, shell=True, check=True)
        # Check if the generated pcap file is valid
        if not is_valid_pcap(tshark_pcap_path):
            print(f"WARNING: Invalid pcap file generated for {signature}.pcap")
        # Write tshark command to a text file for debugging
        with open(os.path.join(folder_path, "tshark_command.txt"), 'w') as cmd_file:
            cmd_file.write(tshark_command)
    except json.JSONDecodeError:
        # Skip invalid JSON lines
        pass

def is_valid_pcap(pcap_path):
    try:
        # Use tshark to check if the pcap file is valid
        tshark_command = f"tshark -r {pcap_path} -qz io,phs"
        result = subprocess.run(tshark_command, shell=True, capture_output=True, text=True)
        if "captured packets" in result.stdout:
            return True
        else:
            return False
    except subprocess.CalledProcessError:
        # Error occurred while checking pcap validity
        return False

def filter_sessions_with_tshark(eve_log_file):
    with open(eve_log_file, 'r') as f:
        executor = ThreadPoolExecutor(max_workers=5)  # Adjust the number of threads as needed
        futures = []
        for line in f:
            try:
                data = json.loads(line)
                if 'alert' in data:
                    future = executor.submit(process_session, data)
                    futures.append(future)
            except json.JSONDecodeError:
                # Skip invalid JSON lines
                continue
        # Wait for all futures to complete
        for future in futures:
            future.result()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <eve.log>")
        sys.exit(1)
    
    eve_log_file = sys.argv[1]
    filter_sessions_with_tshark(eve_log_file)
