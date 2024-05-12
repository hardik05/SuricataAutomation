# SuricataAutomation
## What is it?
Many times we have huge pcap file(s) and we want to check them for suricata detection. Also we want to extract specific session on which the rule has triggered. This is a time consuming task. So this project automates everything from running suricata, generating alerts and extracting related session and store them as pcap.
## What is required?
You need to have suricata,python3 and wireshark installed. You also need to enable pcapfile name in eve.log. you can change this setting in suricata configuration yaml file.
## How to use it?
1. First use run_suricata.py as follows:
   python3 run_suricata.py <dir containing test pcap> <dir name for suricata log files>
   note: you need to create dir for log files if it doesnot exists.
   This will generate fast.log, suricata.log, eve.log and other files.
2. Then you can simply run second script:
   extract_eve_multi_ipv6.py <path to eve.log>
   This will parse eve.log file and then extract signature id, signature name,src/dst ip and ports and create a new folder with signatureid_signaturename, it then runs tshark for     the src/dstip/port pair and will extract requires sessions. In this way you will have pcap organized by signature id and signature namea and only relevent sessions will be         present which will avoid noise.
## Limitaitons?
It does not support ICMP and Fragmented IP packets yet. This will require some tshark command line changes. Pull requests are always welcome.
## Credits
Hardik Shah
[https://twitter.com/hardik05]
