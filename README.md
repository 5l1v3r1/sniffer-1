# sniffer
Simple script on Python3 which sniffs trafic                                 
# INSTALL                                               
git clone https://github.com/zertmark/sniffer.git                                            
cd sniffer && chmod +x installer.sh && ./installer.sh                                  
# RUN                                 
python3 sniffer.py interface(e.g. eth0,wlan0) --port(e.g. 80) or --protocol(e.g. tcp,upd) --write <path_to_file>
