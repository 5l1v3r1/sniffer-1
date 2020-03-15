import progressbar
import time 
import os 
from scapy.all import *
import scapy
import argparse
import colorama
from colorama import Fore,Back,Style
colorama.init()
def parse_arguments():
 global path_to_file,protocol,interface,port
 parser = argparse.ArgumentParser(description="SNIFFER")
 parser.add_argument("--protocol", help="Type of protocol to sniff(tcp,upd)")
 parser.add_argument("--port",help="You can use this to capture specified kind of protocol e.g. '--port 80' will capture http")
 parser.add_argument("--write", help="Save to file path")
 parser.add_argument("interface", help="Interface to use")
 args= parser.parse_args()
 path_to_file= args.write
 protocol = args.protocol
 port=args.port
 interface=args.interface
def main():
 parse_arguments()
 create_sniff()
 sniff()
def create_sniff():
 global sniffer 
 print("Starting...")
 if str(protocol) != "None":
  print(protocol)
  sniffer = AsyncSniffer(iface=interface,filter=protocol)
 if str(port)!="None":
  print(port)
  sniffer = AsyncSniffer(iface=interface,filter="port "+port)
def animation():
 global bar
 right=False
 left=True
 count=0
 bar = progressbar.ProgressBar(maxval=100, widgets=['Capturing packets(Press CNTRL^C to stop):', progressbar.Bar(left=Fore.RED+'[', marker=Fore.GREEN+'~', right=Fore.RED+']'+Fore.RESET),progressbar.ReverseBar(left=Fore.RED+'[', marker=Fore.GREEN+'~', right=Fore.RED+']'+Fore.RESET),]).start()
 while True:
  if left == True:
   count+=1
   bar.update(count)
   time.sleep(0.03)
   if count == 100:
    left=False
    right=True
  if right==True:
   count=0
   left=True
   right=False
def sniff():
 sniffer.start()
 try:
  animation()
 except KeyboardInterrupt:
  bar.finish()
  sniffer.stop()
  save(sniffer.results)
def save(data):
 if str(path_to_file) != "None":
  print(Fore.RESET+"\n"+Fore.GREEN+"File was saved in {}".format(path_to_file))
  wrpcap(path_to_file,data)
 else:
  print(Fore.RESET+"\n"+Fore.GREEN+str(data))
main()
