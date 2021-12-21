
from scapy.all import *
import os

pkts=sniff(iface="enp0s3",filter="arp",count=10)
fname=input("Enter the file name to save the sniffed packets to: ")
wrpcap("/home/jegadeesh/Documents/CN/{fname}.cap",pkts)

c_dict={}

def get_macbyip(ipaddr):
    broadcastpkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ipaddr)
    ans, unans = srp(broadcastpkt, timeout=2, verbose=False)
    mac = ans[0][1].hwsrc
    return mac


def check_attack():
    pkts1 = rdpcap("/home/jegadeesh/Documents/CN/{fname}.cap")
    flag = False
    for pkt in pkts1:
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:
            ip = pkt[ARP].psrc
            orgmac = get_macbyip(ip)
            dupmac = pkt[ARP].hwsrc
            c_dict[orgmac]=dupmac
         
    print("---------------ARP SPOOF ATTACK DETECTION----------------")
    print("MESSAGE ALERT:\t\t\tREALMAC:\t\t\tFAKEMAC:")
    for key in c_dict:
       if(key!=c_dict[key]):
          flag=True
          print(f"You are under attack!\t\t{key}\t\t{c_dict[key]}")
       else:
          print(f"You are Safe\t\t\t{key}\t\t\t{c_dict[key]}") 
    
    if(flag):
      gip=input("Enter your gateway Ip: ")
      gmac=get_macbyip(gip)
      os.system(f"sudo arp -s {gip} {gmac}")
      print("You have been saved from ARP Spoof Attack") 	   

check_attack()
