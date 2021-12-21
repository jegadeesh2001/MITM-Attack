from scapy.all import *

from scapy.layers.inet import TCP
pkts=sniff(iface="eth0",filter="port 80",count=60)

fileloc="/home/jegadeesh/Documents/CN/"
file=input("Enter the file name to save the packets to: ")
filepath=fileloc+"/"+file+".cap"
wrpcap(filepath,pkts)

def check_payload():
    pkts1 = rdpcap(filepath)
    print("----------------------------------------Sniffed Information from the victim-----------------------------------------------")
    print("SourecIp\t\tDestinationIp\t\tDestinationPort\t\tPayload")
    for pkt in pkts1:
        if pkt[TCP].payload:
            if pkt[IP].dport==80:
                print(f"{pkt[IP].src}\t\t{pkt[IP].dst}\t\t{pkt[IP].dport}\t\tstr{(bytes(pkt[TCP].payload))}")
                print("-------------------------------------------------------------------------------------------------------------------------------")

check_payload()
