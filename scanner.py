from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
import dpkt

file = sys.argv[1]
packets = rdpcap(file)

def arpspoofing(file):
    cats = ['192.168.0.1007c:d1:c3:94:9e:b8', '192.168.0.103d8:96:95:01:a5:c9', '192.168.0.1f8:1a:67:cd:57:6e']
    i = 0
    while i < len(packets):
        pkt = packets[i]
        if pkt.haslayer(ARP):
            if pkt[ARP].op == 2:
                src_MAC = pkt[ARP].hwsrc
                src_IP = pkt[ARP].psrc
                dst_MAC = pkt[ARP].hwdst
                cat = src_IP + src_MAC
                if cat != cats[0] and cat != cats[1] and cat != cats[2]:
                    print("ARP spoofing!")
                    print("Src MAC: " + src_MAC)
                    print("Dst MAC: " + dst_MAC)
                    print("Packet Number: " + str(i))
        i += 1

def synflood(file):
    i = 0
    totalcount = 0
    dest = []
    times = []
    packetnums = []
    used = [0]
    flooded = False
    while i < len(packets):
        pkt = packets[i]
        n = 0
        while n < len(used):
            if pkt.haslayer(TCP) and pkt[TCP].dport == used[n]:
                flooded = True
            n += 1
        if pkt.haslayer(TCP) and flooded == False:
            time = pkt.time
            dst_port = pkt[TCP].dport
            dest.append(dst_port)
            times.append(time)
            totaltime = times[0]-time
            if dst_port == dest[0]:
                totalcount += 1
                packetnums.append(i)
            if totalcount > 100 and totaltime <= 1:
                print("SYN Floods!")
                print("Dst IP: " + str(pkt[IP].dst))
                print("Dst Port: " + str(dest[0]))
                print("Packet number: " + str(packetnums)[1:-1])
                used.append(dest[0])
                totalcount = 0
                dest = []
                times = []
                packetnums = []
        i += 1


if __name__ == '__main__':
    #arpspoofing(packets)
    synflood(packets)