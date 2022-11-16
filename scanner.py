from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether, getmacbyip
import dpkt
import datetime
import socket
from dpkt.compat import compat_ord

file = sys.argv[1]
packets = rdpcap(file)

def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)


def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def print_packets(pcap):
    """Print out information about each packet in a pcap

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:

        # Print out the timestamp in UTC
        # print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        # print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)

        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            #print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        # Now unpack the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data

        packetType = ip.data.__class__.__name__
        # if(packetType == "TCP"):
        #     tcp = ip.data
        #     if(tcp.flags == 2): # i.e TH_SYN = 2

        #         break

        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        # Print out the info
        # print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
        #       (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))


def arpspoofing(file):
    cats = ['192.168.0.1007c:d1:c3:94:9e:b8', '192.168.0.103d8:96:95:01:a5:c9', '192.168.0.1f8:1a:67:cd:57:6e', '192.168.0.10160:fe:c5:9e:63:3c']
    i = 0
    while i < len(packets):
        pkt = packets[i]
        if pkt.haslayer(ARP):
            if pkt[ARP].op == 2:
                src_MAC = pkt[ARP].hwsrc
                src_IP = pkt[ARP].psrc
                dst_MAC = pkt[ARP].hwdst
                cat = src_IP + src_MAC
                if cat != cats[0] and cat != cats[1] and cat != cats[2] and cat != cats[3]:
                    print("ARP spoofing!")
                    print("Src MAC: " + src_MAC)
                    print("Dst MAC: " + dst_MAC)
                    print("Packet Number: " + str(i))
        i += 1


def detectPortScanning(file):
    destinations = {}
    packetNumber = {}
    i = 0
    f = open(file,'rb')
    pcap = dpkt.pcap.Reader(f)

    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:
        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        # print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)

        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            #print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            i += 1
            continue

        # Now unpack the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data
        destAddr = inet_to_str(ip.dst)

        packetType = ip.data.__class__.__name__
        if(packetType == "TCP"):
            # Unpacking data within the IP frame ( the TCP packet )
            # Pulling out sport, dport, seq, ack, _off, flags, win, sum, urp
            tcp = ip.data
            destPort = tcp.dport

            if(tcp.flags == 2): # i.e TH_SYN = 2
                if(destinations.get(destAddr) != None):
                    # Check if already contains specified port
                    listOfPorts = destinations.get(destAddr)
                    packetPort = packetNumber.get(destAddr)
                    if(destPort in listOfPorts):
                        i += 1
                        continue
                    else:
                        listOfPorts.append(destPort)
                        packetPort.append(i)
                else:
                        destinations[destAddr] = [destPort]
                        packetNumber[destAddr] = [i]

        if(packetType == "UDP"):
            # Unpacking data within the IP frame ( the UDP packet )
            # Pulling out sport, dport, ulen, sum
            udp = ip.data
            destPort = udp.dport
            if(destinations.get(destAddr) != None):
                # Check if already contains specified port
                listOfPorts = destinations.get(destAddr)
                packetPort = packetNumber.get(destAddr)
                if(destPort in listOfPorts):
                    i += 1
                    continue
                else:
                    listOfPorts.append(destPort)
                    packetPort.append(i)
            else:
                destinations[destAddr] = [destPort]
                packetNumber[destAddr] = [i]
        i += 1

    for key in destinations.keys():
    # Check if ip address has 100 or more ports checked
        if(len(destinations.get(key)) >= 100):
            # Sending a port scan message
            print("Port scan!")
            print(f'Dst IP: {key}')
            print("Packet number:", end=" ")
            print(*packetNumber.get(key),sep=", ")


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
    arpspoofing(packets)
    detectPortScanning(file)
    synflood(packets)