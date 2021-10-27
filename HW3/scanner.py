import dpkt
import socket
import sys
from collections import defaultdict, deque
from itertools import chain


def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def mac_to_str(address):
    return ":".join(f"{b:02x}" for b in address)


def arpspoofing(pcap):
    realmap = {
        "192.168.0.100": "7c:d1:c3:94:9e:b8",
        "192.168.0.103": "d8:96:95:01:a5:c9",
        "192.168.0.1": "f8:1a:67:cd:57:6e",
    }
    for pnum, (_, buf) in enumerate(pcap):
        eth = dpkt.ethernet.Ethernet(buf)
        if not (isinstance(eth.data, dpkt.arp.ARP) and eth.data.op == 2):
            continue
        spa = inet_to_str(eth.data.spa)
        sha = mac_to_str(eth.data.sha)
        if spa in realmap and sha != realmap[spa]:
            print("ARP spoofing!")
            print(f"Src MAC: {sha}")
            print(f"Dst MAC: {mac_to_str(eth.data.tha)}")
            print(f"Packet number: {pnum}")


def portscan(pcap):
    data = defaultdict(
        lambda: (set(), [])
    )  # key: dst, value: (set(ports), [packet numbers])
    for pnum, (_, buf) in enumerate(pcap):
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        ip = eth.data
        if not (
            (isinstance(ip.data, dpkt.tcp.TCP) and ip.data.flags == 2)
            or isinstance(ip.data, dpkt.udp.UDP)
        ):
            continue
        dst = ip.dst
        dport = ip.data.dport
        if dport not in data[dst][0]:
            data[dst][0].add(dport)
            data[dst][1].append(pnum)

    for dst, (ports, pnums) in data.items():
        if len(ports) >= 100:
            print("Port scan!")
            print(f"Dst IP: {inet_to_str(dst)}")
            print(f"Packet number: {', '.join(map(str, pnums))}")


def synflood(pcap):
    synpkts = defaultdict(list)  # key (src, sport, dst, dport, seq)
    for pnum, (ts, buf) in enumerate(pcap):
        eth = dpkt.ethernet.Ethernet(buf)
        if not (
            isinstance(eth.data, dpkt.ip.IP) and isinstance(eth.data.data, dpkt.tcp.TCP)
        ):
            continue
        ip = eth.data
        tcp = eth.data.data
        if tcp.flags == 0x2:  # SYN
            key = (ip.src, tcp.sport, ip.dst, tcp.dport, tcp.seq)
            synpkts[key].append((pnum, ts, ip.dst, tcp.dport))
        elif tcp.flags == 0x10:  # ACK
            key = (ip.src, tcp.sport, ip.dst, tcp.dport, tcp.seq - 1)
            if key in synpkts and synpkts[key]:
                synpkts[key].pop()

    data = defaultdict(deque)
    for pnum, ts, dst, dport in sorted(chain.from_iterable(synpkts.values())):
        key = (dst, dport)
        if len(data[key]) > 100:
            continue
        data[key].append((pnum, ts))
        while ts - data[key][0][1] > 1:
            data[key].popleft()
        if len(data[key]) > 100:
            print("SYN floods!")
            print(f"Dst IP: {inet_to_str(dst)}")
            print(f"Dst Port: {dport}")
            print(f"Packet number: {', '.join(map(lambda x: str(x[0]), data[key]))}")


def main():
    assert len(sys.argv) == 2
    with open(sys.argv[1], "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        arpspoofing(pcap)
        f.seek(0)
        pcap = dpkt.pcap.Reader(f)
        portscan(pcap)
        f.seek(0)
        pcap = dpkt.pcap.Reader(f)
        synflood(pcap)


if __name__ == "__main__":
    main()
