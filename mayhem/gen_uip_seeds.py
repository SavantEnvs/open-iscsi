#!/usr/bin/env python3
"""Regenerates mayhem/fuzz_uip_packet/testsuite/ (frame-sequence seeds for fuzz_uip_packet.c).

Seed layout: 1 selector byte (low 2 bits: IPv4 mode 1=static 2=DHCP, next 2 bits:
IPv6 mode 1=static 2/3=DHCP), then [u16le length][Ethernet frame]* records.
"""
import os
import struct
import sys

MAC = bytes.fromhex("001122334455")      # NIC_MAC in fuzz_uip_packet.c
PEER = bytes.fromhex("02aabbccddee")
BCAST = b"\xff" * 6
ALL_NODES_MAC = bytes.fromhex("333300000001")
SRV_MAC = bytes.fromhex("333300010002")

ETH_IP, ETH_ARP, ETH_IP6 = 0x0800, 0x0806, 0x86DD


def eth(dst, src, typ, payload):
    return dst + src + struct.pack(">H", typ) + payload


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(">%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ip4(src, dst, proto, payload, ttl=64):
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, ttl, proto, 0, src, dst)
    hdr = hdr[:10] + struct.pack(">H", csum(hdr)) + hdr[12:]
    return hdr + payload


def udp4(sport, dport, payload):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def ip6(src, dst, nxt, payload, hop=255):
    return struct.pack(">IHBB16s16s", 6 << 28, len(payload), nxt, hop, src, dst) + payload


def addr6(s):
    import socket
    return socket.inet_pton(socket.AF_INET6, s)


LL = addr6("fe80::1")
NIC_LL = addr6("fe80::0211:22ff:fe33:4455")
ALLNODES = addr6("ff02::1")
HOST6 = addr6("2001:db8::10")
HOST4 = bytes([192, 168, 1, 10])
PEER4 = bytes([192, 168, 1, 1])


def icmp6(typ, code, body):
    return struct.pack(">BBH", typ, code, 0) + body


def ra(flags=0x80, with_prefix=True):
    body = struct.pack(">BBHII", 64, flags, 1800, 0, 0)
    if with_prefix:
        body += struct.pack(">BBBBIII", 3, 4, 64, 0xC0, 86400, 14400, 0) + addr6("2001:db8::")
    return eth(ALL_NODES_MAC, PEER, ETH_IP6, ip6(LL, ALLNODES, 58, icmp6(134, 0, body)))


def dhcp6(msg, opts):
    # transaction id as ipv6_udp_handle_dhcp() compares it for MAC ..:33:44:55
    hdr = bytes([msg, 0x33, 0x23, 0x00])
    pl = hdr + opts
    udp = struct.pack(">HHHH", 547, 546, 8 + len(pl), 0) + pl
    return eth(MAC, SRV_MAC, ETH_IP6, ip6(LL, NIC_LL, 17, udp))


def opt6(code, data):
    return struct.pack(">HH", code, len(data)) + data


def ia_na(addr):
    iaaddr = opt6(5, addr + struct.pack(">II", 3600, 7200))
    return opt6(3, struct.pack(">III", 0x306373, 1800, 2880) + iaaddr)


def dhcp4(msgtype, extra=b""):
    m = struct.pack(">BBBB4sHH4s4s4s4s", 2, 1, 6, 0, bytes([0xAD, 0xDE, 0x12, 0x23]), 0, 0x8000,
                    b"\0" * 4, bytes([192, 168, 1, 77]), b"\0" * 4, b"\0" * 4)
    m += MAC + b"\0" * 10 + b"\0" * 64 + b"\0" * 128
    m += bytes([99, 130, 83, 99])
    m += bytes([53, 1, msgtype]) + bytes([1, 4, 255, 255, 255, 0, 3, 4, 192, 168, 1, 1, 6, 4, 8, 8, 8, 8, 51, 4, 0, 1, 81, 128, 54, 4, 192, 168, 1, 1])
    m += extra + b"\xff"
    return eth(BCAST, PEER, ETH_IP, ip4(PEER4, b"\xff" * 4, 17, udp4(67, 68, m)))


def arp(op, spa, tpa, tha=b"\0" * 6):
    body = struct.pack(">HHBBH6s4s6s4s", 1, 0x0800, 6, 4, op, PEER, spa, tha, tpa)
    return eth(BCAST if op == 1 else MAC, PEER, ETH_ARP, body)


def echo4():
    icmp = struct.pack(">BBHHH", 8, 0, 0, 1, 1) + b"abcdefgh"
    icmp = icmp[:2] + struct.pack(">H", csum(icmp)) + icmp[4:]
    return eth(MAC, PEER, ETH_IP, ip4(PEER4, HOST4, 1, icmp))


def tcp_syn(dport):
    hdr = struct.pack(">HHIIBBHHH", 40000, dport, 1000, 0, 0x60, 0x02, 4096, 0, 0) + bytes([2, 4, 5, 0xB4])
    return eth(MAC, PEER, ETH_IP, ip4(PEER4, HOST4, 6, hdr))


def ns6():
    body = struct.pack(">I", 0) + HOST6 + bytes([1, 1]) + PEER
    return eth(MAC, PEER, ETH_IP6, ip6(addr6("fe80::2"), HOST6, 58, icmp6(135, 0, body)))


def na6():
    body = struct.pack(">I", 0x60000000) + addr6("fe80::2") + bytes([2, 1]) + PEER
    return eth(MAC, PEER, ETH_IP6, ip6(addr6("fe80::2"), NIC_LL, 58, icmp6(136, 0, body)))


def echo6():
    body = struct.pack(">HH", 1, 1) + b"abcdefgh"
    return eth(MAC, PEER, ETH_IP6, ip6(addr6("fe80::2"), NIC_LL, 58, icmp6(128, 0, body)))


def udp6_other():
    udp = struct.pack(">HHHH", 5000, 5001, 8 + 4, 0) + b"ping"
    return eth(MAC, PEER, ETH_IP6, ip6(addr6("fe80::2"), NIC_LL, 17, udp))


def seed(sel, frames):
    out = bytes([sel])
    for f in frames:
        out += struct.pack("<H", len(f)) + f
    return out


SEEDS = {
    "dhcpv6_advertise_reply": seed(0b1000, [
        ra(), dhcp6(2, opt6(1, b"\0" * 10) + opt6(2, b"\0\1\0\1\0\0\0\0" + PEER) + ia_na(addr6("2001:db8::77")) + opt6(23, addr6("2001:db8::53"))),
        dhcp6(7, opt6(1, b"\0" * 10))]),
    "dhcpv6_ra_only": seed(0b1000, [ra(0x40, True)]),
    "ndp_static_v6": seed(0b0100, [ra(0, True), ns6(), na6(), echo6(), udp6_other()]),
    "dhcpv4_offer_ack": seed(0b10, [dhcp4(2), dhcp4(5)]),
    "ipv4_static_arp_icmp": seed(0b01, [arp(1, PEER4, HOST4), arp(2, PEER4, HOST4, MAC), echo4(), tcp_syn(3260)]),
    "dual_stack": seed(0b1001, [arp(1, PEER4, HOST4), echo4(), ra(), ns6(), echo6()]),
}


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    for name, data in SEEDS.items():
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(data)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "mayhem/fuzz_uip_packet/testsuite")
