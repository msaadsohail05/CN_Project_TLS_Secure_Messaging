"""Dependency-free capture reader: classic pcap + pcapng, Ethernet / Linux-cooked / raw-IP,
IPv4 + TCP only. Enough for tcpdump captures taken on veth interfaces inside namespaces,
so the analysis scripts run on a machine with nothing but Python.

    for pkt in packets("evidence/captures/tls13_full.pcapng"): ...

Each packet is a dict: ts (float s), src, sport, dst, dport, flags, seq, ack, payload (bytes),
ip_len (IP total length), hdr_len (IP + TCP header bytes), frame_len (bytes on the wire as captured).
"""
import struct

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def _pcap(data):
    magic = data[:4]
    endian, nano = {b"\xd4\xc3\xb2\xa1": ("<", False), b"\xa1\xb2\xc3\xd4": (">", False),
                    b"\x4d\x3c\xb2\xa1": ("<", True), b"\xa1\xb2\x3c\x4d": (">", True)}[magic]
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    pos = 24
    while pos + 16 <= len(data):
        sec, frac, incl, orig = struct.unpack(endian + "IIII", data[pos:pos + 16])
        pos += 16
        yield sec + frac / (1e9 if nano else 1e6), linktype, data[pos:pos + incl], orig
        pos += incl


def _pcapng(data):
    pos, endian, ifaces = 0, "<", []        # ifaces: list of (linktype, ts_divisor)
    while pos + 12 <= len(data):
        btype = struct.unpack(endian + "I", data[pos:pos + 4])[0]
        if btype == 0x0A0D0D0A:             # section header: byte-order magic decides endianness
            endian = "<" if data[pos + 8:pos + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            ifaces = []
        blen = struct.unpack(endian + "I", data[pos + 4:pos + 8])[0]
        body = data[pos + 8:pos + blen - 4]
        if btype == 1:                      # interface description
            linktype = struct.unpack(endian + "H", body[:2])[0]
            div, o = 1e6, 8
            while o + 4 <= len(body):       # options: if_tsresol (code 9)
                code, olen = struct.unpack(endian + "HH", body[o:o + 4])
                if code == 0:
                    break
                if code == 9:
                    r = body[o + 4]
                    div = 2.0 ** (r & 0x7F) if r & 0x80 else 10.0 ** r
                o += 4 + ((olen + 3) & ~3)
            ifaces.append((linktype, div))
        elif btype == 6:                    # enhanced packet block
            iface, hi, lo, cap, orig = struct.unpack(endian + "IIIII", body[:20])
            linktype, div = ifaces[iface]
            yield ((hi << 32) | lo) / div, linktype, body[20:20 + cap], orig
        pos += blen


def _l3(linktype, frame):
    if linktype == 1:                       # Ethernet
        et = struct.unpack("!H", frame[12:14])[0]
        off = 14
        if et == 0x8100:                    # one VLAN tag
            et = struct.unpack("!H", frame[16:18])[0]
            off = 18
        return frame[off:] if et == 0x0800 else None
    if linktype == 113:                     # Linux cooked (tcpdump -i any)
        return frame[16:] if struct.unpack("!H", frame[14:16])[0] == 0x0800 else None
    if linktype in (101, 12):               # raw IP
        return frame
    return None


def packets(path):
    with open(path, "rb") as f:
        data = f.read()
    reader = _pcapng if data[:4] == b"\x0a\x0d\x0d\x0a" else _pcap
    for ts, linktype, frame, orig in reader(data):
        ip = _l3(linktype, frame)
        if not ip or len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
            continue
        ihl = (ip[0] & 0x0F) * 4
        total = struct.unpack("!H", ip[2:4])[0]
        tcp = ip[ihl:total]
        if len(tcp) < 20:
            continue
        sport, dport, seq, ack = struct.unpack("!HHII", tcp[:12])
        doff = (tcp[12] >> 4) * 4
        yield dict(ts=ts, src=".".join(map(str, ip[12:16])), sport=sport,
                   dst=".".join(map(str, ip[16:20])), dport=dport, flags=tcp[13],
                   seq=seq, ack=ack, payload=bytes(tcp[doff:]), ip_len=total, hdr_len=ihl + doff,
                   frame_len=orig)
