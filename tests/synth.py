"""Build a classic .pcap from the byte chunks a Tap recorded, so the capture analyser can be
unit-tested without tcpdump or root. Packets get plausible Ethernet/IPv4/TCP headers
(MSS 1448 segmentation, a pure ACK for each data segment, 3-way handshake, FIN exchange).
"""
import struct

MSS = 1448


def _csum(b):
    if len(b) % 2:
        b += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _packet(src, sport, dst, dport, seq, ack, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0,
                     bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    ip = ip[:10] + struct.pack("!H", _csum(ip)) + ip[12:]
    return b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00" + ip + tcp


def write_pcap(path, chunks, client_ip="10.0.1.10", server_ip="10.0.2.10", server_port=8443,
               base_port=40000):
    """chunks: iterable of (t, conn_id, 'c2s'|'s2c'|'open', bytes)."""
    pkts, state = [], {}
    for t, cid, d, data in chunks:
        cport = base_port + cid
        st = state.setdefault(cid, dict(cseq=1000, sseq=5000, t=t))
        if d == "open":
            pkts.append((t, _packet(client_ip, cport, server_ip, server_port, st["cseq"], 0, 0x02)))
            pkts.append((t + 1e-5, _packet(server_ip, server_port, client_ip, cport, st["sseq"], st["cseq"] + 1, 0x12)))
            st["cseq"] += 1; st["sseq"] += 1
            pkts.append((t + 2e-5, _packet(client_ip, cport, server_ip, server_port, st["cseq"], st["sseq"], 0x10)))
            continue
        a, b = ("cseq", "sseq") if d == "c2s" else ("sseq", "cseq")
        src, sp, dst, dp = ((client_ip, cport, server_ip, server_port) if d == "c2s"
                            else (server_ip, server_port, client_ip, cport))
        for i in range(0, len(data), MSS):
            seg = data[i:i + MSS]
            pkts.append((t + i * 1e-9, _packet(src, sp, dst, dp, st[a], st[b], 0x18, seg)))
            st[a] += len(seg)
            pkts.append((t + 1e-5 + i * 1e-9, _packet(dst, dp, src, sp, st[b], st[a], 0x10)))
    pkts.sort(key=lambda p: p[0])
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for t, pkt in pkts:
            f.write(struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(pkt), len(pkt)) + pkt)
