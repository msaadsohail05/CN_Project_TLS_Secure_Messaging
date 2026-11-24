"""Stage 15: layered byte-overhead analysis straight from a packet capture.

    python3 -m bench.analyze_overhead evidence/captures/tls13_full.pcapng --server-port 8443
    python3 -m bench.analyze_overhead e2ee_exchange.pcapng --e2ee --messages 100 --plaintext-bytes 6400 --name-len 3

For every TCP connection to the server port it reports

  * TCP setup: SYN / SYN-ACK / ACK timing (-> TCP handshake time) and bytes
  * TLS: the record layer (types, count, bytes), ClientHello / ServerHello sizes,
         negotiated version (from ServerHello supported_versions) and whether the server
         selected a resumption PSK (pre_shared_key extension)
  * handshake bytes per direction (everything up to the client's Finished in TLS 1.3)
  * a layered accounting of an application exchange (what the "total wire overhead" is made of):

        plaintext  +  E2EE (24 B nonce + 16 B MAC per message)  +  app framing (4 B length,
        1 B type, 1 B name length, name)  +  TLS records (5 B header + 1 B inner type +
        16 B AEAD tag = 22 B each)  +  TCP/IP headers (incl. pure ACKs)  +  retransmissions

    The residual (REGISTER / PUBLISH / LOOKUP frames, close_notify) is reported separately
    as other_control_frames_and_alerts; if it is large something is wrong.

In TLS 1.3 everything after the ServerHello is an encrypted "application data" record,
so without the key log a capture cannot tell handshake records from data records. The
handshake/data boundary is therefore taken at the client's first encrypted record (its
Finished), which is exact for connections without client certificates (ours).
"""
import argparse
import json
import struct
import sys
from collections import defaultdict

import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from bench import pcap

TYPES = {20: "change_cipher_spec", 21: "alert", 22: "handshake", 23: "application_data"}
VERSIONS = {0x0301: "TLS1.0", 0x0302: "TLS1.1", 0x0303: "TLS1.2", 0x0304: "TLS1.3"}
EXT_SNI, EXT_SUPPORTED_VERSIONS, EXT_PSK = 0, 43, 41


def reassemble(pkts):
    """In-order TCP payload of one direction: sort by seq, drop retransmitted overlap.
    Returns (bytes, retransmitted_payload_bytes, first_ts_of_each_chunk list)."""
    segs = sorted((p for p in pkts if p["payload"]), key=lambda p: (p["seq"], p["ts"]))
    out, nxt, retrans, marks = bytearray(), None, 0, []
    for p in segs:
        s, data = p["seq"], p["payload"]
        if nxt is None:
            nxt = s
        if s + len(data) <= nxt:
            retrans += len(data)
            continue
        if s < nxt:
            retrans += nxt - s
            data = data[nxt - s:]
        marks.append((len(out), p["ts"]))
        out += data
        nxt += len(data)
    return bytes(out), retrans, marks


def ts_at(marks, offset):
    t = marks[0][1] if marks else None
    for start, ts in marks:
        if start <= offset:
            t = ts
        else:
            break
    return t


def records(stream, marks):
    """Parse a TLS record stream -> list of dicts."""
    out, pos = [], 0
    while pos + 5 <= len(stream):
        ctype, ver, length = stream[pos], struct.unpack("!H", stream[pos + 1:pos + 3])[0], \
            struct.unpack("!H", stream[pos + 3:pos + 5])[0]
        if ctype not in TYPES or (ver >> 8) != 3:
            break                                   # not TLS (e.g. plain TCP frames)
        body = stream[pos + 5:pos + 5 + length]
        out.append(dict(type=ctype, name=TYPES[ctype], version=ver, length=length, wire=5 + length,
                        ts=ts_at(marks, pos), body=body))
        pos += 5 + length
    return out


def parse_extensions(b):
    exts, pos = {}, 0
    while pos + 4 <= len(b):
        t, l = struct.unpack("!HH", b[pos:pos + 4])
        exts[t] = b[pos + 4:pos + 4 + l]
        pos += 4 + l
    return exts


def parse_hello(body, is_server):
    """body = handshake message (type, 3-byte len, hello). Returns a small dict."""
    if len(body) < 40:
        return {}
    pos = 4 + 2 + 32
    sid = body[pos]
    pos += 1 + sid
    if is_server:
        cipher = struct.unpack("!H", body[pos:pos + 2])[0]
        pos += 3
    else:
        n = struct.unpack("!H", body[pos:pos + 2])[0]
        pos += 2 + n
        pos += 1 + body[pos]
        cipher = None
    elen = struct.unpack("!H", body[pos:pos + 2])[0] if pos + 2 <= len(body) else 0
    exts = parse_extensions(body[pos + 2:pos + 2 + elen])
    info = dict(cipher=cipher, has_psk=EXT_PSK in exts)
    sv = exts.get(EXT_SUPPORTED_VERSIONS)
    if sv:
        info["version"] = VERSIONS.get(struct.unpack("!H", sv[-2:])[0], "?")
    else:
        info["version"] = "TLS1.2" if is_server else "?"
    if not is_server and EXT_SNI in exts:
        info["sni"] = exts[EXT_SNI][5:].decode(errors="replace")
    return info


def summarize_records(recs):
    c = defaultdict(lambda: dict(count=0, wire=0))
    for r in recs:
        c[r["name"]]["count"] += 1
        c[r["name"]]["wire"] += r["wire"]
    return dict(c)


def analyze(path, server_port=8443, e2ee=False, messages=None, plaintext_bytes=None, name_len=None):
    flows = defaultdict(list)
    for p in pcap.packets(path):
        if p["dport"] == server_port:
            flows[(p["src"], p["sport"], p["dst"], p["dport"])].append(p)
        elif p["sport"] == server_port:
            flows[(p["dst"], p["dport"], p["src"], p["sport"])].append(p)
    result = []
    for (cip, cport, sip, sport), pkts in flows.items():
        c2s = [p for p in pkts if p["dport"] == server_port]
        s2c = [p for p in pkts if p["sport"] == server_port]
        syn = next((p for p in c2s if p["flags"] & pcap.SYN and not p["flags"] & pcap.ACK), None)
        synack = next((p for p in s2c if p["flags"] & pcap.SYN), None)
        ack3 = next((p for p in c2s if p["flags"] & pcap.ACK and not p["flags"] & pcap.SYN and syn and p["ts"] >= syn["ts"]), None)
        cs, c_re, cmarks = reassemble(c2s)
        ss, s_re, smarks = reassemble(s2c)
        crecs, srecs = records(cs, cmarks), records(ss, smarks)
        flow = dict(client=f"{cip}:{cport}", server=f"{sip}:{sport}", packets=dict(c2s=len(c2s), s2c=len(s2c)))
        if syn and ack3:
            flow["tcp_handshake_ms_at_capture_point"] = round((ack3["ts"] - syn["ts"]) * 1000, 3)
        if synack and syn:
            flow["syn_to_synack_ms"] = round((synack["ts"] - syn["ts"]) * 1000, 3)
        # --- bytes by layer
        l3 = dict(c2s=sum(p["ip_len"] for p in c2s), s2c=sum(p["ip_len"] for p in s2c))
        hdr = dict(c2s=sum(p["hdr_len"] for p in c2s), s2c=sum(p["hdr_len"] for p in s2c))
        pay = dict(c2s=len(cs) + c_re, s2c=len(ss) + s_re)
        flow["bytes"] = dict(l3_total=l3, header_bytes=hdr, tcp_payload=pay,
                             retransmitted_payload=dict(c2s=c_re, s2c=s_re),
                             pure_acks=dict(c2s=sum(1 for p in c2s if not p["payload"] and p["flags"] == pcap.ACK),
                                            s2c=sum(1 for p in s2c if not p["payload"] and p["flags"] == pcap.ACK)))
        if crecs and srecs:
            ch = next((r for r in crecs if r["type"] == 22), None)
            sh = next((r for r in srecs if r["type"] == 22), None)
            tls = dict(records=dict(c2s=summarize_records(crecs), s2c=summarize_records(srecs)))
            if ch:
                tls["client_hello"] = dict(wire=ch["wire"], **parse_hello(ch["body"], False))
            if sh:
                h = parse_hello(sh["body"], True)
                tls["server_hello"] = dict(wire=sh["wire"], **h)
                tls["version"] = h.get("version")
                tls["resumed"] = bool(h.get("has_psk")) and h.get("version") == "TLS1.3"
            tls12 = tls.get("version") == "TLS1.2"
            # handshake / data boundary
            if tls12:
                # TLS 1.2 full handshake: each side's flight ends with its CCS + one encrypted Finished record
                c_ccs = [i for i, r in enumerate(crecs) if r["type"] == 20]
                s_ccs = [i for i, r in enumerate(srecs) if r["type"] == 20]
                cut_c = (c_ccs[0] + 2) if c_ccs else len(crecs)
                cut_s = (s_ccs[0] + 2) if s_ccs else len(srecs)
            else:
                first23 = next((i for i, r in enumerate(crecs) if r["type"] == 23), len(crecs))
                cut_c = first23 + 1                       # + the client Finished record
                fin_ts = crecs[first23]["ts"] if first23 < len(crecs) else None
                cut_s = len([r for r in srecs if fin_ts is None or r["ts"] <= fin_ts])
            hs_c, hs_s = crecs[:cut_c], srecs[:cut_s]
            app_c, app_s = crecs[cut_c:], srecs[cut_s:]
            tls["handshake_bytes"] = dict(c2s=sum(r["wire"] for r in hs_c), s2c=sum(r["wire"] for r in hs_s),
                                          records_c2s=len(hs_c), records_s2c=len(hs_s))
            tls["post_handshake_records"] = dict(c2s=len(app_c), s2c=len(app_s),
                                                 c2s_bytes=sum(r["wire"] for r in app_c),
                                                 s2c_bytes=sum(r["wire"] for r in app_s))
            if hs_c and hs_s and syn:
                tls["handshake_ms_at_capture_point"] = round((hs_c[-1]["ts"] - hs_c[0]["ts"]) * 1000, 3)
            per_rec = 22 if not tls12 else 5 + 8 + 16        # TLS1.2 AES-GCM: explicit nonce 8 + tag 16
            tls["record_overhead_per_app_record_bytes"] = per_rec
            flow["tls"] = tls
            # --- layered accounting of the application exchange, client -> server direction
            if messages and plaintext_bytes is not None:
                n = messages
                e2ee_oh = 40 * n if e2ee else 0
                frame_oh = n * (4 + 1 + 1 + (name_len or 0))
                tls_oh = len(app_c) * per_rec
                hdr_oh = hdr["c2s"]
                wire = l3["c2s"]
                handshake = tls["handshake_bytes"]["c2s"]
                explained = plaintext_bytes + e2ee_oh + frame_oh + tls_oh + hdr_oh + c_re + handshake
                flow["layers_c2s"] = dict(
                    plaintext=plaintext_bytes, e2ee=e2ee_oh, app_framing=frame_oh, tls_records=tls_oh,
                    tcpip_headers=hdr_oh, retransmissions=c_re, handshake_records=handshake,
                    total_wire_l3=wire, other_control_frames_and_alerts=wire - explained,
                    overhead_total=wire - plaintext_bytes,
                    overhead_ratio=round((wire - plaintext_bytes) / plaintext_bytes, 3) if plaintext_bytes else None)
        elif cs or ss:
            # not TLS: plain TCP frames
            flow["tls"] = None
            flow["note"] = "no TLS records found (plain TCP flow)"
        result.append(flow)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("capture")
    p.add_argument("--server-port", type=int, default=8443)
    p.add_argument("--e2ee", action="store_true")
    p.add_argument("--messages", type=int)
    p.add_argument("--plaintext-bytes", type=int, help="total plaintext the client sent (all messages)")
    p.add_argument("--name-len", type=int, help="recipient name length, for the app framing term")
    p.add_argument("--json", action="store_true")
    a = p.parse_args()
    res = analyze(a.capture, a.server_port, a.e2ee, a.messages, a.plaintext_bytes, a.name_len)
    if a.json:
        print(json.dumps(res, indent=1, default=str))
        return
    for f in res:
        print(f"\nflow {f['client']} -> {f['server']}")
        for k in ("tcp_handshake_ms_at_capture_point", "syn_to_synack_ms"):
            if k in f:
                print(f"  {k}: {f[k]}")
        t = f.get("tls")
        if t:
            print(f"  TLS {t.get('version')}  resumed={t.get('resumed')}  ClientHello {t.get('client_hello', {}).get('wire')} B"
                  f"  ServerHello {t.get('server_hello', {}).get('wire')} B")
            print("  handshake bytes:", t["handshake_bytes"])
            print("  records after handshake:", t["post_handshake_records"])
        print("  bytes:", f["bytes"])
        if "layers_c2s" in f:
            print("  layers (client->server):")
            for k, v in f["layers_c2s"].items():
                print(f"    {k:18s} {v}")


if __name__ == "__main__":
    main()
