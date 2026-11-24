"""One-shot handshake probes: open a connection (or two), do one application round trip,
print what happened. These exist so each capture in evidence/captures contains exactly
one clean protocol exchange.

    python3 -m bench.probe tcp      --host 10.0.2.10 --plain-port 8080
    python3 -m bench.probe tls13    --host 10.0.2.10 --keylog evidence/captures/tls13_full.keylog
    python3 -m bench.probe tls12    ...
    python3 -m bench.probe resumed  ...        # full handshake, then a resumed one on a new TCP connection
    python3 -m bench.probe badca    ...        # client that trusts the wrong CA: must be refused
"""
import argparse
import os
import ssl
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tlsutil
from bench.exp_handshake import probe


def show(label, c):
    print(f"{label}: {c.version} {c.cipher} tcp={c.tcp_ms:.2f}ms tls={c.tls_ms:.2f}ms resumed={c.reused}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("kind", choices=["tcp", "tls12", "tls13", "resumed", "badca"])
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--tls-port", type=int, default=8443)
    p.add_argument("--plain-port", type=int, default=8080)
    p.add_argument("--ca", default="certs/ca.crt")
    p.add_argument("--keylog")
    a = p.parse_args()

    if a.kind == "tcp":
        c = tlsutil.timed_connect(a.host, a.plain_port, None)
        probe(c.sock); show("plain TCP", c); c.sock.close()
    elif a.kind in ("tls12", "tls13"):
        ctx = tlsutil.client_ctx(a.ca, {"tls12": "1.2", "tls13": "1.3"}[a.kind], a.keylog)
        c = tlsutil.timed_connect(a.host, a.tls_port, ctx)
        probe(c.sock); show(a.kind, c); c.sock.close()
    elif a.kind == "resumed":
        ctx = tlsutil.client_ctx(a.ca, "1.3", a.keylog)
        c = tlsutil.timed_connect(a.host, a.tls_port, ctx)
        probe(c.sock)                         # the NewSessionTicket arrives after the handshake
        sess = c.sock.session; show("full   ", c); c.sock.close()
        c = tlsutil.timed_connect(a.host, a.tls_port, ctx, session=sess)
        probe(c.sock); show("resumed", c); c.sock.close()
        if not c.reused:
            sys.exit("session was NOT resumed")
    else:
        try:
            tlsutil.timed_connect(a.host, a.tls_port, tlsutil.client_ctx("certs/rogue/ca.crt", "1.3", a.keylog))
        except ssl.SSLCertVerificationError as e:
            print("REFUSED as expected:", e.verify_message)
        else:
            sys.exit("client accepted a certificate from a CA it should not trust")


if __name__ == "__main__":
    main()
