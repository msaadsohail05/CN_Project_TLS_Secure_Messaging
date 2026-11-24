"""Stage 13: handshake experiment runner (+ stage 12 timing instrumentation).

For one network condition it runs `--runs` repetitions; in each run it opens `--conns`
sequential connections for each configuration

    tcp           plain TCP (baseline: just the 3-way handshake)
    tls12         TLS 1.2 full handshake
    tls13         TLS 1.3 full handshake
    tls13_resumed TLS 1.3 PSK resumption (a priming connection is made first)

and appends one CSV row per connection. The order of configurations is shuffled in every
run to spread drift evenly. Failures are recorded, never silently dropped.

Per connection we record (all from the client's own clock):
    tcp_ms   connect(): SYN -> handshake ACK
    tls_ms   first ClientHello -> handshake finished
    ttfd_ms  connection start -> first application reply received ("time to first data")
"""
import argparse
import csv
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tlsutil
from protocol import LOOKUP, recv_frame, send_frame

CONFIGS = ["tcp", "tls12", "tls13", "tls13_resumed"]
FIELDS = ["cond", "config", "run", "conn", "t_start_ns", "tcp_ms", "tls_ms", "ttfd_ms",
          "resumed", "version", "cipher", "error"]


def probe(sock):
    """One application round trip: it forces the server's post-handshake NewSessionTicket
    to be read (TLS 1.3) and gives the time-to-first-data measurement."""
    send_frame(sock, LOOKUP, b"probe")
    recv_frame(sock)


def one(host, port, ctx, session=None):
    t0 = time.perf_counter_ns()
    c = tlsutil.timed_connect(host, port, ctx, session=session)
    probe(c.sock)
    ttfd = (time.perf_counter_ns() - t0) / 1e6
    sess = c.sock.session if ctx is not None else None
    c.sock.close()
    return c, ttfd, sess


def run_config(config, args, run):
    host = args.host
    port = args.plain_port if config == "tcp" else args.tls_port
    ctx = None
    if config == "tls12":
        ctx = tlsutil.client_ctx(args.ca, "1.2")
    elif config in ("tls13", "tls13_resumed"):
        ctx = tlsutil.client_ctx(args.ca, "1.3")   # one context: resumption needs the same object
    session = None
    if config == "tls13_resumed":
        try:
            _, _, session = one(host, port, ctx)   # priming full handshake, not recorded
        except Exception as e:
            return [dict(cond=args.cond, config=config, run=run, conn=0, error=f"prime: {e}")]
    rows = []
    for i in range(1, args.conns + 1):
        row = dict(cond=args.cond, config=config, run=run, conn=i, t_start_ns=time.time_ns())
        try:
            c, ttfd, sess = one(host, port, ctx, session if config == "tls13_resumed" else None)
            if config == "tls13_resumed" and sess is not None:
                session = sess
            row.update(tcp_ms=round(c.tcp_ms, 3), tls_ms=round(c.tls_ms, 3), ttfd_ms=round(ttfd, 3),
                       resumed=int(c.reused), version=c.version, cipher=c.cipher, error="")
        except Exception as e:
            row.update(error=f"{type(e).__name__}: {e}")
        rows.append(row)
    return rows


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--tls-port", type=int, default=8443)
    p.add_argument("--plain-port", type=int, default=8080)
    p.add_argument("--ca", default="certs/ca.crt")
    p.add_argument("--cond", required=True, help="label of the network condition, e.g. rtt20_loss0")
    p.add_argument("--runs", type=int, default=5)
    p.add_argument("--conns", type=int, default=20)
    p.add_argument("--configs", nargs="+", default=CONFIGS, choices=CONFIGS)
    p.add_argument("--seed", type=int)
    p.add_argument("--out", required=True)
    args = p.parse_args()
    rng = random.Random(args.seed)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    new = not os.path.exists(args.out)
    with open(args.out, "a", newline="") as f:
        w = csv.DictWriter(f, FIELDS)
        if new:
            w.writeheader()
        for run in range(1, args.runs + 1):
            order = args.configs[:]
            rng.shuffle(order)
            for config in order:
                for row in run_config(config, args, run):
                    w.writerow(row)
                f.flush()
            print(f"handshake {args.cond} run {run}/{args.runs} done ({', '.join(order)})", flush=True)


if __name__ == "__main__":
    main()
