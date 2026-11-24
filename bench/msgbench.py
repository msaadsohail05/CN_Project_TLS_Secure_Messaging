"""Stage 14: message-latency runner. One process plays Client A (send) or Client B (recv).

    recv  waits for N messages and records, for each, latency = receive time minus the
          send timestamp Client A embedded in the message, in microseconds. Both clients
          run on one host so they share one clock (no clock sync needed).
    send  sends N messages of a given payload size, paced `--interval-ms` apart so that
          queueing at the sender does not masquerade as network latency.

The timestamp is taken before encryption and the receive time after decryption, so the
e2ee mode includes the real cost of NaCl Box on both ends.

Plaintext layout: [8-byte send time_ns][4-byte seq][padding up to --payload bytes].
The lines "READY" / "DONE" / "SENT" on stdout let run_experiments.py order the processes.
"""
import argparse
import csv
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import keystore
from client import MODES, Client, connect

FIELDS = ["cond", "mode", "payload", "run", "seq", "latency_us", "wire_bytes"]


def open_client(args, user, emit):
    keystore.KEY_DIR = args.keydir
    port = args.plain_port if args.mode == "tcp" else args.tls_port
    conn = connect(args.host, port, args.mode, args.ca, keylog=args.keylog)
    return Client(user, keystore.load_or_create_keypair(user), conn.sock, args.mode, emit=emit).start()


def recv(args):
    rows, done, ready = [], threading.Event(), threading.Event()
    state = {"reg": False, "pub": False}

    def emit(kind, **kw):
        if kind == "registered":
            state["reg"] = True
        elif kind == "published":
            state["pub"] = True
        elif kind == "message":
            d = kw["data"]
            ts, seq = int.from_bytes(d[:8], "big"), int.from_bytes(d[8:12], "big")
            rows.append(dict(cond=args.cond, mode=args.mode, payload=args.payload, run=args.run,
                             seq=seq, latency_us=round((kw["t_ns"] - ts) / 1000, 1),
                             wire_bytes=kw["wire"]))
            if len(rows) >= args.n:
                done.set()
        if state["reg"] and (state["pub"] or not MODES[args.mode][1]):
            ready.set()

    c = open_client(args, args.user, emit)
    if not ready.wait(20):
        sys.exit("recv: never became ready")
    print("READY", flush=True)
    if MODES[args.mode][1]:
        # Key discovery (a LOOKUP round trip) is a one-off cost, not per-message latency:
        # fetch the sender's key before the first message arrives so it is not timed.
        def warm():
            while not done.is_set() and c.get_key(args.peer, timeout=2) is None:
                time.sleep(0.2)
        threading.Thread(target=warm, daemon=True).start()
    done.wait(args.timeout)
    time.sleep(0.05)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    new = not os.path.exists(args.out)
    with open(args.out, "a", newline="") as f:
        w = csv.DictWriter(f, FIELDS)
        if new:
            w.writeheader()
        w.writerows(sorted(rows, key=lambda r: r["seq"]))
    print(f"DONE {len(rows)}/{args.n}", flush=True)
    c.close()


def send(args):
    registered = threading.Event()
    c = open_client(args, args.user, lambda k, **kw: registered.set() if k == "registered" else None)
    if not registered.wait(20):
        sys.exit("send: never registered")
    if MODES[args.mode][1] and c.get_key(args.to) is None:   # key lookup stays outside the timing
        sys.exit("send: no key for recipient")
    time.sleep(args.warmup)                       # let the receiver finish its own key lookup
    pad = max(args.payload, 12) - 12
    for seq in range(args.n):
        msg = time.time_ns().to_bytes(8, "big") + seq.to_bytes(4, "big") + b"\x00" * pad
        c.send_message(args.to, msg)
        time.sleep(args.interval_ms / 1000)
    time.sleep(0.3)
    print(f"SENT {args.n}", flush=True)
    c.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("role", choices=["send", "recv"])
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--tls-port", type=int, default=8443)
    p.add_argument("--plain-port", type=int, default=8080)
    p.add_argument("--ca", default="certs/ca.crt")
    p.add_argument("--mode", choices=list(MODES), required=True)
    p.add_argument("--payload", type=int, default=64)
    p.add_argument("-n", type=int, default=100)
    p.add_argument("--interval-ms", type=float, default=10)
    p.add_argument("--user")
    p.add_argument("--to", default="bob")
    p.add_argument("--peer", default="alice", help="recv: whom to pre-fetch the key of")
    p.add_argument("--warmup", type=float, default=1.5, help="send: seconds to wait before the first message")
    p.add_argument("--cond", default="adhoc")
    p.add_argument("--run", type=int, default=1)
    p.add_argument("--out", default="results/raw/latency_adhoc.csv")
    p.add_argument("--keydir", default="keys")
    p.add_argument("--keylog")
    p.add_argument("--timeout", type=float, default=120)
    args = p.parse_args()
    args.user = args.user or ("alice" if args.role == "send" else "bob")
    (send if args.role == "send" else recv)(args)


if __name__ == "__main__":
    main()
