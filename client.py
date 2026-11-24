"""Secure-messaging client.

Three operating modes share this one code path (stage 11):

    tcp   plain TCP, no TLS, no end-to-end encryption      (baseline)
    tls   TLS 1.3 to the relay, application data in clear  (hop security only)
    e2ee  TLS 1.3 to the relay + NaCl Box end-to-end       (the real system)

CLI:
    python3 client.py alice --host 10.0.2.10 --mode e2ee
    python3 client.py alice --mode e2ee --trust "bob=ab12 ..."   # pin a fingerprint

`Client` is also a library class driven by an `emit(kind, **info)` callback, which
is how the web UI, the benchmarks and the tests use it.
"""
import argparse
import socket
import sys
import threading
import time

from nacl.exceptions import CryptoError
from nacl.public import Box, PublicKey

import tlsutil
from keystore import fingerprint, load_or_create_keypair
from protocol import *

MODES = {"tcp": (False, False), "tls": (True, False), "e2ee": (True, True)}  # (tls, e2ee)


def connect(host, port, mode="e2ee", ca="certs/ca.crt", sni="relay.local",
            keylog=None, tls_version="1.3", session=None):
    """Open the transport for a mode. Returns tlsutil.Conn (socket + timings)."""
    use_tls = MODES[mode][0]
    ctx = tlsutil.client_ctx(ca, tls_version, keylog) if use_tls else None
    return tlsutil.timed_connect(host, port, ctx, sni, session)


class Client:
    def __init__(self, user, sk, sock, mode="e2ee", emit=None, tamper=False, trust=None):
        self.user, self.sk, self.sock, self.mode = user, sk, sock, mode
        self.e2ee = MODES[mode][1]
        self.emit = emit or self._print
        self.tamper = tamper                  # demo hook: corrupt a byte in transit
        self.trust = dict(trust or {})        # name -> expected fingerprint (pinned)
        self.keys = {}                        # name -> public key we accepted (first seen wins)
        self.waiting = {}                     # name -> Event while a lookup is in flight
        self.pending = {}                     # sender -> ciphertexts waiting for their key
        self.lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.pub = sk.public_key.encode()

    # ---------------------------------------------------------------- output
    @staticmethod
    def _print(kind, **kw):
        if kind == "message":
            print(f"\n[{kw['sender']}] {kw['text']}")
        elif kind == "lookup":
            print(f"\n[lookup] {kw['who']}: fingerprint {kw['fp']}")
        elif kind == "nokey":
            print(f"\n[lookup] {kw['who']}: no key published")
        elif kind == "auth_failed":
            print(f"\n[{kw['sender']}] !! message failed authentication, dropped")
        elif kind == "key_changed":
            print(f"\n!! WARNING: key for {kw['who']} changed; keeping the first one")
        elif kind == "fingerprint_mismatch":
            print(f"\n!! FINGERPRINT MISMATCH for {kw['who']}: relay gave {kw['got']} "
                  f"but you pinned {kw['expected']}. Refusing to use this key.")
        elif kind == "error":
            print("\n[error]", kw["msg"])
        elif kind == "closed":
            print("\nconnection closed")
        elif kind in ("registered", "published"):
            print(f"\n[{kind}]")

    def send(self, ftype, payload=b""):
        with self.send_lock:              # main thread and receiver thread both send
            send_frame(self.sock, ftype, payload)

    def start(self):
        self.send(REGISTER, self.user.encode())
        if self.e2ee:
            self.send(PUBLISH, self.pub)
        threading.Thread(target=self.receiver, daemon=True).start()
        return self

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    # ---------------------------------------------------------------- sending
    def lookup(self, name):
        self.send(LOOKUP, name.encode())

    def get_key(self, name, timeout=5):
        with self.lock:
            if name in self.keys:
                return self.keys[name]
            ev = self.waiting.setdefault(name, threading.Event())
        self.lookup(name)
        ev.wait(timeout)
        with self.lock:
            self.waiting.pop(name, None)
            return self.keys.get(name)

    def send_message(self, to, data):
        """Send text or bytes to `to`. Returns True if a frame went out."""
        if isinstance(data, str):
            data = data.encode()
        if self.e2ee:
            key = self.get_key(to)
            if key is None:
                self.emit("error", msg=f"cannot send: no trusted public key for {to}")
                return False
            # encrypt() returns nonce (24 B) + ciphertext + MAC (16 B): a fixed 40 B overhead
            data = bytes(Box(self.sk, PublicKey(key)).encrypt(data))
            if self.tamper:
                b = bytearray(data)
                b[-1] ^= 0x01
                data = bytes(b)
        self.send(MESSAGE, pack_name(to, data))
        return True

    # ---------------------------------------------------------------- receiving
    def _deliver(self, sender, ct):
        with self.lock:
            key = self.keys[sender]
        try:
            pt = Box(self.sk, PublicKey(key)).decrypt(ct)
        except CryptoError:
            return self.emit("auth_failed", sender=sender)
        self.emit("message", sender=sender, text=pt.decode(errors="replace"), data=pt,
                  t_ns=time.time_ns(), wire=len(ct), e2ee=True)

    def on_message(self, payload):
        sender, body = unpack_name(payload)
        if not self.e2ee:
            return self.emit("message", sender=sender, text=body.decode(errors="replace"),
                             data=body, t_ns=time.time_ns(), wire=len(body), e2ee=False)
        with self.lock:
            known = sender in self.keys
            if not known:
                self.pending.setdefault(sender, []).append(body)
        if known:
            self._deliver(sender, body)
        else:
            self.lookup(sender)               # decrypt once the key arrives

    def on_lookup(self, payload):
        who, rest = unpack_name(payload)
        with self.lock:
            ev = self.waiting.get(who)
        if rest[:1] != b"\x01":
            with self.lock:
                dropped = len(self.pending.pop(who, []))
            self.emit("nokey", who=who, dropped=dropped)
            if ev:
                ev.set()
            return
        key = rest[1:]
        fp = fingerprint(key)
        expected = self.trust.get(who)
        if expected and expected != fp:
            with self.lock:
                self.pending.pop(who, None)
            self.emit("fingerprint_mismatch", who=who, got=fp, expected=expected)
            if ev:
                ev.set()
            return
        with self.lock:
            old = self.keys.get(who)
            if old is None:
                self.keys[who] = key
            queued = self.pending.pop(who, []) if old is None else []
        if old is not None and old != key:
            self.emit("key_changed", who=who)
        else:
            self.emit("lookup", who=who, fp=fp, key=key)
        if ev:
            ev.set()
        for ct in queued:
            self._deliver(who, ct)

    def receiver(self):
        try:
            while True:
                ftype, payload = recv_frame(self.sock)
                if ftype == MESSAGE:
                    self.on_message(payload)
                elif ftype == LOOKUP:
                    self.on_lookup(payload)
                elif ftype == ERROR:
                    self.emit("error", msg=payload.decode(errors="replace"))
                elif ftype == PUBLISH:
                    self.emit("published")
                elif ftype == REGISTER:
                    self.emit("registered")
        except (ConnectionError, OSError, ValueError):
            self.emit("closed")


def parse_trust(items):
    out = {}
    for it in items or []:
        name, _, fp = it.partition("=")
        out[name.strip()] = " ".join(fp.split())
    return out


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("user")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--mode", choices=list(MODES), default="e2ee")
    p.add_argument("--tls", action="store_true", help="legacy alias for --mode e2ee")
    p.add_argument("--tls-version", choices=["1.2", "1.3"], default="1.3")
    p.add_argument("--ca", default="certs/ca.crt")
    p.add_argument("--sni", default="relay.local", help="name the certificate must match")
    p.add_argument("--keylog")
    p.add_argument("--trust", action="append", metavar="NAME=FINGERPRINT",
                   help="pin a peer's key fingerprint (repeatable)")
    p.add_argument("--tamper", action="store_true",
                   help="demo only: flip one byte of every outgoing ciphertext")
    args = p.parse_args()
    if args.tls:
        args.mode = "e2ee"

    if not NAME_RE.match(args.user):
        sys.exit("username must be 1-32 characters: letters, digits, _ or -")

    sk = load_or_create_keypair(args.user)
    pub = sk.public_key.encode()
    print("my public key:", pub.hex())
    print("fingerprint:  ", fingerprint(pub))

    try:
        conn = connect(args.host, args.port, args.mode, args.ca, args.sni, args.keylog,
                       args.tls_version)
    except Exception as e:                      # ssl.SSLError, OSError
        print("connection failed:", e)
        sys.exit(1)
    if MODES[args.mode][0]:
        print("connected:", conn.version, conn.cipher)

    c = Client(args.user, sk, conn.sock, args.mode, tamper=args.tamper,
               trust=parse_trust(args.trust)).start()
    print(f"mode={args.mode}. type 'bob: hello' to send, '/lookup bob' to fetch a key, '/quit' to exit")
    for line in sys.stdin:
        line = line.strip()
        if line == "/quit":
            break
        if line.startswith("/lookup "):
            c.lookup(line.split(" ", 1)[1])
        elif ":" in line:
            to, text = line.split(":", 1)
            c.send_message(to.strip(), text.strip())
    c.close()
