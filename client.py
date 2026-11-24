import argparse, socket, ssl, sys, threading
from nacl.public import Box, PublicKey
from nacl.exceptions import CryptoError
from protocol import *
from keystore import load_or_create_keypair, fingerprint

class Client:
    def __init__(self, sock, sk, tamper=False):
        self.sock, self.sk, self.tamper = sock, sk, tamper
        self.keys = {}      # name -> public key we trust (first key seen is kept)
        self.waiting = {}   # name -> Event, for lookups started by send_message
        self.pending = {}   # sender -> ciphertexts waiting for that sender's key
        self.lock = threading.Lock()
        self.send_lock = threading.Lock()

    def send(self, ftype, payload=b""):
        with self.send_lock:        # main thread and receiver thread both send
            send_frame(self.sock, ftype, payload)

    # ---- sending side ----
    def get_key(self, name):
        with self.lock:
            if name in self.keys:
                return self.keys[name]
            ev = self.waiting.setdefault(name, threading.Event())
        self.send(LOOKUP, name.encode())
        ev.wait(5)
        with self.lock:
            self.waiting.pop(name, None)
            return self.keys.get(name)

    def send_message(self, to, text):
        key = self.get_key(to)
        if key is None:
            print(f"cannot send: no public key for {to}")
            return
        # encrypt() returns nonce (24 B) + ciphertext + MAC (16 B)
        ct = bytes(Box(self.sk, PublicKey(key)).encrypt(text.encode()))
        if self.tamper:             # demo hook: corrupt one byte in transit
            b = bytearray(ct)
            b[-1] ^= 0x01
            ct = bytes(b)
        self.send(MESSAGE, pack_name(to, ct))

    # ---- receiving side (runs in the receiver thread) ----
    def show(self, sender, ct):
        with self.lock:
            key = self.keys[sender]
        try:
            pt = Box(self.sk, PublicKey(key)).decrypt(ct)
            print(f"\n[{sender}] {pt.decode(errors='replace')}")
        except CryptoError:
            print(f"\n[{sender}] !! message failed authentication, dropped")

    def on_message(self, payload):
        sender, ct = unpack_name(payload)
        with self.lock:
            known = sender in self.keys
            if not known:
                self.pending.setdefault(sender, []).append(ct)
        if known:
            self.show(sender, ct)
        else:
            self.send(LOOKUP, sender.encode())   # decrypt once the key arrives

    def on_lookup(self, payload):
        who, rest = unpack_name(payload)
        if rest[:1] != b"\x01":
            with self.lock:
                dropped = len(self.pending.pop(who, []))
                ev = self.waiting.get(who)
            print(f"\n[lookup] {who}: no key published")
            if dropped:
                print(f"         dropped {dropped} message(s) that could not be verified")
            if ev:
                ev.set()
            return
        key = rest[1:]
        with self.lock:
            old = self.keys.get(who)
            if old is None:
                self.keys[who] = key
            queued = self.pending.pop(who, []) if old is None else []
            ev = self.waiting.get(who)
        if old is not None and old != key:
            print(f"\n!! WARNING: key for {who} changed; keeping the first one")
        else:
            print(f"\n[lookup] {who}: fingerprint {fingerprint(key)}")
        if ev:
            ev.set()
        for ct in queued:
            self.show(who, ct)

    def receiver(self):
        try:
            while True:
                ftype, payload = recv_frame(self.sock)
                if ftype == MESSAGE:
                    self.on_message(payload)
                elif ftype == LOOKUP:
                    self.on_lookup(payload)
                elif ftype == ERROR:
                    print("\n[error]", payload.decode())
                elif ftype == PUBLISH:
                    print("\n[key published]")
                elif ftype == REGISTER:
                    print("\n[registered]")
        except (ConnectionError, OSError):
            print("\nconnection closed")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("user")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--tls", action="store_true")
    p.add_argument("--ca", default="certs/ca.crt")
    p.add_argument("--sni", default="relay.local", help="name the certificate must match")
    p.add_argument("--keylog")
    p.add_argument("--tamper", action="store_true",
                   help="demo only: flip one byte of every outgoing ciphertext")
    args = p.parse_args()

    if not NAME_RE.match(args.user):
        sys.exit("username must be 1-32 characters: letters, digits, _ or -")

    sk = load_or_create_keypair(args.user)
    pub = sk.public_key.encode()
    print("my public key:", pub.hex())
    print("fingerprint:  ", fingerprint(pub))

    sock = socket.create_connection((args.host, args.port))
    if args.tls:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=args.ca)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        if args.keylog:
            ctx.keylog_filename = args.keylog
        try:
            sock = ctx.wrap_socket(sock, server_hostname=args.sni)
        except ssl.SSLError as e:
            print("TLS handshake failed:", e)
            sys.exit(1)
        print("connected:", sock.version(), sock.cipher()[0])

    c = Client(sock, sk, tamper=args.tamper)
    c.send(REGISTER, args.user.encode())
    c.send(PUBLISH, pub)
    threading.Thread(target=c.receiver, daemon=True).start()
    print("type 'bob: hello' to send, '/lookup bob' to fetch a key, '/quit' to exit")
    for line in sys.stdin:
        line = line.strip()
        if line == "/quit":
            break
        if line.startswith("/lookup "):
            c.send(LOOKUP, line.split(" ", 1)[1].encode())
        elif ":" in line:
            to, text = line.split(":", 1)
            c.send_message(to.strip(), text.strip())
    sock.close()