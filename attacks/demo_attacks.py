"""Stage 17: the security demonstrations, as self-contained scenarios.

Each scenario builds a tiny throw-away system on loopback (relay, clients, attacker), runs
the attack and returns a structured verdict: what we expected, what happened, pass/fail and
a timeline. The same code drives the CLI below and the web UI's "Attack lab".

    python3 -m attacks.demo_attacks            # run everything, print a report
    python3 -m attacks.demo_attacks untrusted_cert key_substitution

Scenarios
  untrusted_cert      on-path MITM with a forged certificate  -> client refuses (required demo 1)
  key_substitution    malicious relay swaps bob's key         -> pinned fingerprint refuses (demo 2)
  key_substitution_unpinned  same attack without pinning      -> succeeds silently (why pinning matters)
  tampering           one flipped ciphertext byte             -> Poly1305 rejects it
  mitm_trusted_tls    victim tricked into trusting the rogue CA, TLS-only mode  -> attacker reads messages
  mitm_trusted_e2ee   same, but E2EE on                       -> attacker sees only ciphertext
  eavesdropper        passive tap on the link                 -> plain TCP readable, TLS opaque
"""
import os
import shutil
import ssl
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import certs_tool
import keystore
import tlsutil
from attacks.evil_relay import EvilRelay
from attacks.tls_mitm import TlsMitm
from client import Client, connect
from keystore import fingerprint
from relay import Relay
from tap import Tap

SECRET = "the vault code is 4711"


class Events:
    def __init__(self):
        self.items, self.cv = [], threading.Condition()

    def __call__(self, kind, **kw):
        with self.cv:
            self.items.append((kind, kw))
            self.cv.notify_all()

    def wait(self, kind, timeout=5, pred=lambda kw: True):
        end = time.time() + timeout
        with self.cv:
            while True:
                for k, kw in self.items:
                    if k == kind and pred(kw):
                        return kw
                left = end - time.time()
                if left <= 0:
                    return None
                self.cv.wait(left)

    def count(self, kind):
        return sum(1 for k, _ in self.items if k == kind)


def server_ctx():
    return tlsutil.server_ctx("certs/server.crt", "certs/server.key")


def user(port, name, mode="e2ee", ca="certs/ca.crt", **kw):
    conn = connect("127.0.0.1", port, mode, ca)
    ev = Events()
    c = Client(name, keystore.load_or_create_keypair(name), conn.sock, mode, emit=ev, **kw).start()
    ev.wait("registered")
    if mode == "e2ee":
        ev.wait("published")
    return c, ev


class Scenario:
    def __init__(self, sid, title, expected):
        self.d = dict(id=sid, title=title, expected=expected, observed="", passed=False, timeline=[])

    def log(self, s):
        self.d["timeline"].append(s)

    def done(self, passed, observed):
        self.d.update(passed=bool(passed), observed=observed)
        return self.d


# ------------------------------------------------------------------ scenarios
def untrusted_cert():
    s = Scenario("untrusted_cert", "Forged certificate on the path (active TLS MITM)",
                 "The client aborts the handshake: certificate verify failed. No application data is ever sent.")
    relay = Relay("127.0.0.1", 0, server_ctx(), verbose=False).start()
    ev = Events()
    mitm = TlsMitm(0, ("127.0.0.1", relay.port), on_event=ev)
    s.log(f"attacker proxy listens on :{mitm.port} with a certificate signed by 'Rogue CA'")
    s.log("client connects to what it thinks is the relay; it trusts only the project CA")
    try:
        connect("127.0.0.1", mitm.port, "tls", "certs/ca.crt")
        res = s.done(False, "client accepted the forged certificate (BAD)")
    except ssl.SSLCertVerificationError as e:
        s.log(f"client: handshake aborted -> {e.verify_message}")
        r = ev.wait("victim-rejected")
        s.log(f"attacker saw the client's fatal alert: {r['reason'] if r else 'connection reset'}")
        res = s.done(True, f"Client refused the connection: {e.verify_message}. Attacker received an alert instead of data; "
                           f"{ev.count('frame')} application frames were exposed.")
    finally:
        mitm.stop(); relay.stop()
    return res


def key_substitution(pinned=True):
    sid = "key_substitution" if pinned else "key_substitution_unpinned"
    s = Scenario(sid, "Malicious relay substitutes Bob's public key" + ("" if pinned else " (no fingerprint check)"),
                 "Alice's pinned fingerprint for Bob does not match the key the relay hands out; she refuses to send."
                 if pinned else "Without pinning the attack succeeds silently: the relay reads everything.")
    relay = EvilRelay("127.0.0.1", 0, server_ctx(), verbose=False).start()
    port = relay.port
    bob, bev = user(port, "bob")
    bob_fp = fingerprint(bob.pub)
    s.log(f"Bob's real fingerprint (shown on his screen): {bob_fp}")
    alice, aev = user(port, "alice", trust={"bob": bob_fp} if pinned else {})
    sent = alice.send_message("bob", SECRET)
    lk = aev.wait("lookup", pred=lambda kw: kw["who"] == "bob", timeout=1)
    if pinned:
        mm = aev.wait("fingerprint_mismatch")
        if mm:
            s.log(f"relay handed Alice a key with fingerprint {mm['got']}")
            s.log("Alice compares it with the pinned one -> MISMATCH, key rejected, nothing encrypted")
        ok = (not sent) and mm is not None and not relay.intercepted
        res = s.done(ok, "Alice refused: fingerprint mismatch detected before any message was encrypted. "
                         f"Relay intercepted {len(relay.intercepted)} messages.")
    else:
        got = bev.wait("message", timeout=3)
        seen = relay.intercepted[0][2].decode() if relay.intercepted else None
        if lk:
            s.log(f"Alice sees Bob's fingerprint as {lk['fp']} (Bob's real one is {bob_fp}): they differ, but nobody checked")
        s.log(f"Bob received: {got['text']!r}  (looks normal)" if got else "Bob received nothing")
        s.log(f"the relay decrypted it in transit: {seen!r}")
        res = s.done(seen == SECRET and got is not None and got["text"] == SECRET,
                     "The attack worked: relay read the plaintext and Bob still received it intact. Only a fingerprint "
                     "comparison reveals it.")
    alice.close(); bob.close(); relay.stop()
    return res


def tampering():
    s = Scenario("tampering", "A ciphertext byte is flipped in transit",
                 "Poly1305 authentication fails on the receiver; the message is dropped, never shown as garbage.")
    relay = Relay("127.0.0.1", 0, server_ctx(), verbose=False).start()
    bob, bev = user(relay.port, "bob")
    alice, _ = user(relay.port, "alice", tamper=True)
    alice.send_message("bob", "pay 100 to carol")
    r = bev.wait("auth_failed")
    s.log("Alice's client flips the last byte of the ciphertext before sending")
    s.log("Bob's client: MAC check failed -> message dropped" if r else "Bob accepted it (BAD)")
    alice.close(); bob.close(); relay.stop()
    return s.done(r is not None and bev.count("message") == 0,
                  "Authentication failed on Bob's side; the corrupted message was dropped.")


def mitm_trusted(mode):
    e2ee = mode == "e2ee"
    s = Scenario("mitm_trusted_" + ("e2ee" if e2ee else "tls"),
                 "Victim trusts the attacker's CA - " + ("TLS + E2EE" if e2ee else "TLS only"),
                 "The attacker terminates TLS and " + ("sees only NaCl ciphertext: E2EE still protects the content."
                                                       if e2ee else "reads every message in clear: TLS alone is not end-to-end."))
    relay = Relay("127.0.0.1", 0, server_ctx(), verbose=False).start()
    ev = Events()
    mitm = TlsMitm(0, ("127.0.0.1", relay.port), on_event=ev)
    s.log("worst case: the attacker got a rogue CA into the clients' trust store, so TLS to the MITM succeeds")
    bob, bev = user(mitm.port, "bob", mode, ca="certs/rogue/ca.crt")
    alice, _ = user(mitm.port, "alice", mode, ca="certs/rogue/ca.crt")
    alice.send_message("bob", SECRET)
    got = bev.wait("message", timeout=4)
    time.sleep(0.2)
    msgs = [f for f in mitm.captured if f["frame"] == "MESSAGE" and f["direction"] == "client->relay"]
    readable = [f for f in msgs if f["readable"]]
    if msgs:
        m = msgs[0]
        s.log("attacker's view of Alice's message: " + (repr(m["text"]) if m["readable"] else f"ciphertext {m['ciphertext_head']}... (unreadable)"))
    s.log(f"Bob decrypted it normally: {got['text']!r}" if got else "Bob got nothing")
    ok = (bool(readable) if not e2ee else (bool(msgs) and not readable)) and got is not None
    obs = ("Attacker read the message in clear: " + repr(readable[0]["text"])) if readable else \
          "Attacker relayed the traffic but could not read it: only ciphertext crossed the wire."
    alice.close(); bob.close(); mitm.stop(); relay.stop()
    return s.done(ok, obs)


def eavesdropper():
    s = Scenario("eavesdropper", "Passive eavesdropper on the R1-R2 link",
                 "Plain TCP: messages visible. TLS: only record headers visible. TLS + E2EE: nothing but ciphertext either way.")
    out, ok = [], True
    for mode in ("tcp", "tls", "e2ee"):
        tls = mode != "tcp"
        relay = Relay("127.0.0.1", 0, server_ctx() if tls else None, verbose=False).start()
        seen = []
        tap = Tap(0, ("127.0.0.1", relay.port), on_record=lambda cid, d, rec: seen.append(rec))
        bob, bev = user(tap.port, "bob", mode); alice, _ = user(tap.port, "alice", mode)
        alice.send_message("bob", SECRET)
        bev.wait("message", timeout=3); time.sleep(0.3)
        leaked = any(r.get("text") and SECRET in r["text"] for r in seen)
        kinds = sorted({r["type"] for r in seen})
        s.log(f"{mode:5s}: eavesdropper parsed {len(seen)} records/frames ({', '.join(kinds)}); secret visible: {leaked}")
        out.append(f"{mode}: {'LEAKED' if leaked else 'opaque'}")
        ok &= (leaked == (mode == "tcp"))
        alice.close(); bob.close(); tap.stop(); relay.stop()
    return s.done(ok, "; ".join(out))


ALL = {
    "untrusted_cert": untrusted_cert,
    "key_substitution": lambda: key_substitution(True),
    "key_substitution_unpinned": lambda: key_substitution(False),
    "tampering": tampering,
    "mitm_trusted_tls": lambda: mitm_trusted("tls"),
    "mitm_trusted_e2ee": lambda: mitm_trusted("e2ee"),
    "eavesdropper": eavesdropper,
}


def run(names=None):
    certs_tool.ensure("certs")
    keystore.KEY_DIR = tempfile.mkdtemp()
    results = []
    try:
        for n in names or ALL:
            keystore.KEY_DIR = tempfile.mkdtemp(dir=keystore.KEY_DIR)
            results.append(ALL[n]())
    finally:
        pass
    return results


if __name__ == "__main__":
    res = run(sys.argv[1:] or None)
    for r in res:
        print(f"\n[{'PASS' if r['passed'] else 'FAIL'}] {r['title']}")
        print("  expected:", r["expected"])
        for t in r["timeline"]:
            print("   -", t)
        print("  observed:", r["observed"])
    sys.exit(0 if all(r["passed"] for r in res) else 1)
