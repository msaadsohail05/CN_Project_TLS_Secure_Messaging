"""The live lab behind the web UI.

Everything here is the real system, not a mock: a Relay (TLS 1.3 or plain TCP), a Tap
recording proxy standing in for the wire between clients and relay, and two real Client
objects (Alice and Bob). The browser only drives and visualises them over a small JSON/SSE API.

Observers, from most to least powerful:
    relay  - sees every frame it forwards (after TLS is removed): readable in `tcp`/`tls`
             mode, NaCl ciphertext in `e2ee` mode.
    wire   - the Tap: a passive on-path observer that parses what a network sniffer could
             parse (TLS record headers, or plain frames when there is no TLS).
"""
import os
import queue
import shutil
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import certs_tool
import keystore
import tlsutil
from attacks.evil_relay import EvilRelay
from client import MODES, Client, connect
from keystore import fingerprint, load_or_create_keypair
from relay import Relay
from tap import Tap

UI_KEYS = os.path.join(ROOT, "keys_ui")


class Hub:
    """Fan-out of events to every connected browser (server-sent events)."""

    def __init__(self):
        self.subs, self.lock = [], threading.Lock()

    def subscribe(self):
        q = queue.Queue(maxsize=500)
        with self.lock:
            self.subs.append(q)
        return q

    def unsubscribe(self, q):
        with self.lock:
            if q in self.subs:
                self.subs.remove(q)

    def publish(self, **evt):
        evt["t"] = round(time.time() * 1000)
        with self.lock:
            for q in self.subs:
                try:
                    q.put_nowait(evt)
                except queue.Full:
                    pass


def printable(b):
    return bool(b) and all(32 <= c < 127 or c in (9, 10, 13) for c in b)


class Lab:
    def __init__(self, hub):
        self.hub = hub
        self.lock = threading.RLock()
        self.cfg = dict(mode="e2ee", tamper=False, evil=False, pin=False)
        self.relay = self.tap = self.alice = self.bob = None
        self.expect = None                    # the last message's expected wire size, to verify the breakdown
        self.conn_user = {}
        self.info = {}
        certs_tool.ensure(os.path.join(ROOT, "certs"))
        os.makedirs(UI_KEYS, exist_ok=True)
        self.rebuild()

    # ------------------------------------------------------------------ lifecycle
    def teardown(self):
        for c in (self.alice, self.bob):
            if c:
                c.close()
        for s in (self.tap, self.relay):
            if s:
                s.stop()
        self.alice = self.bob = self.tap = self.relay = None

    def rebuild(self, **changes):
        with self.lock:
            self.cfg.update({k: v for k, v in changes.items() if k in self.cfg})
            self.teardown()
            mode, evil = self.cfg["mode"], self.cfg["evil"] and self.cfg["mode"] == "e2ee"
            use_tls, use_e2ee = MODES[mode]
            ctx = tlsutil.server_ctx(os.path.join(ROOT, "certs/server.crt"),
                                     os.path.join(ROOT, "certs/server.key")) if use_tls else None
            cls = EvilRelay if evil else Relay
            self.relay = cls("127.0.0.1", 0, ctx, on_event=self.on_relay, verbose=False).start()
            self.tap = Tap(0, ("127.0.0.1", self.relay.port), on_record=self.on_wire)
            self.conn_user = {1: "alice", 2: "bob"}
            keystore.KEY_DIR = UI_KEYS
            ask, bsk = load_or_create_keypair("alice"), load_or_create_keypair("bob")
            self.fp = {"alice": fingerprint(ask.public_key.encode()), "bob": fingerprint(bsk.public_key.encode())}
            ca = os.path.join(ROOT, "certs/ca.crt")
            trust = {"bob": self.fp["bob"]} if self.cfg["pin"] else {}
            conn_a = connect("127.0.0.1", self.tap.port, mode, ca)
            self.alice = Client("alice", ask, conn_a.sock, mode, emit=self.client_cb("alice"),
                                tamper=self.cfg["tamper"], trust=trust).start()
            conn_b = connect("127.0.0.1", self.tap.port, mode, ca)
            self.bob = Client("bob", bsk, conn_b.sock, mode, emit=self.client_cb("bob")).start()
            self.info = dict(version=conn_a.version, cipher=conn_a.cipher, tcp_ms=round(conn_a.tcp_ms, 2),
                             tls_ms=round(conn_a.tls_ms, 2))
            self.hub.publish(type="reset", state=self.state())
            return self.state()

    def state(self):
        return dict(cfg=self.cfg, fp=getattr(self, "fp", {}), info=self.info,
                    relay_port=self.relay.port if self.relay else None)

    # ------------------------------------------------------------------ callbacks
    def client_cb(self, who):
        def cb(kind, **kw):
            if kind == "message":
                self.hub.publish(type="chat", who=who, dir="in", frm=kw["sender"], text=kw["text"],
                                 e2ee=kw["e2ee"], wire=kw["wire"])
            elif kind == "lookup":
                self.hub.publish(type="fp", who=who, peer=kw["who"], fp=kw["fp"])
            elif kind == "fingerprint_mismatch":
                self.hub.publish(type="alert", who=who, level="danger", title="Fingerprint mismatch",
                                 text=f"The relay returned a key for {kw['who']} that does not match the pinned "
                                      f"fingerprint. {who.title()} refuses to encrypt.",
                                 got=kw["got"], expected=kw["expected"])
            elif kind == "auth_failed":
                self.hub.publish(type="alert", who=who, level="danger", title="Authentication failed",
                                 text=f"A message from {kw['sender']} failed its Poly1305 check and was dropped.")
            elif kind == "error":
                self.hub.publish(type="alert", who=who, level="warn", title="Error", text=kw["msg"])
            elif kind == "nokey":
                self.hub.publish(type="alert", who=who, level="warn", title="No key", text=f"{kw['who']} has no published key")
        return cb

    def on_relay(self, kind, **kw):
        if kind == "forward":
            body = kw["body"]
            self.hub.publish(type="relay", kind="forward", sender=kw["sender"], to=kw["to"], size=kw["size"],
                             head=kw["head"], readable=printable(body), text=body.decode() if printable(body) else None)
        elif kind == "intercepted":
            self.hub.publish(type="relay", kind="intercepted", sender=kw["sender"], to=kw["to"], text=kw["plaintext"])
        elif kind in ("register", "publish", "lookup"):
            self.hub.publish(type="relay", kind=kind, **{k: str(v) for k, v in kw.items() if k != "key"})

    def on_wire(self, cid, direction, rec):
        who = self.conn_user.get(cid, f"conn{cid}")
        rec = dict(rec)
        rtype = rec.pop("type")                       # "type" is the event discriminator, so rename
        self.hub.publish(type="wire", rtype=rtype, who=who, dir=direction, **rec)
        if self.expect and direction == "c2s" and who == "alice" and rec["wire"] == self.expect["wire"]:
            self.hub.publish(type="breakdown", verified=True, **self.expect)
            self.expect = None

    # ------------------------------------------------------------------ actions
    def send(self, who, text):
        with self.lock:
            me, peer = (self.alice, "bob") if who == "alice" else (self.bob, "alice")
            mode = self.cfg["mode"]
            data = text.encode()
            name = peer.encode()
            frame = 4 + 1 + 1 + len(name) + len(data) + (40 if MODES[mode][1] else 0)
            parts = [dict(layer="plaintext", bytes=len(data), note="what you typed"),]
            if MODES[mode][1]:
                parts.append(dict(layer="e2ee", bytes=40, note="24 B nonce + 16 B Poly1305 MAC"))
            parts.append(dict(layer="framing", bytes=4 + 1 + 1 + len(name), note="4 B length + 1 B type + 1 B name len + recipient"))
            wire = frame
            if MODES[mode][0]:
                parts.append(dict(layer="tls", bytes=22, note="5 B record header + 1 B inner type + 16 B AEAD tag"))
                wire = 5 + frame + 1 + 16
            parts.append(dict(layer="tcpip", bytes=40, note="IP 20 B + TCP 20 B (typical, modelled)"))
            self.expect = dict(wire=wire, parts=parts, who=who, mode=mode)
            self.hub.publish(type="chat", who=who, dir="out", to=peer, text=text)
            ok = me.send_message(peer, text)
            return ok

    def rogue_client(self):
        """A client that has been given the attacker's CA: connects to the real relay, so the
        relay's real certificate does not verify and the handshake fails."""
        if not MODES[self.cfg["mode"]][0]:
            return dict(ok=False, text="Plain TCP mode has no TLS, so there is no certificate to check.")
        import ssl
        try:
            connect("127.0.0.1", self.relay.port, "tls", os.path.join(ROOT, "certs/rogue/ca.crt"))
            return dict(ok=False, text="Handshake unexpectedly succeeded.")
        except ssl.SSLCertVerificationError as e:
            self.hub.publish(type="alert", who="mallory", level="ok", title="Certificate rejected",
                             text=f"A client that does not trust our CA aborts the handshake: {e.verify_message}.")
            return dict(ok=True, text=e.verify_message)
