"""End-to-end tests for the messaging core. Run: python -m unittest discover -s tests -v"""
import os, shutil, ssl, sys, tempfile, threading, time, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import certs_tool, keystore, tlsutil
from client import Client, connect
from protocol import *
from relay import Relay

certs_tool.ensure("certs")
KEYS = tempfile.mkdtemp()
keystore.KEY_DIR = KEYS


class Collector:
    def __init__(self):
        self.events, self.cv = [], threading.Condition()

    def __call__(self, kind, **kw):
        with self.cv:
            self.events.append((kind, kw))
            self.cv.notify_all()

    def wait(self, kind, timeout=5, pred=lambda kw: True):
        end = time.time() + timeout
        with self.cv:
            while True:
                for k, kw in self.events:
                    if k == kind and pred(kw):
                        return dict(kw, kind=k)
                left = end - time.time()
                if left <= 0:
                    return None
                self.cv.wait(left)


def make(relay, user, mode="e2ee", **kw):
    conn = connect("127.0.0.1", relay.port, mode, "certs/ca.crt")
    col = Collector()
    c = Client(user, keystore.load_or_create_keypair(user), conn.sock, mode, emit=col, **kw).start()
    assert col.wait("registered")
    return c, col


class CoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = Collector()
        ctx = tlsutil.server_ctx("certs/server.crt", "certs/server.key", allow_tls12=True)
        cls.relay = Relay("127.0.0.1", 0, ctx, plain_port=0, on_event=cls.events, verbose=False).start()
        cls.plain_port = cls.relay.plain_port

    @classmethod
    def tearDownClass(cls):
        cls.relay.stop()
        shutil.rmtree(KEYS, ignore_errors=True)

    def test_e2ee_roundtrip_and_relay_sees_only_ciphertext(self):
        a, _ = make(self.relay, "alice1"); b, bc = make(self.relay, "bob1")
        self.assertTrue(a.send_message("bob1", "hello bob, secret"))
        m = bc.wait("message")
        self.assertEqual(m["text"], "hello bob, secret")
        fwd = self.events.wait("forward", pred=lambda kw: kw["to"] == "bob1")
        self.assertNotIn(b"secret", fwd["body"])
        self.assertEqual(fwd["size"], len(b"hello bob, secret") + 40)   # 24 nonce + 16 MAC
        a.close(); b.close()

    def test_tls_only_mode_relay_can_read(self):
        a, _ = make(self.relay, "alice2", "tls"); b, bc = make(self.relay, "bob2", "tls")
        a.send_message("bob2", "visible to relay")
        self.assertEqual(bc.wait("message")["text"], "visible to relay")
        fwd = self.events.wait("forward", pred=lambda kw: kw["to"] == "bob2")
        self.assertEqual(fwd["body"], b"visible to relay")
        a.close(); b.close()

    def test_plain_tcp_baseline(self):
        conn = connect("127.0.0.1", self.plain_port, "tcp")
        col = Collector(); c = Client("tcpuser", keystore.load_or_create_keypair("tcpuser"), conn.sock, "tcp", emit=col).start()
        self.assertTrue(col.wait("registered")); self.assertEqual(conn.version, "TCP"); c.close()

    def test_tamper_is_rejected(self):
        a, _ = make(self.relay, "alice3", tamper=True); b, bc = make(self.relay, "bob3")
        a.send_message("bob3", "this will be corrupted")
        self.assertIsNotNone(bc.wait("auth_failed"))
        a.close(); b.close()

    def test_fingerprint_pin_mismatch_refuses(self):
        a, _ = make(self.relay, "alice4", trust={"bob4": "0000 0000 0000 0000 0000 0000 0000 0000"})
        b, _ = make(self.relay, "bob4")
        self.assertFalse(a.send_message("bob4", "should not go out"))
        a.close(); b.close()

    def test_matching_fingerprint_pin_allows(self):
        b, _ = make(self.relay, "bob5")
        fp = keystore.fingerprint(b.pub)
        a, _ = make(self.relay, "alice5", trust={"bob5": fp})
        self.assertTrue(a.send_message("bob5", "ok")); a.close(); b.close()

    def test_untrusted_ca_is_refused(self):
        certs_tool.ensure("certs")
        with self.assertRaises(ssl.SSLCertVerificationError):
            connect("127.0.0.1", self.relay.port, "tls", "certs/rogue/ca.crt")

    def test_tls12_client_refused_by_tls13_only_relay(self):
        ctx13 = tlsutil.server_ctx("certs/server.crt", "certs/server.key")
        r = Relay("127.0.0.1", 0, ctx13, verbose=False).start()
        try:
            with self.assertRaises(ssl.SSLError):
                connect("127.0.0.1", r.port, "tls", "certs/ca.crt", tls_version="1.2")
        finally:
            r.stop()

    def test_tls12_works_when_allowed(self):
        c = connect("127.0.0.1", self.relay.port, "tls", "certs/ca.crt", tls_version="1.2")
        self.assertEqual(c.version, "TLSv1.2"); c.sock.close()

    def test_session_resumption_is_real(self):
        ctx = tlsutil.client_ctx("certs/ca.crt")      # resumption needs the SAME context object
        c1 = tlsutil.timed_connect("127.0.0.1", self.relay.port, ctx)
        self.assertFalse(c1.reused)
        send_frame(c1.sock, LOOKUP, b"probe"); recv_frame(c1.sock)     # let the ticket arrive
        sess = c1.sock.session; c1.sock.close()
        c2 = tlsutil.timed_connect("127.0.0.1", self.relay.port, ctx, "relay.local", sess)
        self.assertTrue(c2.reused); self.assertEqual(c2.version, "TLSv1.3"); c2.sock.close()

    def test_name_taken(self):
        a, _ = make(self.relay, "dup")
        conn = connect("127.0.0.1", self.relay.port, "tls", "certs/ca.crt")
        send_frame(conn.sock, REGISTER, b"dup"); t, p = recv_frame(conn.sock)
        self.assertEqual((t, p), (ERROR, b"name taken")); conn.sock.close(); a.close()


if __name__ == "__main__":
    unittest.main()
