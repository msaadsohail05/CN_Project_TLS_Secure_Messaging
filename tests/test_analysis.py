"""Capture-analysis tests: a real TLS conversation is recorded by the tap, turned into a pcap,
and the analyser must recover the protocol facts we know to be true."""
import os, sys, tempfile, time, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT); sys.path.insert(0, os.path.join(ROOT, "tests")); os.chdir(ROOT)

import certs_tool, keystore, tlsutil
from bench import analyze_overhead as ao
from client import Client, connect
from protocol import *
from relay import Relay
from synth import write_pcap
from tap import Tap
from test_core import Collector, make   # noqa: reuse helpers

certs_tool.ensure("certs")


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.ctx = tlsutil.server_ctx("certs/server.crt", "certs/server.key", allow_tls12=True)
        self.relay = Relay("127.0.0.1", 0, self.ctx, verbose=False).start()
        self.tap = Tap(0, ("127.0.0.1", self.relay.port), keep_chunks=True)
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        self.tap.stop(); self.relay.stop()

    def pcap(self):
        p = os.path.join(self.dir, "t.pcap")
        write_pcap(p, self.tap.chunks)
        return p

    def test_e2ee_exchange_layers(self):
        class R: port = self.tap.port
        a, ac = make(R, "alice9"); b, bc = make(R, "bob9")
        N, size = 10, 64
        for i in range(N):
            a.send_message("bob9", b"x" * size)
        for _ in range(N):
            self.assertIsNotNone(bc.wait("message", pred=lambda kw: True))
        time.sleep(0.3); a.close(); b.close(); time.sleep(0.3)
        flows = ao.analyze(self.pcap(), 8443, e2ee=True, messages=N, plaintext_bytes=N * size, name_len=5)
        self.assertEqual(len(flows), 2)
        f = flows[0]                                          # alice's connection
        t = f["tls"]
        self.assertEqual(t["version"], "TLS1.3"); self.assertFalse(t["resumed"])
        self.assertEqual(t["client_hello"]["sni"], "relay.local")
        L = f["layers_c2s"]
        self.assertEqual(L["e2ee"], 400)                      # 10 msgs * 40 B
        self.assertEqual(L["app_framing"], N * (6 + 5))
        # the analyser's residual is only REGISTER/PUBLISH/LOOKUP frames + close_notify: small
        self.assertLess(abs(L["other_control_frames_and_alerts"]), 250)
        self.assertGreater(L["overhead_ratio"], 0.5)

    def test_tls12_detected(self):
        c = connect("127.0.0.1", self.tap.port, "tls", "certs/ca.crt", tls_version="1.2")
        send_frame(c.sock, LOOKUP, b"probe"); recv_frame(c.sock); c.sock.close(); time.sleep(0.2)
        f = ao.analyze(self.pcap(), 8443)[0]
        self.assertEqual(f["tls"]["version"], "TLS1.2")

    def test_resumption_detected_and_smaller(self):
        ctx = tlsutil.client_ctx("certs/ca.crt")
        c1 = tlsutil.timed_connect("127.0.0.1", self.tap.port, ctx)
        send_frame(c1.sock, LOOKUP, b"probe"); recv_frame(c1.sock)
        sess = c1.sock.session; c1.sock.close(); time.sleep(0.2)
        c2 = tlsutil.timed_connect("127.0.0.1", self.tap.port, ctx, session=sess)
        send_frame(c2.sock, LOOKUP, b"probe"); recv_frame(c2.sock); c2.sock.close(); time.sleep(0.2)
        full, res = ao.analyze(self.pcap(), 8443)
        self.assertFalse(full["tls"]["resumed"]); self.assertTrue(res["tls"]["resumed"])
        # resumption skips the certificate chain, so the server's side of the handshake shrinks a lot
        self.assertLess(res["tls"]["handshake_bytes"]["s2c"], full["tls"]["handshake_bytes"]["s2c"] * 0.75)   # tickets ride along in the resumed flight

    def test_tap_sees_plain_text_only_when_unprotected(self):
        seen = []
        tap2 = Tap(0, ("127.0.0.1", self.relay.port), on_record=lambda cid, d, rec: seen.append(rec))
        c = connect("127.0.0.1", tap2.port, "tls", "certs/ca.crt")
        send_frame(c.sock, REGISTER, b"eve-target"); recv_frame(c.sock); time.sleep(0.2); c.sock.close()
        self.assertTrue(seen and all(r["layer"] == "tls" for r in seen))
        self.assertNotIn("eve-target", repr(seen))
        tap2.stop()


if __name__ == "__main__":
    unittest.main()
