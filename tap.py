"""A passive on-path observer: a recording TCP proxy.

It sits between clients and the relay exactly where an eavesdropper on the R1-R2 transit
link would sit: it forwards bytes untouched and remembers every byte it saw. It never has
any key, so what it can parse is precisely what a network observer can parse:

  * TLS flows   -> record headers only (content type, version, length). Payloads are opaque.
  * plain flows -> the application frames themselves, readable text and all.

Used by the web UI ("what the wire shows"), by the unit tests (to synthesise a capture), and
runnable on its own as a stand-in for tcpdump when you just want to look:

    python3 tap.py --listen 9443 --target 127.0.0.1:8443
"""
import argparse
import itertools
import socket
import struct
import threading
import time

TLS_TYPES = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "ApplicationData"}
FRAME_NAMES = {1: "REGISTER", 2: "LOOKUP", 3: "MESSAGE", 4: "ERROR", 5: "PUBLISH"}
VERSIONS = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2 (legacy field)", 0x0304: "TLS 1.3"}


class Stream:
    """Incrementally parses one direction of one connection."""

    def __init__(self):
        self.buf, self.kind = b"", None          # kind: "tls" | "plain" | None until known

    def feed(self, data):
        self.buf += data
        out = []
        if self.kind is None and self.buf:
            self.kind = "tls" if self.buf[0] in TLS_TYPES and len(self.buf) >= 3 and self.buf[1] == 3 else "plain"
        while self.kind == "tls" and len(self.buf) >= 5:
            ctype, ver, n = self.buf[0], struct.unpack("!H", self.buf[1:3])[0], struct.unpack("!H", self.buf[3:5])[0]
            if len(self.buf) < 5 + n:
                break
            body, self.buf = self.buf[5:5 + n], self.buf[5 + n:]
            out.append(dict(layer="tls", type=TLS_TYPES.get(ctype, str(ctype)), type_id=ctype,
                            version=VERSIONS.get(ver, hex(ver)), length=n, wire=5 + n, head=body[:12].hex()))
        while self.kind == "plain" and len(self.buf) >= 5:
            n = struct.unpack("!I", self.buf[:4])[0]
            if len(self.buf) < 4 + n:
                break
            frame, self.buf = self.buf[4:4 + n], self.buf[4 + n:]
            ft, payload = frame[0], frame[1:]
            readable = payload[1 + payload[0]:] if ft == 3 and payload else payload
            out.append(dict(layer="app", type=FRAME_NAMES.get(ft, str(ft)), type_id=ft, length=n, wire=4 + n,
                            text=(readable[:200].decode("utf-8", "replace") if ft == 3 and readable.isascii() else None),
                            head=frame[:12].hex()))
        return out


class Tap:
    def __init__(self, listen_port, target, host="127.0.0.1", on_record=None, keep_chunks=False):
        self.target, self.on_record, self.keep = target, on_record, keep_chunks
        self.chunks = []                          # (t, conn_id, 'c2s'|'s2c', bytes)
        self.ids = itertools.count(1)
        self.srv = socket.create_server((host, listen_port))
        self.srv.settimeout(0.5)
        self.port = self.srv.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self._stop:
            try:
                c, addr = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                u = socket.create_connection(self.target)
            except OSError:
                c.close()
                continue
            cid = next(self.ids)
            for s in (c, u):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._seen(cid, "open", b"", addr)
            threading.Thread(target=self._pump, args=(cid, c, u, "c2s"), daemon=True).start()
            threading.Thread(target=self._pump, args=(cid, u, c, "s2c"), daemon=True).start()

    def _seen(self, cid, direction, data, addr=None):
        if self.keep:
            self.chunks.append((time.time(), cid, direction, data))

    def _pump(self, cid, src, dst, direction):
        stream = Stream()
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                self._seen(cid, direction, data)
                dst.sendall(data)
                if self.on_record:
                    for rec in stream.feed(data):
                        self.on_record(cid, direction, rec)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def stop(self):
        self._stop = True
        try:
            self.srv.close()
        except OSError:
            pass


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--listen", type=int, required=True)
    ap.add_argument("--target", required=True, help="host:port of the real relay")
    a = ap.parse_args()
    h, _, p = a.target.rpartition(":")

    def show(cid, d, rec):
        extra = f" text={rec['text']!r}" if rec.get("text") else ""
        print(f"conn {cid} {d} {rec['layer']}:{rec['type']} {rec['wire']}B{extra}", flush=True)

    Tap(a.listen, (h, int(p)), on_record=show)
    threading.Event().wait()
