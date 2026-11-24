"""The relay: a TLS 1.3 (or plain TCP) message router that never decrypts anything.

It keeps two in-memory tables, username -> connection and username -> X25519
public key, and forwards MESSAGE frames by recipient name. The body of a message
is opaque to it: with end-to-end encryption on, it is NaCl Box ciphertext.

CLI (unchanged from stage 5/6, plus a few flags):
    python3 relay.py --host 10.0.2.10 --port 8443 --tls [--plain-port 8080]
                     [--allow-tls12] [--keylog FILE]

`Relay` is also a library class: the web UI, the tests and the attack demos all
build on it (see the two hook methods at the bottom of the class).
"""
import argparse
import socket
import ssl
import threading

from protocol import *
import tlsutil


class Peer:
    """One connected client. Each peer has its own send lock so a slow client
    can never stall frames going to a different client."""

    def __init__(self, sock, addr):
        self.sock, self.addr, self.name = sock, addr, None
        self.lock = threading.Lock()

    def send(self, ftype, payload=b""):
        with self.lock:
            send_frame(self.sock, ftype, payload)


class Relay:
    def __init__(self, host="127.0.0.1", port=8443, ctx=None, plain_port=None,
                 on_event=None, verbose=True):
        self.host, self.port, self.ctx, self.plain_port = host, port, ctx, plain_port
        self.on_event, self.verbose = on_event, verbose
        self.peers = {}      # username -> Peer
        self.pubkeys = {}    # username -> 32-byte X25519 public key
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self._listeners = []
        self._open = set()

    # ------------------------------------------------------------ plumbing
    def emit(self, kind, **kw):
        if self.verbose:
            detail = " ".join(f"{k}={v}" for k, v in kw.items() if k != "body")
            print(f"[relay] {kind} {detail}", flush=True)
        if self.on_event:
            try:
                self.on_event(kind, **kw)
            except Exception:
                pass

    def start(self):
        """Bind the listeners and return immediately (threads do the work)."""
        specs = [(self.port, self.ctx)]
        if self.plain_port is not None:
            specs.append((self.plain_port, None))
        for i, (port, ctx) in enumerate(specs):
            srv = socket.create_server((self.host, port))
            srv.settimeout(0.5)
            actual = srv.getsockname()[1]               # resolves port 0
            if i == 0:
                self.port = actual
            else:
                self.plain_port = actual
            self._listeners.append(srv)
            threading.Thread(target=self._accept, args=(srv, ctx), daemon=True).start()
            self.emit("listening", host=self.host, port=actual, proto="TLS" if ctx else "plain TCP")
        return self

    def stop(self):
        self._stop.set()
        for s in self._listeners:
            try:
                s.close()
            except OSError:
                pass
        for s in list(self._open):
            try:
                s.close()
            except OSError:
                pass

    def _accept(self, srv, ctx):
        while not self._stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            threading.Thread(target=self._handle, args=(conn, addr, ctx), daemon=True).start()

    # ------------------------------------------------------------ hooks
    def key_for(self, requester, user, real_key):
        """Which public key to hand out for `user`. Honest relays return real_key;
        the attack demo overrides this (see attacks/evil_relay.py)."""
        return real_key

    def rewrite(self, sender, to, body):
        """Last look at a message before forwarding. Honest relays pass it through."""
        return body

    # ------------------------------------------------------------ per client
    def _handle(self, conn, addr, ctx):
        peer = None
        try:
            if ctx is not None:
                # Handshake runs in this client's own thread so one stalled
                # connection cannot block the accept loop for everybody else.
                conn.settimeout(10)
                conn = tlsutil.SafeTLS(ctx.wrap_socket(conn, server_side=True))
                self.emit("tls", peer=addr, version=conn.version(), cipher=conn.cipher()[0],
                          resumed=bool(conn.session_reused))
            peer = Peer(conn, addr)
            self._open.add(conn)
            while True:
                ftype, payload = recv_frame(conn)
                self._dispatch(peer, ftype, payload)
        except ssl.SSLError as e:
            self.emit("tls-failure", peer=addr, reason=e.reason or e)
        except socket.timeout:
            self.emit("handshake-timeout", peer=addr)
        except (ConnectionError, ValueError, OSError):
            pass
        finally:
            if peer is not None:
                with self.lock:
                    if peer.name and self.peers.get(peer.name) is peer:
                        del self.peers[peer.name]
                        self.pubkeys.pop(peer.name, None)
            self._open.discard(conn)
            try:
                conn.close()
            except OSError:
                pass
            self.emit("closed", peer=addr, user=peer.name if peer else None)

    def _dispatch(self, peer, ftype, payload):
        if ftype == REGISTER:
            user = payload.decode(errors="replace")
            if peer.name is not None:
                return peer.send(ERROR, b"already registered")
            if not NAME_RE.match(user):
                return peer.send(ERROR, b"invalid name")
            with self.lock:
                taken = user in self.peers
                if not taken:
                    self.peers[user] = peer
            if taken:
                return peer.send(ERROR, b"name taken")
            peer.name = user
            peer.send(REGISTER, b"ok")
            self.emit("register", user=user, addr=peer.addr)
        elif ftype == PUBLISH:
            if peer.name is None:
                return peer.send(ERROR, b"register first")
            if len(payload) != 32:
                return peer.send(ERROR, b"bad key length")
            with self.lock:
                self.pubkeys[peer.name] = payload
            peer.send(PUBLISH, b"ok")
            self.emit("publish", user=peer.name, key=payload.hex())
        elif ftype == LOOKUP:
            user = payload.decode(errors="replace")
            if not NAME_RE.match(user):
                return peer.send(ERROR, b"invalid name")
            with self.lock:
                key = self.pubkeys.get(user)
            if key:
                key = self.key_for(peer.name, user, key)
            body = (b"\x01" + key) if key else b"\x00"
            peer.send(LOOKUP, pack_name(user, body))
            self.emit("lookup", by=peer.name, user=user, found=bool(key))
        elif ftype == MESSAGE:
            if peer.name is None:
                return peer.send(ERROR, b"register first")
            to, body = unpack_name(payload)
            with self.lock:
                dest = self.peers.get(to)
            if dest is None:
                return peer.send(ERROR, b"unknown recipient")
            body = self.rewrite(peer.name, to, body)
            self.emit("forward", sender=peer.name, to=to, size=len(body), head=body[:24].hex(),
                      body=body)
            dest.send(MESSAGE, pack_name(peer.name, body))
        else:
            peer.send(ERROR, b"unknown type")


def build_ctx(args):
    if not args.tls:
        return None
    return tlsutil.server_ctx(args.cert, args.key, allow_tls12=args.allow_tls12,
                              keylog=args.keylog)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--plain-port", type=int, help="also listen on plain TCP here (baseline mode, e.g. 8080)")
    p.add_argument("--tls", action="store_true", help="serve TLS on --port (TLS 1.3 only)")
    p.add_argument("--allow-tls12", action="store_true", help="also accept TLS 1.2 (comparison runs only)")
    p.add_argument("--cert", default="certs/server.crt")
    p.add_argument("--key", default="certs/server.key")
    p.add_argument("--keylog", help="write TLS secrets here for Wireshark")
    args = p.parse_args()

    relay = Relay(args.host, args.port, build_ctx(args), args.plain_port).start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        relay.stop()
