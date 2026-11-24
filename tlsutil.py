"""Shared TLS helpers: context builders and a timed connect used by every tool.

Everything that opens a TLS connection in this project goes through here so
that the version pinning, key logging and timing are done in exactly one place.
"""
import select
import socket
import ssl
import threading
import time

VERSIONS = {"1.2": ssl.TLSVersion.TLSv1_2, "1.3": ssl.TLSVersion.TLSv1_3}


def server_ctx(cert, key, allow_tls12=False, keylog=None):
    """Relay-side context. TLS 1.3 only unless allow_tls12 (comparison runs)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = VERSIONS["1.2"] if allow_tls12 else VERSIONS["1.3"]
    ctx.maximum_version = VERSIONS["1.3"]
    ctx.load_cert_chain(cert, key)
    if keylog:
        ctx.keylog_filename = keylog
    return ctx


def client_ctx(ca, version="1.3", keylog=None):
    """Client-side context that pins exactly one TLS version and verifies the
    relay certificate (chain + hostname/IP SAN) against our private CA."""
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
    ctx.minimum_version = ctx.maximum_version = VERSIONS[version]
    if keylog:
        ctx.keylog_filename = keylog
    return ctx


class SafeTLS:
    """Thread-safe wrapper around an established SSLSocket.

    A blocking SSLSocket must not be read and written from two threads at once: OpenSSL's
    SSL object is not thread-safe, and in TLS 1.3 a read can also have to process a
    post-handshake message (NewSessionTicket) while another thread is mid-write. Our relay
    and clients do exactly that (one thread reads, others send), so every TLS socket goes
    through this wrapper: the socket is non-blocking, each SSL call happens under a lock, and
    waiting for readiness happens OUTSIDE the lock so a blocked reader never starves writers.

    It offers just what protocol.py uses (recv / sendall) plus close(); everything else
    (session, version(), cipher(), ...) is delegated to the wrapped socket.
    """

    def __init__(self, sock):
        sock.setblocking(False)
        self._s = sock
        self._lock = threading.Lock()

    def _wait(self, read):
        try:
            select.select([self._s] if read else [], [] if read else [self._s], [], 1.0)
        except (ValueError, OSError) as e:       # socket closed by another thread
            raise ConnectionError("socket closed") from e

    def recv(self, n):
        while True:
            with self._lock:
                try:
                    return self._s.recv(n)
                except (ssl.SSLWantReadError, BlockingIOError):
                    want_read = True
                except ssl.SSLWantWriteError:
                    want_read = False
            self._wait(want_read)

    def sendall(self, data):
        view = memoryview(data)
        while len(view):
            with self._lock:
                try:
                    n = self._s.send(view)
                    want_read = None
                except (ssl.SSLWantReadError, BlockingIOError):
                    n, want_read = 0, True
                except ssl.SSLWantWriteError:
                    n, want_read = 0, False
            if n:
                view = view[n:]
            else:
                self._wait(want_read)

    def settimeout(self, _):                     # stays non-blocking; callers use timeouts elsewhere
        pass

    def close(self):
        self._s.close()

    def __getattr__(self, name):
        return getattr(self._s, name)


class Conn:
    """Result of timed_connect: the socket plus what was measured."""
    __slots__ = ("sock", "tcp_ms", "tls_ms", "reused", "version", "cipher")


def timed_connect(host, port, ctx=None, sni="relay.local", session=None, timeout=15):
    """Open a connection and time the two phases separately.

    tcp_ms  : connect() call, i.e. SYN sent -> handshake ACK (1 RTT).
    tls_ms  : first ClientHello -> handshake complete (do_handshake()).
    Plain TCP (ctx is None) reports tls_ms = 0.
    """
    c = Conn()
    t0 = time.perf_counter_ns()
    raw = socket.create_connection((host, port), timeout=timeout)
    t1 = time.perf_counter_ns()
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    c.tcp_ms = (t1 - t0) / 1e6
    c.tls_ms, c.reused, c.version, c.cipher = 0.0, False, "TCP", ""
    if ctx is None:
        c.sock = raw
        raw.settimeout(None)
        return c
    wrapped = ctx.wrap_socket(raw, server_hostname=sni, session=session,
                              do_handshake_on_connect=False)
    t2 = time.perf_counter_ns()
    wrapped.do_handshake()
    t3 = time.perf_counter_ns()
    c.tls_ms = (t3 - t2) / 1e6
    c.reused = bool(wrapped.session_reused)
    c.version = wrapped.version()
    c.cipher = wrapped.cipher()[0]
    c.sock = SafeTLS(wrapped)
    return c
