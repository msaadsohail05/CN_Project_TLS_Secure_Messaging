"""Loopback delay emulator, used ONLY by `run_experiments.py --env local` on machines
without network namespaces (e.g. a Windows laptop) so the whole pipeline can be
exercised end to end. It is a user-space model, not tc netem: results produced through
it are labelled env=loopback-emulated and are never a substitute for the netns runs.

A DelayProxy listens on a port and forwards every TCP connection to a target, holding
each chunk of bytes for `one_way_ms` in each direction.

Limitation worth stating in any write-up: connect() completes against the proxy's own
listener, so TCP-connect time is NOT inflated by the emulated delay; TLS handshake time
and time-to-first-data are.
"""
import queue
import socket
import threading
import time


def _pump(src, dst, delay_s):
    q = queue.Queue()

    def reader():
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                q.put((time.perf_counter() + delay_s, data))
        except OSError:
            pass
        q.put((0, None))

    def writer():
        try:
            while True:
                due, data = q.get()
                if data is None:
                    break
                wait = due - time.perf_counter()
                if wait > 0:
                    time.sleep(wait)
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    s.close()
                except OSError:
                    pass

    threading.Thread(target=reader, daemon=True).start()
    threading.Thread(target=writer, daemon=True).start()


class DelayProxy:
    def __init__(self, listen_port, target, one_way_ms, host="127.0.0.1"):
        self.target, self.delay = target, one_way_ms / 1000.0
        self.srv = socket.create_server((host, listen_port))
        self.srv.settimeout(0.5)
        self.port = self.srv.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self._stop:
            try:
                c, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                u = socket.create_connection(self.target)
            except OSError:
                c.close()
                continue
            for s in (c, u):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            _pump(c, u, self.delay)
            _pump(u, c, self.delay)

    def stop(self):
        self._stop = True
        try:
            self.srv.close()
        except OSError:
            pass
