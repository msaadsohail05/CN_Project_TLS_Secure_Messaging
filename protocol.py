import struct

import re
REGISTER, LOOKUP, MESSAGE, ERROR, PUBLISH = 1, 2, 3, 4, 5
NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")  # usernames: safe for file names too
MAX_FRAME = 1 << 20  # 1 MiB safety limit

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return buf

def send_frame(sock, ftype, payload=b""):
    body = bytes([ftype]) + payload
    sock.sendall(struct.pack("!I", len(body)) + body)

def recv_frame(sock):
    (length,) = struct.unpack("!I", recv_exact(sock, 4))
    if length < 1 or length > MAX_FRAME:
        raise ValueError("bad frame length")
    body = recv_exact(sock, length)
    return body[0], body[1:]

def pack_name(name, body):
    n = name.encode()
    return bytes([len(n)]) + n + body

def unpack_name(payload):
    n = payload[0]
    return payload[1:1 + n].decode(), payload[1 + n:]