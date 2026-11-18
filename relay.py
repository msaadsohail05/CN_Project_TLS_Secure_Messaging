import argparse, socket, ssl, threading
from protocol import *

clients = {}                 # username -> socket
pubkeys = {}                 # username -> 32-byte X25519 public key
lock = threading.Lock()      # protects clients and pubkeys
send_lock = threading.Lock() # stops two threads interleaving frames on one socket

def safe_send(sock, ftype, payload=b""):
    with send_lock:
        send_frame(sock, ftype, payload)

def handle(conn, addr, ctx):
    name = None
    try:
        if ctx is not None:
            conn.settimeout(10)
            conn = ctx.wrap_socket(conn, server_side=True)
            conn.settimeout(None)
            print(f"TLS handshake ok from {addr}: {conn.version()} {conn.cipher()[0]} resumed={conn.session_reused}")
        while True:
            ftype, payload = recv_frame(conn)
            if ftype == REGISTER:
                user = payload.decode()
                if name is not None:
                    safe_send(conn, ERROR, b"already registered")
                    continue
                if not NAME_RE.match(user):
                    safe_send(conn, ERROR, b"invalid name")
                    continue
                with lock:
                    taken = user in clients
                    if not taken:
                        clients[user] = conn
                if taken:
                    safe_send(conn, ERROR, b"name taken")
                    continue
                name = user
                safe_send(conn, REGISTER, b"ok")
                print(f"registered {user} from {addr}")
            elif ftype == PUBLISH:
                if name is None:
                    safe_send(conn, ERROR, b"register first")
                    continue
                if len(payload) != 32:
                    safe_send(conn, ERROR, b"bad key length")
                    continue
                with lock:
                    pubkeys[name] = payload
                safe_send(conn, PUBLISH, b"ok")
                print(f"published key for {name}: {payload.hex()[:16]}...")
            elif ftype == LOOKUP:
                user = payload.decode()
                if not NAME_RE.match(user):
                    safe_send(conn, ERROR, b"invalid name")
                    continue
                with lock:
                    key = pubkeys.get(user)
                body = (b"\x01" + key) if key else b"\x00"
                safe_send(conn, LOOKUP, pack_name(user, body))
            elif ftype == MESSAGE:
                if name is None:
                    safe_send(conn, ERROR, b"register first")
                    continue
                to, body = unpack_name(payload)
                with lock:
                    dest = clients.get(to)
                if dest is None:
                    safe_send(conn, ERROR, b"unknown recipient")
                else:
                    print(f"forward {name}->{to}: {len(body)} bytes: {body.hex()[:48]}...")
                    safe_send(dest, MESSAGE, pack_name(name, body))
            else:
                safe_send(conn, ERROR, b"unknown type")
    except ssl.SSLError as e:
        print(f"TLS failure from {addr}: {e.reason or e}")
    except socket.timeout:
        print(f"handshake timed out from {addr}")
    except (ConnectionError, ValueError, OSError):
        pass
    finally:
        with lock:
            if name and clients.get(name) is conn:
                del clients[name]
                pubkeys.pop(name, None)
        conn.close()
        print(f"closed {addr}")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--tls", action="store_true", help="require TLS 1.3")
    p.add_argument("--tls-version", choices=["1.3", "1.2"], default="1.3",help="the only TLS version the relay will accept")
    p.add_argument("--cert", default="certs/server.crt")
    p.add_argument("--key", default="certs/server.key")
    p.add_argument("--keylog", help="write TLS secrets here for Wireshark")
    args = p.parse_args()

    ctx = None
    if args.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        v = ssl.TLSVersion.TLSv1_3 if args.tls_version == "1.3" else ssl.TLSVersion.TLSv1_2
        ctx.minimum_version = v
        ctx.maximum_version = v
        ctx.load_cert_chain(args.cert, args.key)
        if args.keylog:
            ctx.keylog_filename = args.keylog

    with socket.create_server((args.host, args.port)) as srv:
        print(f"relay listening on {args.host}:{args.port} ({'TLS ' + args.tls_version if ctx else 'plain TCP'})")
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle, args=(conn, addr, ctx), daemon=True).start()