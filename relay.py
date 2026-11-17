import argparse, socket, ssl, threading
from protocol import *

clients = {}                 # username -> socket
lock = threading.Lock()      # protects the clients dict
send_lock = threading.Lock() # stops two threads interleaving frames on one socket

def safe_send(sock, ftype, payload=b""):
    with send_lock:
        send_frame(sock, ftype, payload)

def handle(conn, addr, ctx):
    name = None
    try:
        if ctx is not None:
            # The handshake happens here, in the client's own thread, so one slow
            # or broken client cannot block the accept loop for everyone else.
            conn.settimeout(10)
            conn = ctx.wrap_socket(conn, server_side=True)
            conn.settimeout(None)
            print(f"TLS handshake ok from {addr}: {conn.version()} {conn.cipher()[0]}")
        while True:
            ftype, payload = recv_frame(conn)
            if ftype == REGISTER:
                user = payload.decode()
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
            elif ftype == LOOKUP:
                with lock:
                    found = payload.decode() in clients
                safe_send(conn, LOOKUP, b"1" if found else b"0")
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
        conn.close()
        print(f"closed {addr}")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--tls", action="store_true", help="require TLS 1.3")
    p.add_argument("--cert", default="certs/server.crt")
    p.add_argument("--key", default="certs/server.key")
    p.add_argument("--keylog", help="write TLS secrets here for Wireshark")
    args = p.parse_args()

    ctx = None
    if args.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(args.cert, args.key)
        if args.keylog:
            ctx.keylog_filename = args.keylog

    with socket.create_server((args.host, args.port)) as srv:
        print(f"relay listening on {args.host}:{args.port} ({'TLS 1.3' if ctx else 'plain TCP'})")
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle, args=(conn, addr, ctx), daemon=True).start()