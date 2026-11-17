import socket, sys, threading
from protocol import *

clients = {}                 # username -> socket
lock = threading.Lock()      # protects the clients dict
send_lock = threading.Lock() # stops two threads interleaving frames on one socket

def safe_send(sock, ftype, payload=b""):
    with send_lock:
        send_frame(sock, ftype, payload)

def handle(conn, addr):
    name = None
    try:
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
    except (ConnectionError, ValueError, OSError):
        pass
    finally:
        with lock:
            if name and clients.get(name) is conn:
                del clients[name]
        conn.close()
        print(f"closed {addr}")

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8443
    with socket.create_server((host, port)) as srv:
        print(f"relay listening on {host}:{port}")
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()