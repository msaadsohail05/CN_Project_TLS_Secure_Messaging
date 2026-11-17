import socket, sys, threading
from protocol import *

def receiver(sock):
    try:
        while True:
            ftype, payload = recv_frame(sock)
            if ftype == MESSAGE:
                sender, body = unpack_name(payload)
                print(f"\n[{sender}] {body.decode()}")
            elif ftype == ERROR:
                print("\n[error]", payload.decode())
            elif ftype == LOOKUP:
                print("\n[lookup]", "online" if payload == b"1" else "not found")
            elif ftype == REGISTER:
                print("\n[registered]")
    except (ConnectionError, OSError):
        print("\nconnection closed")

if __name__ == "__main__":
    user = sys.argv[1]
    host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 8443
    sock = socket.create_connection((host, port))
    send_frame(sock, REGISTER, user.encode())
    threading.Thread(target=receiver, args=(sock,), daemon=True).start()
    print("type 'bob: hello' to send, '/lookup bob' to check, '/quit' to exit")
    for line in sys.stdin:
        line = line.strip()
        if line == "/quit":
            break
        if line.startswith("/lookup "):
            send_frame(sock, LOOKUP, line.split(" ", 1)[1].encode())
        elif ":" in line:
            to, text = line.split(":", 1)
            send_frame(sock, MESSAGE, pack_name(to.strip(), text.strip().encode()))
    sock.close()