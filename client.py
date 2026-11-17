import argparse, socket, ssl, sys, threading
from protocol import *
from keystore import load_or_create_keypair, fingerprint

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
                who, rest = unpack_name(payload)
                if rest[:1] == b"\x01":
                    key = rest[1:]
                    print(f"\n[lookup] {who}: key {key.hex()}")
                    print(f"         fingerprint {fingerprint(key)}")
                else:
                    print(f"\n[lookup] {who}: no key published")
            elif ftype == PUBLISH:
                print("\n[key published]")
            elif ftype == REGISTER:
                print("\n[registered]")
    except (ConnectionError, OSError):
        print("\nconnection closed")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("user")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--tls", action="store_true")
    p.add_argument("--ca", default="certs/ca.crt")
    p.add_argument("--sni", default="relay.local", help="name the certificate must match")
    p.add_argument("--keylog")
    args = p.parse_args()

    if not NAME_RE.match(args.user):
        sys.exit("username must be 1-32 characters: letters, digits, _ or -")

    sk = load_or_create_keypair(args.user)
    pub = sk.public_key.encode()
    print("my public key:", pub.hex())
    print("fingerprint:  ", fingerprint(pub))

    sock = socket.create_connection((args.host, args.port))
    if args.tls:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=args.ca)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        if args.keylog:
            ctx.keylog_filename = args.keylog
        try:
            sock = ctx.wrap_socket(sock, server_hostname=args.sni)
        except ssl.SSLError as e:
            print("TLS handshake failed:", e)
            sys.exit(1)
        print("connected:", sock.version(), sock.cipher()[0])

    send_frame(sock, REGISTER, args.user.encode())
    send_frame(sock, PUBLISH, pub)
    threading.Thread(target=receiver, args=(sock,), daemon=True).start()
    print("type 'bob: hello' to send, '/lookup bob' to fetch a key, '/quit' to exit")
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