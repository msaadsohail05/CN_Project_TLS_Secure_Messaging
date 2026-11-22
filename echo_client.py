import socket, ssl

ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="certs/ca.crt")
ctx.minimum_version = ssl.TLSVersion.TLSv1_3

with socket.create_connection(("127.0.0.1", 8443)) as sock:
    with ctx.wrap_socket(sock, server_hostname="relay.local") as tls:
        print(tls.version(), tls.cipher())
        tls.sendall(b"hello")
        print(tls.recv(1024))
