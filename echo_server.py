import socket, ssl

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain("certs/server.crt", "certs/server.key")

with socket.create_server(("127.0.0.1", 8443)) as srv:
    print("listening on 8443")
    while True:
        conn, addr = srv.accept()
        try:
            with ctx.wrap_socket(conn, server_side=True) as tls:
                data = tls.recv(1024)
                tls.sendall(data)
        except ssl.SSLError as e:
            print("handshake failed:", e)