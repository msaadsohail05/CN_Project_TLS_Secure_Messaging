import argparse, socket, ssl, time
from protocol import *

def make_ctx(ca, version, keylog):
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
    v = ssl.TLSVersion.TLSv1_3 if version == "1.3" else ssl.TLSVersion.TLSv1_2
    ctx.minimum_version = v
    ctx.maximum_version = v
    if keylog:
        ctx.keylog_filename = keylog
    return ctx

def connect(ctx, host, port, sni, session, name):
    raw = socket.create_connection((host, port))
    t0 = time.perf_counter()
    tls = ctx.wrap_socket(raw, server_hostname=sni, session=session)  # does the handshake
    ms = (time.perf_counter() - t0) * 1000
    # In TLS 1.3 the server sends its session ticket right after the handshake.
    # Reading one frame makes Python process it, so tls.session is resumable.
    send_frame(tls, REGISTER, name.encode())
    recv_frame(tls)
    return tls, ms

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--ca", default="certs/ca.crt")
    p.add_argument("--sni", default="relay.local")
    p.add_argument("--tls-version", choices=["1.3", "1.2"], default="1.3")
    p.add_argument("--keylog")
    args = p.parse_args()

    ctx = make_ctx(args.ca, args.tls_version, args.keylog)

    t1, ms1 = connect(ctx, args.host, args.port, args.sni, None, "probe-a")
    sess = t1.session
    print(f"connection 1 (full):    {t1.version()} {t1.cipher()[0]} "
          f"resumed={t1.session_reused} handshake={ms1:.2f} ms")
    print(f"  session ticket received: {sess.has_ticket}, lifetime hint {sess.ticket_lifetime_hint}s")
    t1.close()

    t2, ms2 = connect(ctx, args.host, args.port, args.sni, sess, "probe-b")
    print(f"connection 2 (resume):  {t2.version()} {t2.cipher()[0]} "
          f"resumed={t2.session_reused} handshake={ms2:.2f} ms")
    t2.close()