"""Create the project's private CA + relay certificate (and a rogue CA for the attack demos).

Same result as gen_certs.sh, but callable from Python so the web UI and the tests can
bootstrap themselves on a machine that only has the `openssl` command line tool.

    python3 certs_tool.py            # makes certs/ (CA + relay cert) and certs/rogue/
"""
import os
import shutil
import subprocess
import sys

SAN = "DNS:relay.local, IP:10.0.2.10, IP:127.0.0.1"


def _run(*args, cwd):
    subprocess.run(["openssl", *args], cwd=cwd, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _make_ca(d, cn):
    _run("genrsa", "-out", "ca.key", "2048", cwd=d)
    # basicConstraints + keyUsage: modern OpenSSL / Python 3.13+ verify in strict mode and
    # reject a CA certificate that lacks them.
    _run("req", "-x509", "-new", "-nodes", "-key", "ca.key", "-sha256", "-days", "365",
         "-subj", f"/CN={cn}", "-out", "ca.crt",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign",
         "-addext", "subjectKeyIdentifier=hash", cwd=d)


def _make_server(d, cn="relay.local"):
    _run("genrsa", "-out", "server.key", "2048", cwd=d)
    _run("req", "-new", "-key", "server.key", "-subj", f"/CN={cn}", "-out", "server.csr", cwd=d)
    with open(os.path.join(d, "server.ext"), "w") as f:
        f.write(f"subjectAltName = {SAN}\nbasicConstraints = CA:FALSE\n"
                "keyUsage = digitalSignature, keyEncipherment\nextendedKeyUsage = serverAuth\n")
    _run("x509", "-req", "-in", "server.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
         "-CAcreateserial", "-out", "server.crt", "-days", "365", "-sha256",
         "-extfile", "server.ext", cwd=d)


def ensure(certs_dir="certs", rogue=True):
    """Idempotent. Returns the certs directory."""
    if shutil.which("openssl") is None:
        raise RuntimeError("openssl command not found; install it or run gen_certs.sh elsewhere")
    ok = all(os.path.exists(os.path.join(certs_dir, n)) for n in ("ca.crt", "server.crt", "server.key"))
    if not ok:
        os.makedirs(certs_dir, exist_ok=True)
        _make_ca(certs_dir, "Project Private CA")
        _make_server(certs_dir)
    rdir = os.path.join(certs_dir, "rogue")
    if rogue and not os.path.exists(os.path.join(rdir, "server.crt")):
        os.makedirs(rdir, exist_ok=True)
        _make_ca(rdir, "Rogue CA")          # attacker's own CA: signs a look-alike relay cert
        _make_server(rdir)
    return certs_dir


if __name__ == "__main__":
    print("certs ready in", ensure(sys.argv[1] if len(sys.argv) > 1 else "certs"))
