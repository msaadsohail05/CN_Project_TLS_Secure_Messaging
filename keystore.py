import os, hashlib
from nacl.public import PrivateKey

KEY_DIR = "keys"

def load_or_create_keypair(user):
    """Return this user's PrivateKey, creating and saving it on first use."""
    os.makedirs(KEY_DIR, mode=0o700, exist_ok=True)
    path = os.path.join(KEY_DIR, f"{user}.key")
    if os.path.exists(path):
        with open(path, "rb") as f:
            return PrivateKey(f.read())
    sk = PrivateKey.generate()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(sk.encode())
    return sk

def fingerprint(pub_bytes):
    """Short readable fingerprint of a public key (for comparing out of band)."""
    h = hashlib.sha256(pub_bytes).hexdigest()[:32]
    return " ".join(h[i:i + 4] for i in range(0, 32, 4))