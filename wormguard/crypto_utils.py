"""Thin, well-documented wrappers around the `cryptography` library.

Nothing here implements a cipher or signature scheme by hand. We only choose
safe parameters (RSA-2048 with PSS padding, ECDSA P-256, SHA-256) and expose a
small API used by the rest of the project.
"""
import hashlib
import hmac
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

CHUNK = 64 * 1024


# ---------------------------------------------------------------- hashing
def sha256_bytes(data: bytes) -> str:
    """Hex SHA-256 digest of a byte string."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path) -> str:
    """Hex SHA-256 digest of a file, read in chunks (works for big files)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(CHUNK)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def hmac_sha256(key: bytes, data: bytes) -> str:
    """Hex HMAC-SHA256 (keyed integrity + authenticity)."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def constant_time_equal(a: str, b: str) -> bool:
    """Compare two strings without leaking where they differ."""
    return hmac.compare_digest(a.encode(), b.encode())


# ------------------------------------------------------------------ keys
def generate_keypair(algo: str = "rsa"):
    """Create a private key. algo = 'rsa' (2048-bit) or 'ecdsa' (P-256)."""
    algo = algo.lower()
    if algo == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if algo in ("ecdsa", "ec"):
        return ec.generate_private_key(ec.SECP256R1())
    raise ValueError("algo must be 'rsa' or 'ecdsa'")


def algo_name(key) -> str:
    """Human-readable algorithm label for a private or public key."""
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return "RSA-2048-PSS-SHA256"
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return "ECDSA-P256-SHA256"
    raise TypeError("unsupported key type")


def save_private_key(key, path, password: str = None) -> None:
    enc = (serialization.BestAvailableEncryption(password.encode())
           if password else serialization.NoEncryption())
    pem = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8, enc)
    p = Path(path)
    p.write_bytes(pem)
    try:
        os.chmod(p, 0o600)          # private keys must not be world-readable
    except OSError:
        pass


def save_public_key(key, path) -> None:
    pub = key.public_key() if hasattr(key, "public_key") else key
    Path(path).write_bytes(pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))


def load_private_key(path, password: str = None):
    return serialization.load_pem_private_key(
        Path(path).read_bytes(), password.encode() if password else None)


def load_public_key(path):
    return serialization.load_pem_public_key(Path(path).read_bytes())


def key_id(public_key) -> str:
    """Key fingerprint = SHA-256 of the DER-encoded public key."""
    pub = public_key.public_key() if hasattr(public_key, "public_key") else public_key
    der = pub.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return sha256_bytes(der)


# ------------------------------------------------------ sign / verify
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                   salt_length=padding.PSS.DIGEST_LENGTH)


def sign(private_key, data: bytes) -> bytes:
    """Sign `data` (hashed with SHA-256 internally)."""
    if isinstance(private_key, rsa.RSAPrivateKey):
        return private_key.sign(data, _PSS, hashes.SHA256())
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    raise TypeError("unsupported private key type")


def verify(public_key, signature: bytes, data: bytes) -> bool:
    """True only if `signature` is a valid signature of `data`."""
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, data, _PSS, hashes.SHA256())
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        else:
            return False
        return True
    except (InvalidSignature, ValueError):
        return False
