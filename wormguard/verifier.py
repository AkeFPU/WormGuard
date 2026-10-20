"""The security decision: should a node accept this package?

Order of checks (cheap and decisive first, and always authenticity before
integrity):

  1. well-formed package?                          -> BAD_PACKAGE
  2. is the signing key revoked?                   -> REVOKED_KEY
  3. is the signing key in the trust store?        -> UNTRUSTED_KEY
  4. is the signature over the manifest valid?     -> BAD_SIGNATURE
  5. does SHA-256(payload) match the manifest?     -> HASH_MISMATCH
  6. is the version newer than what is installed?  -> ROLLBACK (replay guard)
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Set

from .crypto_utils import (constant_time_equal, key_id, load_public_key,
                           sha256_bytes, verify)
from .package import PackageError, parse_package

OK = "OK"
BAD_PACKAGE = "BAD_PACKAGE"
REVOKED_KEY = "REVOKED_KEY"
UNTRUSTED_KEY = "UNTRUSTED_KEY"
BAD_SIGNATURE = "BAD_SIGNATURE"
HASH_MISMATCH = "HASH_MISMATCH"
ROLLBACK = "ROLLBACK"


@dataclass
class VerifyResult:
    ok: bool
    code: str
    message: str
    manifest: Optional[dict] = None


@dataclass
class TrustStore:
    """Public keys we trust, plus a revocation list (like a tiny PKI)."""
    keys: Dict[str, object] = field(default_factory=dict)   # key_id -> public key
    revoked: Set[str] = field(default_factory=set)

    def add(self, public_key) -> str:
        kid = key_id(public_key)
        self.keys[kid] = public_key
        return kid

    def revoke(self, kid: str) -> None:
        self.revoked.add(kid)

    @classmethod
    def from_directory(cls, trusted_dir, revoked_file=None):
        ts = cls()
        for pem in sorted(Path(trusted_dir).glob("*.pem")):
            ts.add(load_public_key(pem))
        if revoked_file and Path(revoked_file).exists():
            ts.revoked = {l.strip() for l in Path(revoked_file).read_text().splitlines()
                          if l.strip()}
        return ts


def verify_package(data: bytes, trust: TrustStore,
                   installed_versions: Optional[Dict[str, int]] = None) -> VerifyResult:
    installed_versions = installed_versions or {}

    try:
        pkg = parse_package(data)
    except PackageError as exc:
        return VerifyResult(False, BAD_PACKAGE, str(exc))
    m = pkg.manifest

    kid = m["key_id"]
    if kid in trust.revoked:
        return VerifyResult(False, REVOKED_KEY,
                            "signing key has been revoked", m)
    pub = trust.keys.get(kid)
    if pub is None:
        return VerifyResult(False, UNTRUSTED_KEY,
                            "signing key is not in the trust store", m)

    if not verify(pub, pkg.signature, pkg.manifest_bytes):
        return VerifyResult(False, BAD_SIGNATURE,
                            "signature does not match the manifest", m)

    if (len(pkg.payload) != m["size"]
            or not constant_time_equal(sha256_bytes(pkg.payload), m["sha256"])):
        return VerifyResult(False, HASH_MISMATCH,
                            "payload was modified after signing", m)

    current = installed_versions.get(m["name"], 0)
    if m["version"] <= current:
        return VerifyResult(False, ROLLBACK,
                            f"version {m['version']} is not newer than installed {current}", m)

    return VerifyResult(True, OK, "signature and hash verified", m)
