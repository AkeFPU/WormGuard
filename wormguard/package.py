"""Signed update package (.wgpkg) = ZIP containing three members:

    manifest.json   canonical JSON: name, version, sha256, size, created,
                    key_id, algorithm
    signature.sig   signature over the *exact bytes* of manifest.json
    payload.bin     the update file itself

Signing the manifest (which contains the payload's SHA-256) binds the
signature to the payload: change one bit of either and verification fails.
"""
import io
import json
import re
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .crypto_utils import algo_name, key_id, sha256_bytes, sign

MAX_PAYLOAD = 50 * 1024 * 1024        # refuse absurd sizes (zip-bomb guard)
MAX_MANIFEST = 64 * 1024
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")   # no slashes -> no path tricks


class PackageError(Exception):
    """Raised when a package is malformed."""


@dataclass
class Package:
    manifest_bytes: bytes
    manifest: dict
    signature: bytes
    payload: bytes


def create_package(payload: bytes, private_key, name: str, version: int,
                   claimed_key_id: str = None) -> bytes:
    """Build a signed package in memory.

    `claimed_key_id` exists only so the demo / simulation can model an attacker
    who *claims* to be the real publisher but signs with the wrong key.
    """
    if not NAME_RE.match(name):
        raise ValueError("name may only contain letters, digits, . _ - ")
    manifest = {
        "name": name,
        "version": int(version),
        "sha256": sha256_bytes(payload),
        "size": len(payload),
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "key_id": claimed_key_id or key_id(private_key.public_key()),
        "algorithm": algo_name(private_key),
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True,
                                separators=(",", ":")).encode()
    signature = sign(private_key, manifest_bytes)
    return _zip(manifest_bytes, signature, payload)


def write_package(payload_path, private_key, out_path, version, name=None) -> Path:
    payload_path = Path(payload_path)
    data = create_package(payload_path.read_bytes(), private_key,
                          name or payload_path.name, version)
    Path(out_path).write_bytes(data)
    return Path(out_path)


def _zip(manifest_bytes, signature, payload) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", manifest_bytes)
        zf.writestr("signature.sig", signature)
        zf.writestr("payload.bin", payload)
    return buf.getvalue()


def parse_package(data: bytes) -> Package:
    """Parse and structurally validate a package. Does NOT check crypto."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise PackageError("not a valid package archive") from exc
    with zf:
        names = set(zf.namelist())
        if names != {"manifest.json", "signature.sig", "payload.bin"}:
            raise PackageError("unexpected archive members")
        if zf.getinfo("payload.bin").file_size > MAX_PAYLOAD:
            raise PackageError("payload too large")
        if zf.getinfo("manifest.json").file_size > MAX_MANIFEST:
            raise PackageError("manifest too large")
        manifest_bytes = zf.read("manifest.json")
        signature = zf.read("signature.sig")
        payload = zf.read("payload.bin")
    try:
        manifest = json.loads(manifest_bytes)
    except ValueError as exc:
        raise PackageError("manifest is not valid JSON") from exc
    ok = (isinstance(manifest, dict)
          and isinstance(manifest.get("name"), str) and NAME_RE.match(manifest["name"])
          and isinstance(manifest.get("version"), int)
          and isinstance(manifest.get("sha256"), str)
          and isinstance(manifest.get("size"), int)
          and isinstance(manifest.get("key_id"), str))
    if not ok:
        raise PackageError("manifest fields missing or invalid")
    return Package(manifest_bytes, manifest, signature, payload)
