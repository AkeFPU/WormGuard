"""File-integrity monitor (bonus module).

A baseline lists SHA-256 of every file in a folder. The baseline itself is
protected with HMAC-SHA256 under a secret key, so malware that rewrites files
cannot also forge a matching baseline without that key.
"""
import json
import secrets
from pathlib import Path

from .crypto_utils import constant_time_equal, hmac_sha256, sha256_file


def new_secret(path) -> None:
    p = Path(path)
    p.write_bytes(secrets.token_bytes(32))
    try:
        p.chmod(0o600)
    except OSError:
        pass


def _scan(folder: Path) -> dict:
    return {str(f.relative_to(folder)): sha256_file(f)
            for f in sorted(folder.rglob("*")) if f.is_file()}


def _mac(secret: bytes, files: dict) -> str:
    return hmac_sha256(secret, json.dumps(files, sort_keys=True).encode())


def create_baseline(folder, secret_path, baseline_path) -> int:
    folder = Path(folder)
    files = _scan(folder)
    secret = Path(secret_path).read_bytes()
    Path(baseline_path).write_text(json.dumps(
        {"files": files, "hmac": _mac(secret, files)}, indent=2))
    return len(files)


def check_baseline(folder, secret_path, baseline_path) -> dict:
    """Return {'baseline_tampered': bool, 'modified': [], 'new': [], 'deleted': []}."""
    secret = Path(secret_path).read_bytes()
    saved = json.loads(Path(baseline_path).read_text())
    tampered = not constant_time_equal(_mac(secret, saved["files"]), saved["hmac"])
    now, old = _scan(Path(folder)), saved["files"]
    return {
        "baseline_tampered": tampered,
        "modified": sorted(k for k in now if k in old and now[k] != old[k]),
        "new": sorted(k for k in now if k not in old),
        "deleted": sorted(k for k in old if k not in now),
    }
