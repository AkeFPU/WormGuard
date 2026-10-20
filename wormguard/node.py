"""A node = one machine that only installs verified updates.

Directory layout of a node:
    <root>/trusted/<key_id>.pem   trusted publisher public keys
    <root>/revoked.txt            revoked key ids, one per line
    <root>/install/               installed payloads
    <root>/state.json             {name: installed version}
    <root>/audit.log              one JSON line per decision
"""
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from .crypto_utils import key_id, load_public_key
from .package import parse_package
from .verifier import TrustStore, VerifyResult, verify_package


class Node:
    def __init__(self, root, name="node"):
        self.name = name
        self.root = Path(root)
        self.trusted_dir = self.root / "trusted"
        self.install_dir = self.root / "install"
        self.state_file = self.root / "state.json"
        self.revoked_file = self.root / "revoked.txt"
        self.log_file = self.root / "audit.log"
        for d in (self.trusted_dir, self.install_dir):
            d.mkdir(parents=True, exist_ok=True)

    # ---- trust management
    def trust_key(self, pub_pem_path) -> str:
        pub = load_public_key(pub_pem_path)
        kid = key_id(pub)
        shutil.copyfile(pub_pem_path, self.trusted_dir / f"{kid}.pem")
        self._log("TRUST_KEY", key_id=kid)
        return kid

    def revoke_key(self, kid: str) -> None:
        with open(self.revoked_file, "a") as f:
            f.write(kid + "\n")
        self._log("REVOKE_KEY", key_id=kid)

    def trust_store(self) -> TrustStore:
        return TrustStore.from_directory(self.trusted_dir, self.revoked_file)

    # ---- state
    def installed_versions(self) -> dict:
        if self.state_file.exists():
            return json.loads(self.state_file.read_text())
        return {}

    # ---- decisions
    def check(self, package_path) -> VerifyResult:
        """Verify only; nothing is installed."""
        data = Path(package_path).read_bytes()
        res = verify_package(data, self.trust_store(), self.installed_versions())
        self._log("VERIFY", res)
        return res

    def install(self, package_path) -> VerifyResult:
        """Verify, and install only if every check passes."""
        data = Path(package_path).read_bytes()
        res = verify_package(data, self.trust_store(), self.installed_versions())
        if res.ok:
            pkg = parse_package(data)
            (self.install_dir / pkg.manifest["name"]).write_bytes(pkg.payload)
            state = self.installed_versions()
            state[pkg.manifest["name"]] = pkg.manifest["version"]
            self.state_file.write_text(json.dumps(state, indent=2))
        self._log("INSTALL" if res.ok else "REJECT", res)
        return res

    def _log(self, event, res: VerifyResult = None, **extra):
        entry = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 "node": self.name, "event": event}
        if res is not None:
            entry.update(code=res.code, message=res.message)
            if res.manifest:
                entry.update(package=res.manifest.get("name"),
                             version=res.manifest.get("version"))
        entry.update(extra)
        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
