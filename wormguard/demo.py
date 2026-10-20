"""Scripted end-to-end demo: `python -m wormguard demo`."""
import tempfile
from pathlib import Path

from .crypto_utils import (generate_keypair, key_id, save_public_key)
from .node import Node
from .package import create_package, write_package


def _show(title, res):
    tag = "ACCEPTED" if res.ok else "REJECTED"
    print(f"  [{tag}] {title}\n           -> {res.code}: {res.message}")


def run_demo(algo="rsa"):
    work = Path(tempfile.mkdtemp(prefix="wormguard_demo_"))
    print(f"Demo workspace: {work}\n")

    print("1. Publisher generates a key pair; node trusts the PUBLIC key only")
    publisher = generate_keypair(algo)
    attacker = generate_keypair(algo)
    save_public_key(publisher, work / "publisher.pub.pem")
    node = Node(work / "node1", "node1")
    kid = node.trust_key(work / "publisher.pub.pem")
    print(f"   publisher key id: {kid[:16]}...\n")

    good = work / "update.txt"
    good.write_text("security patch v1")
    pkg_dir = work / "pkgs"
    pkg_dir.mkdir()

    print("2. Legitimate update (signed by the trusted publisher)")
    p1 = write_package(good, publisher, pkg_dir / "v1.wgpkg", version=1)
    _show("update v1 from publisher", node.install(p1))

    print("\n3. Attack: worm disguised as an update, signed with the attacker's own key")
    worm = create_package(b"WORM CODE", attacker, "update.txt", 2)
    (pkg_dir / "worm.wgpkg").write_bytes(worm)
    _show("worm signed by unknown key", node.install(pkg_dir / "worm.wgpkg"))

    print("\n4. Attack: worm claims the publisher's identity but signs with the wrong key")
    forged = create_package(b"WORM CODE", attacker, "update.txt", 2,
                            claimed_key_id=kid)
    (pkg_dir / "forged.wgpkg").write_bytes(forged)
    _show("forged publisher identity", node.install(pkg_dir / "forged.wgpkg"))

    print("\n5. Attack: a worm modifies the payload inside a genuine signed package")
    p2 = write_package(good, publisher, pkg_dir / "v2.wgpkg", version=2)
    import zipfile, io
    src = zipfile.ZipFile(p2)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n in src.namelist():
            z.writestr(n, b"INFECTED PAYLOAD" if n == "payload.bin" else src.read(n))
    (pkg_dir / "tampered.wgpkg").write_bytes(buf.getvalue())
    _show("payload tampered after signing", node.install(pkg_dir / "tampered.wgpkg"))

    print("\n6. Attack: replay of an old (vulnerable) version")
    _show("re-sending v1 after v1 is installed", node.install(p1))

    print("\n7. Genuine newer update still works")
    _show("update v2 from publisher", node.install(p2))

    print("\n8. Key compromise: publisher key is revoked (like a stolen certificate)")
    node.revoke_key(kid)
    p3 = write_package(good, publisher, pkg_dir / "v3.wgpkg", version=3)
    _show("update v3 signed with revoked key", node.install(p3))

    print(f"\nAudit log written to: {node.log_file}")
    print("Installed versions:", node.installed_versions())
