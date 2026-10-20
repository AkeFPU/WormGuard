import io
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wormguard import integrity
from wormguard.crypto_utils import (generate_keypair, key_id, load_private_key,
                                    load_public_key, save_private_key,
                                    save_public_key, sha256_bytes)
from wormguard.node import Node
from wormguard.package import create_package, write_package
from wormguard.simulation import SimConfig, run_simulation
from wormguard.verifier import (BAD_PACKAGE, BAD_SIGNATURE, HASH_MISMATCH, OK,
                                REVOKED_KEY, ROLLBACK, UNTRUSTED_KEY,
                                TrustStore, verify_package)


def replace_member(pkg: bytes, member: str, new: bytes) -> bytes:
    src = zipfile.ZipFile(io.BytesIO(pkg))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        for n in src.namelist():
            z.writestr(n, new if n == member else src.read(n))
    return out.getvalue()


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.pub_key = generate_keypair("ecdsa")
        self.evil = generate_keypair("ecdsa")
        self.trust = TrustStore()
        self.kid = self.trust.add(self.pub_key.public_key())

    def test_sha256_known_vector(self):
        self.assertEqual(sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_valid_package_accepted_for_both_algorithms(self):
        for algo in ("rsa", "ecdsa"):
            k = generate_keypair(algo)
            t = TrustStore(); t.add(k.public_key())
            pkg = create_package(b"patch", k, "app.bin", 1)
            self.assertEqual(verify_package(pkg, t).code, OK, algo)

    def test_tampered_payload_rejected(self):
        pkg = create_package(b"patch", self.pub_key, "a.bin", 1)
        bad = replace_member(pkg, "payload.bin", b"worm")
        self.assertEqual(verify_package(bad, self.trust).code, HASH_MISMATCH)

    def test_tampered_manifest_rejected(self):
        # attacker rewrites manifest so the hash matches the worm payload
        import json
        pkg = create_package(b"patch", self.pub_key, "a.bin", 1)
        m = json.loads(zipfile.ZipFile(io.BytesIO(pkg)).read("manifest.json"))
        m["sha256"] = sha256_bytes(b"worm"); m["size"] = 4
        bad = replace_member(replace_member(pkg, "payload.bin", b"worm"),
                             "manifest.json", json.dumps(m, sort_keys=True, separators=(",", ":")).encode())
        self.assertEqual(verify_package(bad, self.trust).code, BAD_SIGNATURE)

    def test_unknown_signer_rejected(self):
        pkg = create_package(b"worm", self.evil, "a.bin", 9)
        self.assertEqual(verify_package(pkg, self.trust).code, UNTRUSTED_KEY)

    def test_forged_key_id_rejected(self):
        pkg = create_package(b"worm", self.evil, "a.bin", 9, claimed_key_id=self.kid)
        self.assertEqual(verify_package(pkg, self.trust).code, BAD_SIGNATURE)

    def test_revoked_key_rejected(self):
        pkg = create_package(b"patch", self.pub_key, "a.bin", 1)
        self.trust.revoke(self.kid)
        self.assertEqual(verify_package(pkg, self.trust).code, REVOKED_KEY)

    def test_rollback_rejected(self):
        pkg = create_package(b"patch", self.pub_key, "a.bin", 1)
        self.assertEqual(verify_package(pkg, self.trust, {"a.bin": 1}).code, ROLLBACK)
        self.assertEqual(verify_package(pkg, self.trust, {"a.bin": 0}).code, OK)

    def test_garbage_rejected(self):
        self.assertEqual(verify_package(b"not a zip", self.trust).code, BAD_PACKAGE)

    def test_bad_name_rejected_at_creation(self):
        with self.assertRaises(ValueError):
            create_package(b"x", self.pub_key, "../evil", 1)


class KeyAndNodeTests(unittest.TestCase):
    def test_key_roundtrip_with_password(self):
        with tempfile.TemporaryDirectory() as d:
            k = generate_keypair("rsa")
            save_private_key(k, Path(d) / "k.pem", "secret")
            save_public_key(k, Path(d) / "k.pub")
            k2 = load_private_key(Path(d) / "k.pem", "secret")
            self.assertEqual(key_id(k2), key_id(load_public_key(Path(d) / "k.pub")))
            with self.assertRaises(Exception):
                load_private_key(Path(d) / "k.pem", "wrong")

    def test_node_installs_and_logs(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            k = generate_keypair("ecdsa")
            save_public_key(k, d / "p.pub")
            (d / "u.txt").write_text("hello")
            node = Node(d / "n")
            node.trust_key(d / "p.pub")
            pkg = write_package(d / "u.txt", k, d / "u.wgpkg", 1)
            self.assertTrue(node.install(pkg).ok)
            self.assertEqual((node.install_dir / "u.txt").read_text(), "hello")
            self.assertEqual(node.installed_versions(), {"u.txt": 1})
            self.assertFalse(node.install(pkg).ok)            # replay blocked
            self.assertGreaterEqual(len(node.log_file.read_text().splitlines()), 3)


class IntegrityTests(unittest.TestCase):
    def test_detects_changes_and_baseline_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d); f = d / "data"; f.mkdir()
            (f / "a.txt").write_text("one"); (f / "b.txt").write_text("two")
            integrity.new_secret(d / "s.key")
            integrity.create_baseline(f, d / "s.key", d / "b.json")
            self.assertEqual(integrity.check_baseline(f, d / "s.key", d / "b.json"),
                {"baseline_tampered": False, "modified": [], "new": [], "deleted": []})
            (f / "a.txt").write_text("INFECTED"); (f / "c.txt").write_text("new"); (f / "b.txt").unlink()
            r = integrity.check_baseline(f, d / "s.key", d / "b.json")
            self.assertEqual((r["modified"], r["new"], r["deleted"]), (["a.txt"], ["c.txt"], ["b.txt"]))
            # attacker edits the baseline to hide the change
            import json
            b = json.loads((d / "b.json").read_text()); b["files"]["a.txt"] = "0" * 64
            (d / "b.json").write_text(json.dumps(b))
            self.assertTrue(integrity.check_baseline(f, d / "s.key", d / "b.json")["baseline_tampered"])


class SimulationTests(unittest.TestCase):
    def test_full_adoption_stops_unsigned_worm(self):
        r = run_simulation(SimConfig(adoption=1.0, seed=3))
        self.assertEqual(r["final"], 1)
        self.assertIn("UNTRUSTED_KEY", r["blocked"])

    def test_forged_id_blocked_as_bad_signature(self):
        r = run_simulation(SimConfig(adoption=1.0, scenario="forged_id", seed=3))
        self.assertEqual(r["final"], 1)
        self.assertIn("BAD_SIGNATURE", r["blocked"])

    def test_no_protection_spreads_widely(self):
        r = run_simulation(SimConfig(adoption=0.0, seed=3))
        self.assertGreater(r["final"], 80)

    def test_more_adoption_means_fewer_infections(self):
        f = [run_simulation(SimConfig(adoption=a, seed=5))["final"] for a in (0.0, 0.5, 1.0)]
        self.assertGreater(f[0], f[1]); self.assertGreater(f[1], f[2])

    def test_stolen_key_works_until_revoked(self):
        no_revoke = run_simulation(SimConfig(adoption=1.0, scenario="stolen_key", seed=3))
        early = run_simulation(SimConfig(adoption=1.0, scenario="stolen_key", revoke_step=2, seed=3))
        self.assertGreater(no_revoke["final"], 80)      # valid signature -> accepted
        self.assertLess(early["final"], no_revoke["final"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
