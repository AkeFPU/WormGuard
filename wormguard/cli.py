"""Command-line interface. Run `python -m wormguard --help`."""
import argparse
import getpass
import sys
from pathlib import Path

from . import integrity
from .crypto_utils import (generate_keypair, key_id, load_private_key,
                           save_private_key, save_public_key)
from .node import Node
from .package import write_package
from .simulation import SimConfig, ascii_table, compare, plot, run_simulation


def _pw(flag, confirm=False):
    if not flag:
        return None
    p = getpass.getpass("Key password: ")
    if confirm and p != getpass.getpass("Repeat password: "):
        sys.exit("Passwords do not match")
    return p


def cmd_keygen(a):
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    key = generate_keypair(a.algo)
    save_private_key(key, out / f"{a.name}.key.pem", _pw(a.password, True))
    save_public_key(key, out / f"{a.name}.pub.pem")
    print(f"Private key: {out / (a.name + '.key.pem')}  (KEEP SECRET)")
    print(f"Public key : {out / (a.name + '.pub.pem')}  (share with nodes)")
    print(f"Key id     : {key_id(key)}")


def cmd_sign(a):
    key = load_private_key(a.key, _pw(a.password))
    out = a.out or (a.file + ".wgpkg")
    write_package(a.file, key, out, a.version, a.name)
    print(f"Signed package written: {out}")


def cmd_trust(a):
    print("Trusted key id:", Node(a.node_dir).trust_key(a.pub))


def cmd_revoke(a):
    Node(a.node_dir).revoke_key(a.key_id)
    print("Revoked", a.key_id)


def _report(res):
    print(("ACCEPTED" if res.ok else "REJECTED"), f"[{res.code}]", res.message)
    return 0 if res.ok else 1


def cmd_verify(a):
    return _report(Node(a.node_dir).check(a.package))


def cmd_install(a):
    return _report(Node(a.node_dir).install(a.package))


def cmd_demo(a):
    from .demo import run_demo
    run_demo(a.algo)


def cmd_simulate(a):
    cfg = SimConfig(nodes=a.nodes, degree=a.degree, infect_prob=a.prob,
                    steps=a.steps, scenario=a.scenario, revoke_step=a.revoke_step,
                    seed=a.seed, algo=a.algo)
    res = compare(cfg, tuple(a.adoption), a.trials)
    print(f"Scenario: {cfg.scenario}  nodes={cfg.nodes}  trials={a.trials}\n")
    print(ascii_table(res, cfg))
    print()
    for ad in a.adoption:
        c = SimConfig(**{**cfg.__dict__, "adoption": ad})
        r = run_simulation(c)
        print(f"adoption {int(ad*100):>3}%: final infected {r['final']:>3}/{cfg.nodes} "
              f"({r['percent']:.0f}%), blocked attempts {r['blocked']}")
    if a.plot:
        print("\nChart saved:" if plot(res, cfg, a.plot) else "\nmatplotlib not installed; chart skipped.", a.plot)


def cmd_int_init(a):
    if not Path(a.secret).exists():
        integrity.new_secret(a.secret)
        print("New secret key created:", a.secret)
    n = integrity.create_baseline(a.folder, a.secret, a.baseline)
    print(f"Baseline of {n} files saved to {a.baseline}")


def cmd_int_check(a):
    r = integrity.check_baseline(a.folder, a.secret, a.baseline)
    if r["baseline_tampered"]:
        print("!! BASELINE FILE HAS BEEN TAMPERED WITH (HMAC mismatch)")
    for k in ("modified", "new", "deleted"):
        for f in r[k]:
            print(f"{k.upper():9} {f}")
    clean = not r["baseline_tampered"] and not any(r[k] for k in ("modified", "new", "deleted"))
    print("All files match the baseline." if clean else "Integrity violations found.")
    return 0 if clean else 1


def cmd_gui(a):
    from .gui import main
    main()


def build_parser():
    p = argparse.ArgumentParser(prog="wormguard",
        description="Prevent worm propagation with digital signatures and SHA-256 verification")
    sp = p.add_subparsers(dest="cmd", required=True)

    s = sp.add_parser("keygen", help="generate a publisher key pair")
    s.add_argument("--name", default="publisher")
    s.add_argument("--algo", choices=["rsa", "ecdsa"], default="rsa")
    s.add_argument("--out", default="keys")
    s.add_argument("--password", action="store_true", help="encrypt the private key")
    s.set_defaults(fn=cmd_keygen)

    s = sp.add_parser("sign", help="hash + sign a file into a .wgpkg package")
    s.add_argument("file")
    s.add_argument("--key", required=True)
    s.add_argument("--version", type=int, required=True)
    s.add_argument("--name"); s.add_argument("--out")
    s.add_argument("--password", action="store_true")
    s.set_defaults(fn=cmd_sign)

    s = sp.add_parser("trust", help="add a publisher public key to a node")
    s.add_argument("--node-dir", required=True); s.add_argument("--pub", required=True)
    s.set_defaults(fn=cmd_trust)

    s = sp.add_parser("revoke", help="revoke a key id on a node")
    s.add_argument("--node-dir", required=True); s.add_argument("--key-id", required=True)
    s.set_defaults(fn=cmd_revoke)

    s = sp.add_parser("verify", help="check a package without installing")
    s.add_argument("package"); s.add_argument("--node-dir", required=True)
    s.set_defaults(fn=cmd_verify)

    s = sp.add_parser("install", help="verify and install a package")
    s.add_argument("package"); s.add_argument("--node-dir", required=True)
    s.set_defaults(fn=cmd_install)

    s = sp.add_parser("demo", help="run the scripted attack/defence demo")
    s.add_argument("--algo", choices=["rsa", "ecdsa"], default="rsa")
    s.set_defaults(fn=cmd_demo)

    s = sp.add_parser("simulate", help="worm spread with/without verification")
    s.add_argument("--nodes", type=int, default=100)
    s.add_argument("--degree", type=int, default=4)
    s.add_argument("--prob", type=float, default=0.4)
    s.add_argument("--steps", type=int, default=25)
    s.add_argument("--trials", type=int, default=5)
    s.add_argument("--seed", type=int, default=1)
    s.add_argument("--algo", choices=["rsa", "ecdsa"], default="ecdsa")
    s.add_argument("--scenario", choices=["unsigned", "forged_id", "stolen_key"], default="unsigned")
    s.add_argument("--revoke-step", type=int, default=None)
    s.add_argument("--adoption", type=float, nargs="+", default=[0.0, 0.5, 1.0])
    s.add_argument("--plot", help="save a PNG chart, e.g. spread.png")
    s.set_defaults(fn=cmd_simulate)

    s = sp.add_parser("integrity-init", help="create an HMAC-protected file baseline")
    s.add_argument("folder"); s.add_argument("--secret", default="integrity.key")
    s.add_argument("--baseline", default="baseline.json")
    s.set_defaults(fn=cmd_int_init)

    s = sp.add_parser("integrity-check", help="compare a folder with its baseline")
    s.add_argument("folder"); s.add_argument("--secret", default="integrity.key")
    s.add_argument("--baseline", default="baseline.json")
    s.set_defaults(fn=cmd_int_check)

    s = sp.add_parser("gui", help="open the graphical interface")
    s.set_defaults(fn=cmd_gui)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        sys.exit(args.fn(args) or 0)
    except (FileNotFoundError, ValueError) as exc:
        sys.exit(f"Error: {exc}")
