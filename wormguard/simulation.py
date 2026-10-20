"""Worm-spread simulation using REAL signature verification.

A network of N nodes is wired randomly. Node 0 ("patient zero") is infected.
Every step, each infected node tries to push a fake "update" (a harmless
simulated payload) to each neighbour:

  * unprotected node  -> accepts it with probability `infect_prob`
  * protected node    -> runs the real `verify_package()`; accepted only if
                         it passes every cryptographic check

Scenarios (what the attacker can do):
  unsigned    attacker signs with their own key          -> UNTRUSTED_KEY
  forged_id   attacker claims the publisher's key id     -> BAD_SIGNATURE
  stolen_key  attacker holds the publisher's private key -> valid until the
              key is revoked at `revoke_step` (the Stuxnet lesson)
"""
import random
from collections import Counter
from dataclasses import dataclass
from typing import Optional

from .crypto_utils import generate_keypair, key_id
from .package import create_package
from .verifier import TrustStore, verify_package

SIM_PAYLOAD = b"SIMULATED-WORM-PAYLOAD (harmless text, for the simulation only)"


@dataclass
class SimConfig:
    nodes: int = 100
    degree: int = 4
    infect_prob: float = 0.4
    steps: int = 25
    adoption: float = 0.0          # fraction of nodes running verification
    scenario: str = "unsigned"     # unsigned | forged_id | stolen_key
    revoke_step: Optional[int] = None
    seed: int = 1
    algo: str = "ecdsa"            # ecdsa is faster for large simulations


def build_graph(n: int, degree: int, rng: random.Random):
    """Connected random graph: a ring plus random extra edges."""
    adj = [set() for _ in range(n)]

    def link(a, b):
        if a != b:
            adj[a].add(b)
            adj[b].add(a)

    for i in range(n):
        link(i, (i + 1) % n)
    target_edges = n * degree // 2
    while sum(len(a) for a in adj) // 2 < target_edges:
        link(rng.randrange(n), rng.randrange(n))
    return adj


def _worm_package(cfg, publisher_key, attacker_key):
    if cfg.scenario == "unsigned":
        return create_package(SIM_PAYLOAD, attacker_key, "update.bin", 999)
    if cfg.scenario == "forged_id":
        return create_package(SIM_PAYLOAD, attacker_key, "update.bin", 999,
                              claimed_key_id=key_id(publisher_key.public_key()))
    if cfg.scenario == "stolen_key":
        return create_package(SIM_PAYLOAD, publisher_key, "update.bin", 999)
    raise ValueError("unknown scenario")


def run_simulation(cfg: SimConfig) -> dict:
    rng = random.Random(cfg.seed)
    adj = build_graph(cfg.nodes, cfg.degree, rng)

    publisher = generate_keypair(cfg.algo)
    attacker = generate_keypair(cfg.algo)
    trust = TrustStore()
    publisher_id = trust.add(publisher.public_key())
    worm = _worm_package(cfg, publisher, attacker)

    others = list(range(1, cfg.nodes))
    rng.shuffle(others)
    protected = set(others[: round(cfg.adoption * (cfg.nodes - 1))])

    infected = {0}
    history = [1]
    blocked = Counter()

    for step in range(1, cfg.steps + 1):
        if cfg.revoke_step is not None and step == cfg.revoke_step:
            trust.revoke(publisher_id)
        newly = set()
        for u in infected:
            for v in adj[u]:
                if v in infected or v in newly:
                    continue
                if v in protected:
                    res = verify_package(worm, trust)
                    if not res.ok:
                        blocked[res.code] += 1
                        continue
                if rng.random() < cfg.infect_prob:
                    newly.add(v)
        infected |= newly
        history.append(len(infected))
    return {"history": history, "final": len(infected),
            "percent": 100.0 * len(infected) / cfg.nodes,
            "blocked": dict(blocked), "protected": len(protected)}


def compare(cfg: SimConfig, adoptions=(0.0, 0.5, 1.0), trials: int = 5) -> dict:
    """Average infection curves over several random networks."""
    out = {}
    for a in adoptions:
        curves = []
        for t in range(trials):
            c = SimConfig(**{**cfg.__dict__, "adoption": a, "seed": cfg.seed + t})
            curves.append(run_simulation(c)["history"])
        out[a] = [sum(col) / len(col) for col in zip(*curves)]
    return out


def plot(results: dict, cfg: SimConfig, path: str) -> bool:
    """Save a PNG chart. Returns False if matplotlib is not installed."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return False
    fig, ax = plt.subplots(figsize=(7, 4.2))
    for a, curve in results.items():
        ax.plot(range(len(curve)), curve, linewidth=2.2,
                label=f"{int(a * 100)}% of nodes verify updates")
    ax.set_xlabel("Time step")
    ax.set_ylabel(f"Infected nodes (out of {cfg.nodes})")
    ax.set_title(f"Worm spread - scenario: {cfg.scenario}")
    ax.grid(alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return True


def ascii_table(results: dict, cfg: SimConfig, every: int = 5) -> str:
    steps = len(next(iter(results.values())))
    cols = [s for s in range(0, steps, every)] + ([steps - 1] if (steps - 1) % every else [])
    head = "adoption | " + " ".join(f"t={s:<3}" for s in cols)
    rows = [head, "-" * len(head)]
    for a, curve in results.items():
        rows.append(f"{int(a * 100):>6}%  | " + " ".join(f"{curve[s]:<5.1f}" for s in cols))
    return "\n".join(rows)
