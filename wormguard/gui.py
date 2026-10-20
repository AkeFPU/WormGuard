"""Tkinter GUI: Publisher / Node / Simulation tabs. Run: python -m wormguard gui"""
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .crypto_utils import (generate_keypair, key_id, load_private_key,
                           save_private_key, save_public_key)
from .node import Node
from .package import write_package
from .simulation import SimConfig, compare

GREEN, RED = "#0a7d4f", "#c62828"
COLORS = ["#c62828", "#f2a518", "#0a7d4f", "#2e6f95"]


class App(ttk.Frame):
    def __init__(self, root):
        super().__init__(root, padding=8)
        self.pack(fill="both", expand=True)
        root.title("WormGuard - Signed Updates vs Worms")
        root.geometry("820x720")

        nb = ttk.Notebook(self)
        nb.pack(fill="x")
        self._publisher_tab(nb)
        self._node_tab(nb)
        self._sim_tab(nb)

        ttk.Label(self, text="Activity log").pack(anchor="w", pady=(8, 0))
        self.log = tk.Text(self, height=11, state="disabled", wrap="word")
        self.log.pack(fill="both", expand=True)
        self.log.tag_config("ok", foreground=GREEN)
        self.log.tag_config("bad", foreground=RED)
        self.log.tag_config("info", foreground="#333333")

    # ------------------------------------------------------------ helpers
    def say(self, text, tag="info"):
        self.log.config(state="normal")
        self.log.insert("end", text + "\n", tag)
        self.log.see("end")
        self.log.config(state="disabled")

    def _row(self, parent, label, var, browse=None, row=0):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=3)
        ttk.Entry(parent, textvariable=var, width=52).grid(row=row, column=1, padx=6)
        if browse:
            ttk.Button(parent, text="Browse", command=browse).grid(row=row, column=2)

    def _pick_file(self, var, types=(("All files", "*.*"),)):
        p = filedialog.askopenfilename(filetypes=types)
        if p:
            var.set(p)

    def _pick_dir(self, var):
        p = filedialog.askdirectory()
        if p:
            var.set(p)

    # --------------------------------------------------------- publisher tab
    def _publisher_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text="1. Publisher")
        self.pk_algo = tk.StringVar(value="rsa")
        self.pk_dir = tk.StringVar(value=str(Path.cwd() / "keys"))
        self.sign_file = tk.StringVar()
        self.sign_key = tk.StringVar()
        self.sign_ver = tk.StringVar(value="1")

        ttk.Label(f, text="Create keys", font=("", 11, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Label(f, text="Algorithm").grid(row=1, column=0, sticky="w")
        ttk.Combobox(f, textvariable=self.pk_algo, values=["rsa", "ecdsa"],
                     state="readonly", width=10).grid(row=1, column=1, sticky="w", padx=6)
        self._row(f, "Output folder", self.pk_dir, lambda: self._pick_dir(self.pk_dir), 2)
        ttk.Button(f, text="Generate key pair", command=self.do_keygen).grid(row=3, column=1, sticky="w", padx=6, pady=4)

        ttk.Separator(f).grid(row=4, column=0, columnspan=3, sticky="ew", pady=8)
        ttk.Label(f, text="Sign an update", font=("", 11, "bold")).grid(row=5, column=0, sticky="w")
        self._row(f, "Update file", self.sign_file, lambda: self._pick_file(self.sign_file), 6)
        self._row(f, "Private key (.pem)", self.sign_key, lambda: self._pick_file(self.sign_key), 7)
        self._row(f, "Version (integer)", self.sign_ver, None, 8)
        ttk.Button(f, text="Hash + sign -> package", command=self.do_sign).grid(row=9, column=1, sticky="w", padx=6, pady=4)

    def do_keygen(self):
        try:
            out = Path(self.pk_dir.get()); out.mkdir(parents=True, exist_ok=True)
            key = generate_keypair(self.pk_algo.get())
            save_private_key(key, out / "publisher.key.pem")
            save_public_key(key, out / "publisher.pub.pem")
            self.sign_key.set(str(out / "publisher.key.pem"))
            self.say(f"Keys created in {out}  (key id {key_id(key)[:16]}...)")
            self.say("Keep publisher.key.pem secret; give publisher.pub.pem to nodes.")
        except Exception as exc:
            messagebox.showerror("Key generation failed", str(exc))

    def do_sign(self):
        try:
            key = load_private_key(self.sign_key.get())
            out = self.sign_file.get() + ".wgpkg"
            write_package(self.sign_file.get(), key, out, int(self.sign_ver.get()))
            self.say(f"Signed package created: {out}", "ok")
        except Exception as exc:
            messagebox.showerror("Signing failed", str(exc))

    # -------------------------------------------------------------- node tab
    def _node_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text="2. Node")
        self.node_dir = tk.StringVar(value=str(Path.cwd() / "node1"))
        self.node_pub = tk.StringVar()
        self.node_pkg = tk.StringVar()
        self.node_revoke = tk.StringVar()
        self._row(f, "Node folder", self.node_dir, lambda: self._pick_dir(self.node_dir), 0)
        self._row(f, "Publisher public key", self.node_pub, lambda: self._pick_file(self.node_pub), 1)
        ttk.Button(f, text="Trust this key", command=self.do_trust).grid(row=2, column=1, sticky="w", padx=6, pady=4)
        ttk.Separator(f).grid(row=3, column=0, columnspan=3, sticky="ew", pady=8)
        self._row(f, "Package (.wgpkg)", self.node_pkg, lambda: self._pick_file(self.node_pkg), 4)
        bar = ttk.Frame(f); bar.grid(row=5, column=1, sticky="w", padx=6, pady=4)
        ttk.Button(bar, text="Verify only", command=lambda: self.do_node(False)).pack(side="left")
        ttk.Button(bar, text="Verify + install", command=lambda: self.do_node(True)).pack(side="left", padx=6)
        ttk.Separator(f).grid(row=6, column=0, columnspan=3, sticky="ew", pady=8)
        self._row(f, "Key id to revoke", self.node_revoke, None, 7)
        ttk.Button(f, text="Revoke key", command=self.do_revoke).grid(row=8, column=1, sticky="w", padx=6, pady=4)

    def do_trust(self):
        try:
            kid = Node(self.node_dir.get()).trust_key(self.node_pub.get())
            self.say(f"Node now trusts key {kid[:16]}...", "ok")
        except Exception as exc:
            messagebox.showerror("Trust failed", str(exc))

    def do_node(self, install):
        try:
            node = Node(self.node_dir.get())
            res = node.install(self.node_pkg.get()) if install else node.check(self.node_pkg.get())
            verb = ("INSTALLED" if install else "VALID") if res.ok else "REJECTED"
            self.say(f"{verb}  [{res.code}] {res.message}", "ok" if res.ok else "bad")
        except Exception as exc:
            messagebox.showerror("Node error", str(exc))

    def do_revoke(self):
        try:
            Node(self.node_dir.get()).revoke_key(self.node_revoke.get().strip())
            self.say("Key revoked on this node.", "bad")
        except Exception as exc:
            messagebox.showerror("Revoke failed", str(exc))

    # ------------------------------------------------------- simulation tab
    def _sim_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text="3. Simulation")
        self.s_nodes = tk.StringVar(value="100")
        self.s_prob = tk.StringVar(value="0.4")
        self.s_trials = tk.StringVar(value="3")
        self.s_scn = tk.StringVar(value="unsigned")
        self.s_rev = tk.StringVar(value="")
        grid = ttk.Frame(f); grid.pack(fill="x")
        for i, (lab, var) in enumerate([("Nodes", self.s_nodes), ("Infect prob.", self.s_prob),
                                        ("Trials", self.s_trials), ("Revoke at step", self.s_rev)]):
            ttk.Label(grid, text=lab).grid(row=0, column=2 * i, padx=(0, 3))
            ttk.Entry(grid, textvariable=var, width=7).grid(row=0, column=2 * i + 1, padx=(0, 10))
        ttk.Label(grid, text="Scenario").grid(row=1, column=0, pady=6)
        ttk.Combobox(grid, textvariable=self.s_scn, values=["unsigned", "forged_id", "stolen_key"],
                     state="readonly", width=12).grid(row=1, column=1, columnspan=2)
        ttk.Button(grid, text="Run simulation", command=self.do_sim).grid(row=1, column=3, columnspan=2)
        self.canvas = tk.Canvas(f, width=760, height=250, bg="white", highlightthickness=1,
                                highlightbackground="#bbbbbb")
        self.canvas.pack(pady=6)

    def do_sim(self):
        try:
            rev = self.s_rev.get().strip()
            cfg = SimConfig(nodes=int(self.s_nodes.get()), infect_prob=float(self.s_prob.get()),
                            scenario=self.s_scn.get(), revoke_step=int(rev) if rev else None)
            trials = int(self.s_trials.get())
        except ValueError:
            messagebox.showerror("Invalid input", "Check the simulation numbers.")
            return
        self.canvas.config(cursor="watch"); self.update_idletasks()
        res = compare(cfg, (0.0, 0.5, 1.0), trials)
        self.canvas.config(cursor="")
        self.draw(res, cfg)
        for a, c in res.items():
            self.say(f"{int(a*100):>3}% verifying nodes -> avg final infected {c[-1]:.1f}/{cfg.nodes}",
                     "bad" if c[-1] > cfg.nodes * 0.5 else "ok")

    def draw(self, res, cfg):
        c = self.canvas; c.delete("all")
        L, R, T, B = 50, 740, 20, 215
        c.create_line(L, B, R, B); c.create_line(L, T, L, B)
        steps = len(next(iter(res.values()))) - 1
        for frac in (0, .5, 1):
            y = B - frac * (B - T)
            c.create_text(L - 6, y, text=str(int(frac * cfg.nodes)), anchor="e", font=("", 9))
            c.create_line(L, y, R, y, fill="#e6e6e6")
        for s in range(0, steps + 1, 5):
            c.create_text(L + s / steps * (R - L), B + 10, text=str(s), font=("", 9))
        for i, (a, curve) in enumerate(res.items()):
            pts = []
            for s, v in enumerate(curve):
                pts += [L + s / steps * (R - L), B - v / cfg.nodes * (B - T)]
            col = COLORS[i % len(COLORS)]
            c.create_line(*pts, fill=col, width=3)
            c.create_text(R - 5, T + 4 + 16 * i, anchor="e", fill=col, font=("", 9, "bold"),
                          text=f"{int(a*100)}% of nodes verify updates")


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
