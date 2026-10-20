# WormGuard
**Preventing Worm Propagation Using Digital Signatures and SHA-256 Integrity Verification**
Cryptography and Network Security project (Group 5, topic: Worms)

Worms often spread by pretending to be a software update. WormGuard shows how
digital signatures and hashing stop that: a node installs an update **only if** it
was signed by a trusted publisher **and** the file still matches its signed SHA-256 hash.

> The worm in the simulation is a harmless text string. No real malware is included.

## Features
| Feature | Where |
|---|---|
| RSA-2048 (PSS) and ECDSA P-256 signing, SHA-256 hashing, optional password-protected private keys | `crypto_utils.py` |
| Signed update package (manifest + signature + payload) | `package.py` |
| 6 security checks: format, revocation, trust, signature, hash, rollback | `verifier.py` |
| Node with trust store, key revocation, install folder, JSON audit log | `node.py` |
| Worm-spread simulation using the **real** verifier (3 attack scenarios) | `simulation.py` |
| HMAC-protected file-integrity monitor (bonus) | `integrity.py` |
| CLI, Tkinter GUI, scripted demo, 18 unit tests | `cli.py`, `gui.py`, `demo.py`, `tests/` |

# How to Run WormGuard

Works on **Windows, Linux and macOS**. Pick your system in each step.

## 1. Install the requirements

You need **Python 3.9+** (and optionally **Git**).

### Windows
1. Download Python from https://www.python.org/downloads/
2. In the installer, **tick "Add python.exe to PATH"**, then click Install.
3. (Optional) Install Git from https://git-scm.com/download/win
4. Open **PowerShell** or **Command Prompt** and check:
```
   python --version
```
   If that fails, try `py --version` and use `py` in place of `python` everywhere below.

### Linux
**Ubuntu / Debian / Mint:**
```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip python3-tk git
```
**Fedora:**
```bash
sudo dnf install python3 python3-pip python3-tkinter git
```
**Arch:**
```bash
sudo pacman -S python python-pip tk git
```
Check: `python3 --version`

### macOS
1. Install Python from https://www.python.org/downloads/ (this includes the GUI toolkit), **or** with Homebrew:
```bash
   brew install python python-tk git
```
2. Check: `python3 --version`

> `python3-tk` / `python-tk` is only needed for the GUI. Everything else works without it.

## 2. Download the project

**With Git (all systems):**
```
git clone https://github.com/YOUR-USERNAME/WormGuard.git
cd WormGuard
```
**Without Git:** on the GitHub page click **Code → Download ZIP**, then extract it.
- Windows: right-click the zip → **Extract All**, open the folder, click the address bar, type `cmd` and press Enter to open a terminal there.
- Linux/macOS: `unzip WormGuard-main.zip && cd WormGuard-main`

## 3. Create a virtual environment and install dependencies

### Windows (PowerShell)
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
### Windows (Command Prompt)
```bat
python -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
```
> If PowerShell says "running scripts is disabled", run this once, then try again:
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

### Linux and macOS
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
When it works, you'll see `(.venv)` at the start of your terminal line.

## 4. Quick start

| What it does | Windows | Linux / macOS |
|---|---|---|
| Attack vs. defence demo | `python -m wormguard demo` | `python3 -m wormguard demo` |
| Worm spread simulation + chart | `python -m wormguard simulate --plot spread.png` | `python3 -m wormguard simulate --plot spread.png` |
| Graphical interface | `python -m wormguard gui` | `python3 -m wormguard gui` |
| Run all tests | `python -m unittest discover -s tests -v` | `python3 -m unittest discover -s tests -v` |

> Once the virtual environment is active, `python` also works on Linux/macOS.

The demo creates its own keys and nodes, so no setup is needed for it.

## 5. Manual workflow

You act as a software publisher sending a safe update to a node.

### Windows
```bat
python -m wormguard keygen --algo rsa --out keys
python -m wormguard trust --node-dir node1 --pub keys\publisher.pub.pem
echo patch v1 > app.txt
python -m wormguard sign app.txt --key keys\publisher.key.pem --version 1
python -m wormguard verify app.txt.wgpkg --node-dir node1
python -m wormguard install app.txt.wgpkg --node-dir node1
```

### Linux and macOS
```bash
python3 -m wormguard keygen --algo rsa --out keys
python3 -m wormguard trust --node-dir node1 --pub keys/publisher.pub.pem
echo "patch v1" > app.txt
python3 -m wormguard sign app.txt --key keys/publisher.key.pem --version 1
python3 -m wormguard verify app.txt.wgpkg --node-dir node1
python3 -m wormguard install app.txt.wgpkg --node-dir node1
```

You should see `ACCEPTED`. If you change even one character inside the `.wgpkg` file and verify again, you'll see `REJECTED`.

**Revoke a stolen key** (use the key id printed by `keygen` or `trust`):
```
python -m wormguard revoke --node-dir node1 --key-id <KEY_ID>
```
Add `--password` to `keygen` and `sign` to protect the private key with a password.

## 6. File integrity monitor (bonus)
```
python -m wormguard integrity-init myfolder
python -m wormguard integrity-check myfolder
```
The second command reports modified, new and deleted files.

## 7. Simulation options
```
python -m wormguard simulate --scenario stolen_key --revoke-step 4 --plot stolen.png
```
| Option | Meaning |
|---|---|
| `--scenario unsigned / forged_id / stolen_key` | Type of attack |
| `--revoke-step N` | Revoke the key at step N |
| `--nodes`, `--prob`, `--trials`, `--steps` | Network size, infection probability, repeats, duration |
| `--adoption 0 0.5 1` | Share of nodes that verify updates |
| `--plot file.png` | Save a chart |

## 8. Troubleshooting

| Problem | Fix |
|---|---|
| `python is not recognized` (Windows) | Reinstall Python with "Add to PATH" ticked, or use `py` |
| `python: command not found` (Linux/macOS) | Use `python3`, or activate the virtual environment first |
| `No module named cryptography` | Activate the virtual environment, then `pip install -r requirements.txt` |
| `ensurepip is not available` / venv fails (Ubuntu) | `sudo apt install python3-venv` |
| `error: externally-managed-environment` | Use the virtual environment from step 3 instead of installing system-wide |
| `No module named tkinter` | Windows/macOS: reinstall Python from python.org. Linux: `sudo apt install python3-tk` |
| `matplotlib not installed; chart skipped` | `pip install matplotlib` |
| `Error: ... No such file` when signing | Run `keygen` first (the `keys/` folder is not in the repo) |
| Leave the virtual environment | `deactivate` |

## Safety note
The "worm" in this project is a harmless text string used for a simulation. No real malware is included.
