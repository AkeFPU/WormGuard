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

## Setup
```bash
pip install -r requirements.txt        # Python 3.9+; tkinter needed only for the GUI
# Linux GUI: sudo apt install python3-tk
```

## Quick start (60 seconds)
```bash
python -m wormguard demo                       # full attack / defence story
python -m wormguard simulate --plot spread.png # worm spread with 0%, 50%, 100% protection
python -m wormguard gui                        # graphical interface
python -m unittest discover -s tests -v        # run all tests
```

## Manual workflow
```bash
python -m wormguard keygen --algo rsa --out keys             # publisher key pair
python -m wormguard trust  --node-dir node1 --pub keys/publisher.pub.pem
echo "patch v1" > app.txt
python -m wormguard sign app.txt --key keys/publisher.key.pem --version 1
python -m wormguard verify  app.txt.wgpkg --node-dir node1   # check only
python -m wormguard install app.txt.wgpkg --node-dir node1   # verify + install
python -m wormguard revoke  --node-dir node1 --key-id <id>   # key compromised
```
Add `--password` to `keygen`/`sign` to encrypt the private key.

Integrity monitor:
```bash
python -m wormguard integrity-init  myfolder     # baseline + secret key
python -m wormguard integrity-check myfolder     # reports modified / new / deleted
```

Simulation options: `--scenario unsigned|forged_id|stolen_key`, `--revoke-step N`,
`--nodes`, `--prob`, `--trials`, `--adoption 0 0.5 1`.

## How a node decides
```
package -> well-formed?  -> key revoked?  -> key trusted?  -> signature valid?
        -> SHA-256 matches?  -> version newer?  -> INSTALL
   any "no" = REJECT + audit log entry
```

## Project layout
```
wormguard/   crypto_utils.py package.py verifier.py node.py
             simulation.py integrity.py demo.py cli.py gui.py
tests/       test_wormguard.py
docs/        spread_unsigned.png, spread_stolen_key_revoked.png
REPORT.md    full project report        VIVA_QA.md  likely viva questions
```

## Sample results (100 nodes, 5 random networks averaged)
| Verifying nodes | Infected at step 5 | Infected at step 10 | Final |
|---|---|---|---|
| 0% | 41.8 | 99.2 | 100 |
| 50% | 6.0 | 18.4 | 36.6 |
| 100% | 1.0 | 1.0 | 1 (patient zero only) |

Stolen-key scenario (attacker holds the publisher's private key): all nodes verify, yet the
worm still reaches 100 nodes, because its signature is genuinely valid. Revoking the key at
step 4 stops it at about 12.6 nodes on average. This is why key revocation matters.
