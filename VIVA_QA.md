# Likely viva questions and short answers

1. **What problem does your project solve?** Worms often pose as updates. We make nodes install only updates that are signed by a trusted publisher and whose SHA-256 hash matches.
2. **Why both a hash and a signature?** The hash detects changes to the file. The signature proves who produced the hash. A hash alone can be recomputed by an attacker.
3. **What exactly is signed?** The manifest (name, version, SHA-256, size, key id). Because the manifest holds the payload hash, one signature protects both.
4. **Why RSA-PSS and not plain RSA?** PSS is a randomised padding scheme with a security proof. ECDSA P-256 is also supported and has smaller keys and signatures.
5. **What does the private key do, and the public key?** The private key signs (publisher only). The public key verifies (every node).
6. **A worm copies the publisher's key id. Does that work?** No. The signature is checked with the trusted key for that id and fails (`BAD_SIGNATURE`).
7. **What if the attacker modifies the payload and the manifest hash?** The manifest signature then fails, because the signed bytes changed.
8. **What is the rollback check for?** It blocks replay of an old, vulnerable but validly signed update.
9. **What if the private key is stolen?** The attacker's packages verify, as in Stuxnet. Revocation fixes this; our simulation shows infection falls from 100 to about 13 nodes when the key is revoked at step 4.
10. **Why is the signature checked before the hash?** Authenticity first: we should not trust any field of an unauthenticated manifest.
11. **Why constant-time comparison?** To avoid leaking, through timing, how many characters of a hash matched.
12. **What is HMAC and where is it used?** A keyed hash. We use it to protect the file-integrity baseline so malware cannot rewrite the baseline.
13. **How does the simulation use cryptography?** Protected nodes call the real `verify_package()` for every delivery attempt; results are not hard-coded.
14. **What are the limits of your work?** It does not stop worms that exploit software bugs; key theft, trust-store tampering and manual revocation are open issues (Section 8 of the report).
15. **How does this connect to real worms?** Stuxnet used stolen certificates (key compromise); WannaCry exploited unpatched systems (patching and segmentation matter); ILOVEYOU used email attachments (attachment hash/signature checks).
