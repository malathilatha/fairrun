"""Q-Day simulation: what happens to data stolen TODAY when a quantum computer exists LATER?

This uses FairRun's real encryption and signing code. Only one thing is simulated: Shor's algorithm.
A large quantum computer running Shor's algorithm could recover X25519 and Ed25519 private keys from their
public keys. We cannot run Shor here, so the attacker is simply HANDED those two classical private keys.
Everything else is real: the attacker holds the same stolen ciphertexts and tries the real unlock steps.

Two attacks, each against a classical-only design and against FairRun's hybrid design:
  1. Harvest now, decrypt later: stolen encrypted bank details (the key-wrapping step is attacked).
  2. Forgery: a forged audit seal (the signature is attacked).

Not simulated, and not claimed: AES-256 is not broken by Shor (Grover's algorithm only halves its strength,
leaving ~128 bits), and ML-KEM / ML-DSA are the NIST post-quantum standards (FIPS 203 / FIPS 204).
"""
from __future__ import annotations

import json
import os
import secrets

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypto import (SIG_ALGS, SIG_DOMAIN, EmployerVault, HybridSigner, KemKeypair, _raw_pub, b64,
                     unb64, verify_signature)

SECRET = "DE89370400440532013000"          # a contractor's (synthetic) IBAN


def _classical_kek(x_shared: bytes, employer: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=f"classical-only|{employer}".encode()).derive(x_shared)


def harvest_now_decrypt_later(employer: str = "acct_alpha", secret: str = SECRET) -> dict:
    kp = KemKeypair.generate("x25519+ml-kem-768/v1")
    aad = employer.encode()

    # --- today: the data is encrypted and the data key is wrapped -------------------------
    dek = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(dek).encrypt(nonce, secret.encode(), aad)

    eph = x25519.X25519PrivateKey.generate()                     # (a) classical-only wrapping
    x_shared = eph.exchange(kp.x_priv.public_key())
    n1 = os.urandom(12)
    classical = {"eph_pub": b64(_raw_pub(eph)), "nonce": b64(n1),
                 "wrapped_dek": b64(AESGCM(_classical_kek(x_shared, employer)).encrypt(n1, dek, aad))}
    hybrid = kp.wrap(dek, employer)                              # (b) FairRun: X25519 + ML-KEM-768

    # --- Q-Day: Shor recovers the classical private key (SIMULATED by handing it over) ------
    stolen_x_priv = kp.x_priv

    def attack_classical() -> str:
        xs = stolen_x_priv.exchange(x25519.X25519PublicKey.from_public_bytes(unb64(classical["eph_pub"])))
        dek2 = AESGCM(_classical_kek(xs, employer)).decrypt(unb64(classical["nonce"]),
                                                            unb64(classical["wrapped_dek"]), aad)
        return AESGCM(dek2).decrypt(nonce, ciphertext, aad).decode()

    def attack_hybrid() -> str:
        xs = stolen_x_priv.exchange(x25519.X25519PublicKey.from_public_bytes(unb64(hybrid["eph_pub"])))
        kek = kp._kek(xs, b"", employer)       # the attacker has the classical half; ML-KEM's half is missing
        dek2 = AESGCM(kek).decrypt(unb64(hybrid["nonce"]), unb64(hybrid["wrapped_dek"]), aad)
        return AESGCM(dek2).decrypt(nonce, ciphertext, aad).decode()

    out = {"stolen_ciphertext": b64(ciphertext)[:40] + "…", "secret": secret,
           "classical_read": None, "hybrid_read": None, "hybrid_error": None,
           "sizes": {"x25519_share_bytes": len(unb64(hybrid["eph_pub"])),
                     "ml_kem_ciphertext_bytes": len(unb64(hybrid["pq_ct"]))}}
    try:
        out["classical_read"] = attack_classical()
    except InvalidTag:
        pass
    try:
        out["hybrid_read"] = attack_hybrid()
    except InvalidTag:
        out["hybrid_error"] = "AES-GCM authentication failed: the ML-KEM half of the key is missing"
    return out


def forge_audit_seal() -> dict:
    signer = HybridSigner.generate()
    public = signer.public()
    genuine = json.dumps({"entries": 52, "root": secrets.token_hex(32)}, sort_keys=True).encode()
    forged = json.dumps({"entries": 52, "root": secrets.token_hex(32), "note": "edited after the fact"},
                        sort_keys=True).encode()
    real_sig = signer.sign(genuine)
    ok_genuine = verify_signature(public, genuine, real_sig)
    sizes = {"ed25519_signature_bytes": len(unb64(real_sig["ed25519"])),
             "ml_dsa_signature_bytes": len(unb64(real_sig["ml_dsa"]))}

    # Q-Day: the attacker recovers the Ed25519 private key (SIMULATED by handing it over)
    stolen_ed = signer.ed
    m = SIG_DOMAIN + signer.alg.encode() + b"|" + forged
    attacker_pq = SIG_ALGS[signer.alg].generate()                # the attacker has no real ML-DSA key
    forged_sig = {"alg": signer.alg, "ed25519": b64(stolen_ed.sign(m)), "ml_dsa": b64(attacker_pq.sign(m))}

    try:                                                         # a classical-only verifier
        ed25519.Ed25519PublicKey.from_public_bytes(unb64(public["ed25519"])).verify(unb64(forged_sig["ed25519"]), m)
        classical_accepts = True
    except InvalidSignature:
        classical_accepts = False
    return {"genuine_ok": ok_genuine, "classical_accepts_forgery": classical_accepts,
            "fairrun_accepts_forgery": verify_signature(public, forged, forged_sig), "sizes": sizes}


def migrate_without_rewrite(employers=("acct_alpha", "acct_bright", "acct_cedar")) -> dict:
    vault = EmployerVault.create("x25519+ml-kem-768/v1")
    recs = {e: vault.encrypt(e, SECRET) for e in employers}
    old = vault.kem.alg
    n = vault.rotate_kem("x25519+ml-kem-1024/v2")
    still_readable = all(vault.decrypt(e, r) == SECRET for e, r in recs.items())
    return {"from": old, "to": vault.kem.alg, "keys_rewrapped": n, "data_untouched": still_readable}


def run_all() -> dict:
    return {"hndl": harvest_now_decrypt_later(), "forgery": forge_audit_seal(), "migration": migrate_without_rewrite()}


# What is protected, in plain words and in technical words (shown in the dashboard)
ALGORITHMS = [
    ("Employer data keys", "AES-256-GCM, one key per employer",
     "A separate safe for each company's data.", "Safe: Shor's algorithm doesn't break it; Grover's only halves its strength."),
    ("Locking those keys", "X25519 + ML-KEM-768 (NIST FIPS 203), hybrid",
     "The safe's key needs two different locks opened. Breaking one isn't enough.",
     "Protects against 'harvest now, decrypt later'."),
    ("Signing the audit log", "Ed25519 + ML-DSA-65 (NIST FIPS 204), both must verify",
     "A seal that needs two signatures. A forger with one still fails.",
     "Protects against forged records after Q-Day."),
    ("Changing algorithms later", "Algorithm id on every key and signature; rotation to ML-KEM-1024 / ML-DSA-87",
     "Swap locks without rebuilding the building.", "Answers NIST's warning that migration takes years."),
    ("Audit chain and proof tree", "SHA-256 hash chain and Merkle tree",
     "A tamper-evident notebook.", "Safe: hashes only lose some margin against quantum attacks."),
    ("Zero-knowledge balance proof", "Pedersen commitments on secp256k1 + range proofs",
     "Each employer checks its own money without seeing others'.",
     "Hiding is unconditional, but 'binding' rests on elliptic curves: NOT quantum-safe yet."),
]
