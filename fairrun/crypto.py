"""FairRun's security layer: per-employer encryption and a hybrid post-quantum signer.

Every key, ciphertext and signature carries an algorithm id, so algorithms can be rotated
without a rewrite (crypto-agility). Keys live in memory here; production would hold the
master keys in a KMS/HSM.

1. Per-employer data keys (DEKs)
   Each employer's contractor bank data is encrypted with ITS OWN AES-256-GCM key. The employer id
   is bound into every ciphertext (AAD), so a record cannot be decrypted with, or moved to, another
   employer. Deleting an employer's key makes all its stored data unreadable (crypto-shredding).

2. Hybrid key wrapping (X25519 + ML-KEM)
   Each DEK is wrapped under a key derived from BOTH a classical X25519 exchange and a post-quantum
   ML-KEM encapsulation. Breaking it needs both broken: protection against "harvest now, decrypt later".

3. Hybrid signatures (Ed25519 + ML-DSA)
   Audit seals are signed with both algorithms; a signature is valid only if BOTH verify
   (the approach of the IETF composite ML-DSA draft).
"""
from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DEK_ALG = "aes-256-gcm"

KEM_ALGS = {
    "x25519+ml-kem-768/v1": mlkem.MLKEM768PrivateKey,
    "x25519+ml-kem-1024/v2": mlkem.MLKEM1024PrivateKey,
}
SIG_ALGS = {
    "ed25519+ml-dsa-65/v1": mldsa.MLDSA65PrivateKey,
    "ed25519+ml-dsa-87/v2": mldsa.MLDSA87PrivateKey,
}
SIG_DOMAIN = b"FairRun-audit-seal|"


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def unb64(s: str) -> bytes:
    return base64.b64decode(s)


def _raw_pub(key) -> bytes:
    """Raw public bytes from a private OR public X25519/Ed25519 key."""
    pub = key.public_key() if hasattr(key, "public_key") else key
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


# ---------------------------------------------------------------------------
# Hybrid KEM keypair (the platform's master key for wrapping employer DEKs)
# ---------------------------------------------------------------------------
@dataclass
class KemKeypair:
    alg: str
    x_priv: x25519.X25519PrivateKey
    pq_priv: object

    @classmethod
    def generate(cls, alg: str) -> "KemKeypair":
        return cls(alg, x25519.X25519PrivateKey.generate(), KEM_ALGS[alg].generate())

    def _kek(self, x_shared: bytes, pq_shared: bytes, employer: str) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=f"FairRun-KEK|{self.alg}|{employer}".encode()).derive(x_shared + pq_shared)

    def wrap(self, dek: bytes, employer: str) -> dict:
        eph = x25519.X25519PrivateKey.generate()
        x_shared = eph.exchange(self.x_priv.public_key())
        pq_shared, pq_ct = self.pq_priv.public_key().encapsulate()
        nonce = os.urandom(12)
        wrapped = AESGCM(self._kek(x_shared, pq_shared, employer)).encrypt(nonce, dek, employer.encode())
        return {"alg": self.alg, "eph_pub": b64(_raw_pub(eph)), "pq_ct": b64(pq_ct),
                "nonce": b64(nonce), "wrapped_dek": b64(wrapped)}

    def unwrap(self, rec: dict, employer: str) -> bytes:
        if rec["alg"] != self.alg:
            raise ValueError(f"key wrapped with {rec['alg']}, this keypair is {self.alg}")
        eph_pub = x25519.X25519PublicKey.from_public_bytes(unb64(rec["eph_pub"]))
        x_shared = self.x_priv.exchange(eph_pub)
        pq_shared = self.pq_priv.decapsulate(unb64(rec["pq_ct"]))
        return AESGCM(self._kek(x_shared, pq_shared, employer)).decrypt(
            unb64(rec["nonce"]), unb64(rec["wrapped_dek"]), employer.encode())


class RetentionError(Exception):
    """The employer's records are still inside their legal retention period."""


class ShreddedError(Exception):
    """The employer's data key was destroyed; its data can no longer be read."""


@dataclass
class EmployerVault:
    """Holds one wrapped data key per employer. Plain DEKs are never stored."""
    kem: KemKeypair
    wrapped: dict[str, dict] = field(default_factory=dict)
    retired_kems: dict[str, KemKeypair] = field(default_factory=dict)

    @classmethod
    def create(cls, kem_alg: str = "x25519+ml-kem-768/v1") -> "EmployerVault":
        return cls(KemKeypair.generate(kem_alg))

    def _dek(self, employer: str, create: bool = False) -> bytes:
        if employer in self._shredded:
            raise ShreddedError(f"data key for {employer} was destroyed")
        if employer not in self.wrapped:
            if not create:
                raise KeyError(f"no data key for {employer}")
            self.wrapped[employer] = self.kem.wrap(AESGCM.generate_key(bit_length=256), employer)
        rec = self.wrapped[employer]
        kem = self.kem if rec["alg"] == self.kem.alg else self.retired_kems[rec["alg"]]
        return kem.unwrap(rec, employer)

    @property
    def _shredded(self) -> set[str]:
        return self.__dict__.setdefault("_shredded_set", set())

    def encrypt(self, employer: str, plaintext: str) -> dict:
        nonce = os.urandom(12)
        ct = AESGCM(self._dek(employer, create=True)).encrypt(nonce, plaintext.encode(), employer.encode())
        return {"alg": DEK_ALG, "employer": employer, "nonce": b64(nonce), "ct": b64(ct)}

    def decrypt(self, employer: str, record: dict) -> str:
        """Decrypt with THIS employer's key. A record of another employer fails (InvalidTag)."""
        return AESGCM(self._dek(employer)).decrypt(unb64(record["nonce"]), unb64(record["ct"]),
                                                   employer.encode()).decode()

    @property
    def _retention(self) -> dict[str, float]:
        return self.__dict__.setdefault("_retention_until", {})

    def keep_records_until(self, employer: str, until: float) -> None:
        """Legal retention lock (e.g. payroll/tax records must be kept for years). Can only be extended."""
        self._retention[employer] = max(until, self._retention.get(employer, 0.0))

    def shred(self, employer: str, now: float | None = None) -> None:
        """Destroy the employer's data key. Refused while a legal retention period is still running."""
        import time
        until = self._retention.get(employer, 0.0)
        if (time.time() if now is None else now) < until:
            raise RetentionError(f"records of {employer} must be kept until "
                                 f"{time.strftime('%Y-%m-%d', time.gmtime(until))}; shredding refused")
        self.wrapped.pop(employer, None)
        self._shredded.add(employer)

    def rotate_kem(self, new_alg: str) -> int:
        """Crypto-agility: re-wrap every employer key under a new KEM. Data itself is untouched."""
        new = KemKeypair.generate(new_alg)
        count = 0
        for emp, rec in list(self.wrapped.items()):
            dek = self._dek(emp)
            self.wrapped[emp] = new.wrap(dek, emp)
            count += 1
        self.retired_kems[self.kem.alg] = self.kem
        self.kem = new
        return count


# ---------------------------------------------------------------------------
# Hybrid signer
# ---------------------------------------------------------------------------
@dataclass
class HybridSigner:
    alg: str
    ed: ed25519.Ed25519PrivateKey
    pq: object

    @classmethod
    def generate(cls, alg: str = "ed25519+ml-dsa-65/v1") -> "HybridSigner":
        return cls(alg, ed25519.Ed25519PrivateKey.generate(), SIG_ALGS[alg].generate())

    def public(self) -> dict:
        return {"alg": self.alg, "ed25519": b64(_raw_pub(self.ed)),
                "ml_dsa": b64(self.pq.public_key().public_bytes_raw())}

    def sign(self, message: bytes) -> dict:
        m = SIG_DOMAIN + self.alg.encode() + b"|" + message
        return {"alg": self.alg, "ed25519": b64(self.ed.sign(m)), "ml_dsa": b64(self.pq.sign(m))}


def verify_signature(public: dict, message: bytes, sig: dict) -> bool:
    """Valid only if BOTH the classical and the post-quantum signature verify."""
    if sig["alg"] != public["alg"]:
        return False
    m = SIG_DOMAIN + sig["alg"].encode() + b"|" + message
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(unb64(public["ed25519"])).verify(unb64(sig["ed25519"]), m)
        _pq_public(public["alg"], unb64(public["ml_dsa"])).verify(unb64(sig["ml_dsa"]), m)
        return True
    except (InvalidSignature, ValueError):
        return False


def _pq_public(alg: str, raw: bytes):
    return {"ed25519+ml-dsa-65/v1": mldsa.MLDSA65PublicKey,
            "ed25519+ml-dsa-87/v2": mldsa.MLDSA87PublicKey}[alg].from_public_bytes(raw)


__all__ = ["EmployerVault", "HybridSigner", "ShreddedError", "verify_signature", "InvalidTag"]
