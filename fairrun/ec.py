"""Minimal secp256k1 arithmetic for Pedersen commitments (demo-grade, pure Python).

secp256k1 has prime order and cofactor 1, so any point that satisfies the curve equation is in the
right group: no small-subgroup checks are needed. This code is NOT constant-time; production would
use a vetted library (e.g. libsecp256k1 or a Ristretto255 implementation).
"""
from __future__ import annotations

import hashlib

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

INF = None


def on_curve(pt) -> bool:
    if pt is INF:
        return True
    x, y = pt
    return 0 <= x < P and 0 <= y < P and (y * y - x * x * x - 7) % P == 0


# Jacobian coordinates internally: (X, Y, Z) with x = X/Z^2, y = Y/Z^3
def _to_j(pt):
    return (pt[0], pt[1], 1) if pt is not INF else (0, 1, 0)


def _from_j(j):
    X, Y, Z = j
    if Z == 0:
        return INF
    zi = pow(Z, -1, P)
    zi2 = zi * zi % P
    return (X * zi2 % P, Y * zi2 * zi % P)


def _jdouble(j):
    X, Y, Z = j
    if Z == 0 or Y == 0:
        return (0, 1, 0)
    S = 4 * X * Y * Y % P
    M = 3 * X * X % P
    X3 = (M * M - 2 * S) % P
    Y3 = (M * (S - X3) - 8 * pow(Y, 4, P)) % P
    return (X3, Y3, 2 * Y * Z % P)


def _jadd(a, b):
    X1, Y1, Z1 = a
    X2, Y2, Z2 = b
    if Z1 == 0:
        return b
    if Z2 == 0:
        return a
    Z1s, Z2s = Z1 * Z1 % P, Z2 * Z2 % P
    U1, U2 = X1 * Z2s % P, X2 * Z1s % P
    S1, S2 = Y1 * Z2s * Z2 % P, Y2 * Z1s * Z1 % P
    if U1 == U2:
        return _jdouble(a) if S1 == S2 else (0, 1, 0)
    H, R = (U2 - U1) % P, (S2 - S1) % P
    H2 = H * H % P
    H3 = H * H2 % P
    U1H2 = U1 * H2 % P
    X3 = (R * R - H3 - 2 * U1H2) % P
    Y3 = (R * (U1H2 - X3) - S1 * H3) % P
    return (X3, Y3, H * Z1 * Z2 % P)


def add(a, b):
    return _from_j(_jadd(_to_j(a), _to_j(b)))


def neg(a):
    return INF if a is INF else (a[0], (-a[1]) % P)


def mul(pt, k: int):
    k %= N
    acc, base = (0, 1, 0), _to_j(pt)
    while k:
        if k & 1:
            acc = _jadd(acc, base)
        base = _jdouble(base)
        k >>= 1
    return _from_j(acc)


class FixedBase:
    """Precomputed 4-bit windows for a fixed generator: ~4x faster than plain mul."""
    def __init__(self, pt):
        self.table = []
        base = _to_j(pt)
        for _ in range(64):
            row, cur = [(0, 1, 0)], (0, 1, 0)
            for _ in range(15):
                cur = _jadd(cur, base)
                row.append(cur)
            self.table.append(row)
            for _ in range(4):
                base = _jdouble(base)

    def mul(self, k: int):
        k %= N
        acc = (0, 1, 0)
        for i in range(64):
            d = (k >> (4 * i)) & 15
            if d:
                acc = _jadd(acc, self.table[i][d])
        return _from_j(acc)


def encode(pt) -> bytes:
    if pt is INF:
        return b"\x00"
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def decode(b: bytes):
    if b == b"\x00":
        return INF
    if len(b) != 33 or b[0] not in (2, 3):
        raise ValueError("bad point")
    x = int.from_bytes(b[1:], "big")
    y = pow((x ** 3 + 7) % P, (P + 1) // 4, P)
    if (y * y - x ** 3 - 7) % P:
        raise ValueError("not on curve")
    if (y & 1) != (b[0] & 1):
        y = P - y
    return (x, y)


def hash_to_point(tag: bytes):
    """Nothing-up-my-sleeve generator: nobody knows its discrete log w.r.t. G."""
    i = 0
    while True:
        x = int.from_bytes(hashlib.sha256(tag + i.to_bytes(4, "big")).digest(), "big") % P
        y2 = (x ** 3 + 7) % P
        y = pow(y2, (P + 1) // 4, P)
        if y * y % P == y2:
            return (x, y if y % 2 == 0 else P - y)
        i += 1


G = (GX, GY)
H = hash_to_point(b"FairRun/pedersen/H/v1")
G_FB, H_FB = FixedBase(G), FixedBase(H)
