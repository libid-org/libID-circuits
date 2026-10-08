#!/usr/bin/env python3
"""Write circuits/oidc-google/Prover.toml: a Google-shaped ID token signed by a
seeded synthetic RSA-2048 key, so no real account's claims enter the repo.

The key is derived from SEED below with a SHA-256 counter stream and
Miller-Rabin, so the same seed gives the same key, token and witness on any
machine. The token's email is mixed case on purpose: the circuit folds it, and
the witness's handle node is the node of the folded address.

Everything public is computed here with hashlib, independently of the
circuit: SHA256(aud), SHA256("libid.google.user-id" || sub),
SHA256("libid.google.handle" || folded email). `nargo execute` refuses a
witness the circuit disagrees with.

The nonce is the Authorization Digest of libid-rs' x and github session
fixtures (chain 31337), so the contracts' Google suite shares their digest.

Usage: scripts/google-fixture-witness.py [--out circuits/oidc-google/Prover.toml]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib

SEED = b"libid oidc-google fixture key v2"
SUB = "100000000000000000001"
EMAIL = "Fixture@Example.com"
AUD = "000000000000-libidfixture.apps.googleusercontent.com"
DIGEST = bytes.fromhex("6beb766c7835d641b3800e8e4c03616d386251c86dcb8b640e59cec9ba42a01f")
IAT = 1893452400
EXP = 1893456000

SIGNING_INPUT_MAX = 1280
PAYLOAD_JSON_MAX = 768
EMAIL_MAX = 62
SUB_MAX = 31
AUDIENCE_MAX = 128
LIMB_BITS = 120
NUM_LIMBS = 18
MOD_BITS = 2048


class Stream:
    """SHA-256 in counter mode over the seed: a deterministic byte source."""

    def __init__(self, seed: bytes) -> None:
        self.seed, self.counter = seed, 0

    def bytes(self, n: int) -> bytes:
        out = b""
        while len(out) < n:
            out += hashlib.sha256(self.seed + self.counter.to_bytes(8, "big")).digest()
            self.counter += 1
        return out[:n]

    def below(self, bound: int) -> int:
        size = (bound.bit_length() + 7) // 8 + 8
        return int.from_bytes(self.bytes(size), "big") % bound


def probably_prime(n: int, stream: Stream) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d, r = d // 2, r + 1
    for _ in range(40):
        a = 2 + stream.below(n - 3)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def prime(bits: int, stream: Stream, e: int) -> int:
    while True:
        candidate = int.from_bytes(stream.bytes(bits // 8), "big")
        candidate |= (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if (candidate - 1) % e != 0 and probably_prime(candidate, stream):
            return candidate


def b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def pkcs1_sha256(message: bytes, n: int, d: int) -> int:
    prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    t = prefix + hashlib.sha256(message).digest()
    em = b"\x00\x01" + b"\xff" * (256 - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"), d, n)


def limbs(value: int) -> list[str]:
    mask = (1 << LIMB_BITS) - 1
    return [hex((value >> (LIMB_BITS * i)) & mask) for i in range(NUM_LIMBS)]


def halves(digest: bytes) -> list[str]:
    return ["0x" + digest[:16].hex(), "0x" + digest[16:].hex()]


def padded(data: bytes, size: int) -> list[int]:
    assert len(data) <= size, (len(data), size)
    return list(data) + [0] * (size - len(data))


def toml_list(values) -> str:
    return "[" + ", ".join(f'"{v}"' if isinstance(v, str) else str(v) for v in values) + "]"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    root = pathlib.Path(__file__).resolve().parent.parent
    parser.add_argument("--out", type=pathlib.Path, default=root / "circuits" / "oidc-google" / "Prover.toml")
    args = parser.parse_args()

    stream, e = Stream(SEED), 65537
    p = prime(1024, stream, e)
    q = prime(1024, stream, e)
    n = p * q
    assert n.bit_length() == MOD_BITS
    d = pow(e, -1, (p - 1) * (q - 1))

    nonce = b64url(DIGEST).decode()
    header = b'{"alg":"RS256","kid":"libid-fixture","typ":"JWT"}'
    payload = json.dumps(
        {
            "iss": "https://accounts.google.com",
            "azp": AUD,
            "aud": AUD,
            "sub": SUB,
            "email": EMAIL,
            "email_verified": True,
            "nonce": nonce,
            "iat": IAT,
            "exp": EXP,
        },
        separators=(",", ":"),
    ).encode()
    signing_input = b64url(header) + b"." + b64url(payload)
    signature = pkcs1_sha256(signing_input, n, d)

    def at(needle: str) -> int:
        return payload.index(needle.encode())

    exp_digits = str(EXP)
    folded = bytes(b + 0x20 if 0x41 <= b <= 0x5A else b for b in EMAIL.encode())
    lines = [
        "# Written by scripts/google-fixture-witness.py: a Google-shaped ID token",
        f"# signed by a seeded synthetic RSA-2048 key, `sub` {SUB}, `email` {EMAIL}.",
        "# scripts/check-verifiers.sh proves it and verifies the proof natively and",
        "# with the Solidity verifier.",
        f"signing_input = {toml_list(padded(signing_input, SIGNING_INPUT_MAX))}",
        f'signing_input_len = "{len(signing_input)}"',
        f'header_b64_len = "{len(b64url(header))}"',
        f"payload_json = {toml_list(padded(payload, PAYLOAD_JSON_MAX))}",
        f'payload_json_len = "{len(payload)}"',
        f'email_offset = "{at(chr(34) + "email" + chr(34) + ":")}"',
        f'nonce_offset = "{at(chr(34) + "nonce" + chr(34) + ":")}"',
        f'sub_offset = "{at(chr(34) + "sub" + chr(34) + ":")}"',
        f'email_verified_offset = "{at(chr(34) + "email_verified" + chr(34))}"',
        f'exp_offset = "{at(chr(34) + "exp" + chr(34) + ":")}"',
        f'exp_len = "{len(exp_digits)}"',
        f'iss_offset = "{at(chr(34) + "iss" + chr(34) + ":")}"',
        f'aud_offset = "{at(chr(34) + "aud" + chr(34) + ":")}"',
        f"email_bytes = {toml_list(padded(EMAIL.encode(), EMAIL_MAX))}",
        f'email_len = "{len(EMAIL)}"',
        f"sub_bytes = {toml_list(padded(SUB.encode(), SUB_MAX))}",
        f'sub_len = "{len(SUB)}"',
        f"audience_bytes = {toml_list(padded(AUD.encode(), AUDIENCE_MAX))}",
        f'audience_len = "{len(AUD)}"',
        f"signature = {toml_list(limbs(signature))}",
        f"redc = {toml_list(limbs((1 << (2 * MOD_BITS + 6)) // n))}",
        f"authorization_digest = {toml_list(list(DIGEST))}",
        f"audience_hash = {toml_list(halves(hashlib.sha256(AUD.encode()).digest()))}",
        f"id_node = {toml_list(halves(hashlib.sha256(b'libid.google.user-id' + SUB.encode()).digest()))}",
        f"handle_node = {toml_list(halves(hashlib.sha256(b'libid.google.handle' + folded).digest()))}",
        f'exp = "{EXP}"',
        f"modulus = {toml_list(limbs(n))}",
    ]
    args.out.write_text("\n".join(lines) + "\n")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
