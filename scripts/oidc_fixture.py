"""The OIDC fixtures' synthetic signer: the nonce digest, a seeded RSA-2048
key, the JOSE header, RS256 signing and noir-bignum's limb encoding. The
Google and Telegram witness scripts sign with it; scripts/check-fixtures.py
reads DIGEST.
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import pathlib

import identity_table  # beside this script

# The nonce: libid-rs' ceremony fixtures' `authorization_digest`;
# scripts/check-fixtures.py compares it with libID-contracts' copies.
DIGEST = bytes.fromhex("dacaffd6c7bfe301e73df3a95263b402c94f561a574910968090d65f9ab069e3")
# noir-bignum's limb width, which the OIDC circuits take from the library.
LIMB_BITS = 120

# The synthetic RSA-2048 signing key.
N = int(
    "ac6e236e39697f5ac592e78ea304a62e443e806438f69af826cfd2c1b8beaadf"
    "af1fe49884224453fbbbe3af9cd90b80663c63ee708512212dceb1a0045debc0"
    "518ad33bf87c7b9594769805fb2ca955d31372eff7a16b0bfdd7785b6d1c2d3b"
    "57985149cb5b0dfb2fcda3a25e0cbbe7bc39d182f6fa11fd8fef5f911b109279"
    "95a3c16c2ed25cc3476d5830b4f1486ea7dfffbe7a4c1742b9b9ff301f79cbbb"
    "4ee80f80aab61826e34d9f6187c63807fe806339d152d0060af6f8b026393974"
    "8d9fa66d2df3bc361e10f6ca12453bdd1750674848dcdf4760e86540a2cd4bb4"
    "4bee0738896f853e321e5977bfb7c23b89e1514fa3c4974d1a0637fece10a53f",
    16,
)
E = 65537
D = int(
    "37e014e121ff9ac25a65c95d825bfe51ddd1771f8309fe9bcd4fe916d77c09b9"
    "2471ac4cf3fc7ab1d050496edddfc3875f19d0b432881ca0ddcc2de911a131c5"
    "07677a1de3decad964dbad55bad7f523979ba4d23827799dd02b239854da1d9a"
    "2e3f708ffe32ca6c0c4891ef0a950bcb0346a52ad047a6cec8f6a3bc4ccde8f8"
    "aefd333bd2ba9a4802755de72ac6198039cd83421af447a8823454aaf1995311"
    "aebbdea7563306c670e11ef17b824e871f624e9d465e3e4dc92b5e3394d0e94d"
    "c6c2f1b8a60b51d7f821f8049647cc1faa3c7e018080e5e6693b7954dc883218"
    "2c498317fa4b58c39d9dd60468d36f49d25358573f74554f5c95ba838bcabeb9",
    16,
)


if pow(pow(2, E, N), D, N) != 2:
    raise SystemExit("oidc_fixture.py: D is not the private exponent of (N, E)")


@dataclasses.dataclass(frozen=True)
class Header:
    """An ID token's JOSE header."""

    alg: str = "RS256"
    kid: str = "libid-fixture"
    typ: str = "JWT"


def compact_json(document: object) -> bytes:
    """A dataclass as the JSON a JWT segment carries: no spaces."""
    return json.dumps(dataclasses.asdict(document), separators=(",", ":")).encode()


def b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def pkcs1_sha256(message: bytes, n: int, d: int) -> int:
    prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    t = prefix + hashlib.sha256(message).digest()
    em = b"\x00\x01" + b"\xff" * (256 - len(t) - 3) + b"\x00" + t
    return pow(int.from_bytes(em, "big"), d, n)


def limbs(value: int, count: int) -> list[str]:
    """`value` as `count` noir-bignum limbs, least significant first."""
    mask = (1 << LIMB_BITS) - 1
    return [hex((value >> (LIMB_BITS * i)) & mask) for i in range(count)]


def redc(n: int, mod_bits: int) -> int:
    """noir-bignum's Barrett constant for modulus `n`."""
    return (1 << (2 * mod_bits + 6)) // n


def rsa_layout(main: pathlib.Path) -> tuple[int, int]:
    """NUM_LIMBS and MOD_BITS of the circuit at `main`, refused unless N has MOD_BITS bits."""
    num_limbs, mod_bits = identity_table.integer("NUM_LIMBS", main), identity_table.integer("MOD_BITS", main)
    if N.bit_length() != mod_bits:
        raise SystemExit(f"{main}: MOD_BITS is {mod_bits}, the synthetic key {N.bit_length()} bits")
    return num_limbs, mod_bits
