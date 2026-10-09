#!/usr/bin/env python3
"""Write circuits/oidc-google/Prover.toml: a Google-shaped ID token signed by a
fixed synthetic RSA-2048 key. The email is mixed case so the circuit folds it.
Public inputs are computed with hashlib, independently of the circuit.

Usage: scripts/google-fixture-witness.py [--out circuits/oidc-google/Prover.toml]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import sys

sys.dont_write_bytecode = True
import identity_table  # noqa: E402  (beside this script)
from identity_table import toml_array  # noqa: E402

SUB = "100000000000000000001"
EMAIL = "Fixture@Example.com"
AUD = "000000000000-libidfixture.apps.googleusercontent.com"
# The nonce: libid-rs' ceremony fixtures' `authorization_digest` (chain 31337);
# CI compares it with libID-contracts' copies.
DIGEST = bytes.fromhex("6beb766c7835d641b3800e8e4c03616d386251c86dcb8b640e59cec9ba42a01f")
IAT = 1893452400
EXP = 1893456000

# circuits/oidc-google/src/main.nr's buffers and RSA modulus layout.
SIGNING_INPUT_MAX = identity_table.integer("SIGNING_INPUT_MAX", identity_table.OIDC_GOOGLE)
PAYLOAD_JSON_MAX = identity_table.integer("PAYLOAD_JSON_MAX", identity_table.OIDC_GOOGLE)
AUDIENCE_MAX = identity_table.integer("AUDIENCE_MAX", identity_table.OIDC_GOOGLE)
NUM_LIMBS = identity_table.integer("NUM_LIMBS", identity_table.OIDC_GOOGLE)
MOD_BITS = identity_table.integer("MOD_BITS", identity_table.OIDC_GOOGLE)
# lib/identity's generated Google constants.
EMAIL_MAX = identity_table.integer("MAX_HANDLE_GOOGLE")
SUB_MAX = identity_table.integer("MAX_ID_GOOGLE")
USER_ID_TAG = identity_table.byte_array("USER_ID_TAG_GOOGLE")
HANDLE_TAG = identity_table.byte_array("HANDLE_TAG_GOOGLE")
# noir-bignum's limb width; main.nr takes it from the library, not as a global.
LIMB_BITS = 120


# The synthetic key. Nothing outside this file signs with it.
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


def hex_halves(digest: bytes) -> list[str]:
    return [f"0x{half:032x}" for half in identity_table.halves(digest)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    root = pathlib.Path(__file__).resolve().parent.parent
    parser.add_argument("--out", type=pathlib.Path, default=root / "circuits" / "oidc-google" / "Prover.toml")
    args = parser.parse_args()

    assert N.bit_length() == MOD_BITS and pow(pow(2, E, N), D, N) == 2
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
    signature = pkcs1_sha256(signing_input, N, D)

    def at(needle: str) -> int:
        return payload.index(needle.encode())

    exp_digits = str(EXP)
    folded = identity_table.fold(EMAIL.encode())
    lines = [
        "# Written by scripts/google-fixture-witness.py: a Google-shaped ID token",
        f"# signed by a seeded synthetic RSA-2048 key, `sub` {SUB}, `email` {EMAIL}.",
        "# scripts/check-verifiers.sh proves it and verifies the proof natively and",
        "# with the Solidity verifier.",
        f"signing_input = {toml_array(identity_table.padded('signing_input', signing_input, SIGNING_INPUT_MAX))}",
        f'signing_input_len = "{len(signing_input)}"',
        f'header_b64_len = "{len(b64url(header))}"',
        f"payload_json = {toml_array(identity_table.padded('payload_json', payload, PAYLOAD_JSON_MAX))}",
        f'payload_json_len = "{len(payload)}"',
        f'email_offset = "{at(chr(34) + "email" + chr(34) + ":")}"',
        f'nonce_offset = "{at(chr(34) + "nonce" + chr(34) + ":")}"',
        f'sub_offset = "{at(chr(34) + "sub" + chr(34) + ":")}"',
        f'email_verified_offset = "{at(chr(34) + "email_verified" + chr(34))}"',
        f'exp_offset = "{at(chr(34) + "exp" + chr(34) + ":")}"',
        f'exp_len = "{len(exp_digits)}"',
        f'iss_offset = "{at(chr(34) + "iss" + chr(34) + ":")}"',
        f'aud_offset = "{at(chr(34) + "aud" + chr(34) + ":")}"',
        f"email_bytes = {toml_array(identity_table.padded('email_bytes', EMAIL.encode(), EMAIL_MAX))}",
        f'email_len = "{len(EMAIL)}"',
        f"sub_bytes = {toml_array(identity_table.padded('sub_bytes', SUB.encode(), SUB_MAX))}",
        f'sub_len = "{len(SUB)}"',
        f"audience_bytes = {toml_array(identity_table.padded('audience_bytes', AUD.encode(), AUDIENCE_MAX))}",
        f'audience_len = "{len(AUD)}"',
        f"signature = {toml_array(limbs(signature))}",
        f"redc = {toml_array(limbs((1 << (2 * MOD_BITS + 6)) // N))}",
        f"authorization_digest = {toml_array(list(DIGEST))}",
        f"audience_hash = {toml_array(hex_halves(hashlib.sha256(AUD.encode()).digest()))}",
        f"id_node = {toml_array(hex_halves(hashlib.sha256(USER_ID_TAG + SUB.encode()).digest()))}",
        f"handle_node = {toml_array(hex_halves(hashlib.sha256(HANDLE_TAG + folded).digest()))}",
        f'exp = "{EXP}"',
        f"modulus = {toml_array(limbs(N))}",
    ]
    args.out.write_text("\n".join(lines) + "\n")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
