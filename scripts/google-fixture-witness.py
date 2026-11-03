#!/usr/bin/env python3
"""Write circuits/oidc-google/Prover.toml: a Google-shaped ID token signed by a
fixed synthetic RSA-2048 key. The email is mixed case so the circuit folds it.
Public inputs are computed with hashlib, independently of the circuit.

Usage: scripts/google-fixture-witness.py [--out circuits/oidc-google/Prover.toml]
"""
from __future__ import annotations

import argparse
import dataclasses
import functools
import hashlib
import pathlib
import sys

sys.dont_write_bytecode = True
import identity_table  # noqa: E402  (beside this script)
import oidc_fixture  # noqa: E402
from identity_table import hex_halves, toml_array  # noqa: E402
from oidc_fixture import DIGEST, D, N, Header, b64url, compact_json, pkcs1_sha256, redc  # noqa: E402

SUB = "100000000000000000001"
EMAIL = "Fixture@Example.com"
AUD = "000000000000-libidfixture.apps.googleusercontent.com"
IAT = 1893452400
EXP = 1893456000

# circuits/oidc-google/src/main.nr's buffers and RSA modulus layout.
SIGNING_INPUT_MAX = identity_table.integer("SIGNING_INPUT_MAX", identity_table.OIDC_GOOGLE)
PAYLOAD_JSON_MAX = identity_table.integer("PAYLOAD_JSON_MAX", identity_table.OIDC_GOOGLE)
AUDIENCE_MAX = identity_table.integer("AUDIENCE_MAX", identity_table.OIDC_GOOGLE)
NUM_LIMBS, MOD_BITS = oidc_fixture.rsa_layout(identity_table.OIDC_GOOGLE)
limbs = functools.partial(oidc_fixture.limbs, count=NUM_LIMBS)
# lib/identity's generated Google constants.
EMAIL_MAX = identity_table.integer("MAX_HANDLE_GOOGLE")
SUB_MAX = identity_table.integer("MAX_ID_GOOGLE")
USER_ID_TAG = identity_table.byte_array("USER_ID_TAG_GOOGLE")
HANDLE_TAG = identity_table.byte_array("HANDLE_TAG_GOOGLE")


@dataclasses.dataclass(frozen=True)
class Claims:
    """The ID token's claims, in the order Google writes them."""

    iss: str
    azp: str
    aud: str
    sub: str
    email: str
    email_verified: bool
    nonce: str
    iat: int
    exp: int


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=pathlib.Path, default=identity_table.OIDC_GOOGLE.parent.parent / "Prover.toml")
    args = parser.parse_args()

    nonce = b64url(DIGEST).decode()
    header = compact_json(Header())
    payload = compact_json(
        Claims(
            iss="https://accounts.google.com",
            azp=AUD,
            aud=AUD,
            sub=SUB,
            email=EMAIL,
            email_verified=True,
            nonce=nonce,
            iat=IAT,
            exp=EXP,
        )
    )
    signing_input = b64url(header) + b"." + b64url(payload)
    signature = pkcs1_sha256(signing_input, N, D)

    def at(claim: str) -> int:
        return payload.index(f'"{claim}":'.encode())

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
        f'email_offset = "{at("email")}"',
        f'nonce_offset = "{at("nonce")}"',
        f'sub_offset = "{at("sub")}"',
        f'email_verified_offset = "{at("email_verified")}"',
        f'exp_offset = "{at("exp")}"',
        f'exp_len = "{len(exp_digits)}"',
        f'iss_offset = "{at("iss")}"',
        f'aud_offset = "{at("aud")}"',
        f"email_bytes = {toml_array(identity_table.padded('email_bytes', EMAIL.encode(), EMAIL_MAX))}",
        f'email_len = "{len(EMAIL)}"',
        f"sub_bytes = {toml_array(identity_table.padded('sub_bytes', SUB.encode(), SUB_MAX))}",
        f'sub_len = "{len(SUB)}"',
        f"audience_bytes = {toml_array(identity_table.padded('audience_bytes', AUD.encode(), AUDIENCE_MAX))}",
        f'audience_len = "{len(AUD)}"',
        f"signature = {toml_array(limbs(signature))}",
        f"redc = {toml_array(limbs(redc(N, MOD_BITS)))}",
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
