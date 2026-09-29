#!/usr/bin/env python3
"""Write circuits/oidc-google/Prover.toml, the witness scripts/check-verifiers.sh
proves: a Google-shaped ID token signed by a synthetic RSA-2048 key.

    scripts/oidc-google-witness.py           rewrite the witness
    scripts/oidc-google-witness.py --check   fail if the committed one differs

The key derives from a fixed seed, so the output is byte-reproducible. The
claims are fixtures: `sub` 100000000000000000001, `email` fixture@example.com,
and as `nonce` the Authorization Digest that platform-ceremonies.md section 3.1
publishes. The array sizes are the circuit's globals in src/main.nr.
"""

import base64
import hashlib
import json
import random
import sys
from pathlib import Path

WITNESS = Path(__file__).resolve().parent.parent / "circuits/oidc-google/Prover.toml"

SIGNING_INPUT_MAX = 1280
PAYLOAD_JSON_MAX = 768
EMAIL_MAX = 62
SUB_MAX = 31
AUDIENCE_MAX = 128
NUM_LIMBS = 18
LIMB_BITS = 120
MOD_BITS = 2048
EXPONENT = 65537
# DER DigestInfo prefix of a SHA-256 PKCS#1 v1.5 signature (RFC 8017 9.2).
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
# bignum's Barrett reduction parameter: floor(2^(2 * MOD_BITS + 6) / modulus).
BARRETT_OVERFLOW_BITS = 6

DIGEST = bytes.fromhex("b318fb559e16a179b853ed2853576cda16032d93b0839bb81a55135d334c0af5")
AUDIENCE = b"000000000000-libidfixture.apps.googleusercontent.com"
SUB = b"100000000000000000001"
EMAIL = b"fixture@example.com"
EXP = 1893456000


def b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


class RsaKey:
    """An RSA-2048 key with public exponent 65537, drawn from a seeded RNG."""

    def __init__(self, seed: int):
        rng = random.Random(seed)
        p, q = self._prime(rng), self._prime(rng)
        self.modulus = p * q
        assert self.modulus.bit_length() == MOD_BITS
        self._private = pow(EXPONENT, -1, (p - 1) * (q - 1))

    @staticmethod
    def _prime(rng: random.Random) -> int:
        while True:
            # The top two bits set make the product exactly MOD_BITS long.
            candidate = rng.getrandbits(MOD_BITS // 2) | (3 << (MOD_BITS // 2 - 2)) | 1
            if candidate % EXPONENT != 1 and RsaKey._is_probable_prime(candidate, rng):
                return candidate

    @staticmethod
    def _is_probable_prime(n: int, rng: random.Random) -> bool:
        d, s = n - 1, 0
        while d % 2 == 0:
            d, s = d // 2, s + 1
        for _ in range(40):
            x = pow(rng.randrange(2, n - 1), d, n)
            if x in (1, n - 1):
                continue
            for _ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def sign(self, message: bytes) -> int:
        """RSASSA-PKCS1-v1_5 with SHA-256."""
        digest_info = SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
        padding = b"\xff" * (MOD_BITS // 8 - 3 - len(digest_info))
        encoded = int.from_bytes(b"\x00\x01" + padding + b"\x00" + digest_info, "big")
        signature = pow(encoded, self._private, self.modulus)
        assert pow(signature, EXPONENT, self.modulus) == encoded
        return signature


def limbs(value: int) -> list:
    mask = (1 << LIMB_BITS) - 1
    return [hex((value >> (LIMB_BITS * i)) & mask) for i in range(NUM_LIMBS)]


def padded(data: bytes, width: int) -> list:
    assert len(data) <= width
    return list(data.ljust(width, b"\0"))


def packed(data: bytes) -> str:
    """Up to 31 bytes, zero-padded, as one big-endian Field."""
    return hex(int.from_bytes(data.ljust(31, b"\0"), "big"))


def witness() -> str:
    key = RsaKey(seed=1)
    header = {"alg": "RS256", "kid": "libid-fixture", "typ": "JWT"}
    payload = {
        "iss": "https://accounts.google.com",
        "azp": AUDIENCE.decode(),
        "aud": AUDIENCE.decode(),
        "sub": SUB.decode(),
        "email": EMAIL.decode(),
        "email_verified": True,
        "nonce": b64url(DIGEST).decode(),
        "iat": EXP - 3600,
        "exp": EXP,
    }
    payload_json = json.dumps(payload, separators=(",", ":")).encode()
    header_b64 = b64url(json.dumps(header, separators=(",", ":")).encode())
    signing_input = header_b64 + b"." + b64url(payload_json)

    def offset(claim: bytes) -> int:
        assert payload_json.count(claim) == 1, claim
        return payload_json.index(claim)

    audience_hash = hashlib.sha256(AUDIENCE).digest()
    fields = {
        "signing_input": padded(signing_input, SIGNING_INPUT_MAX),
        "signing_input_len": len(signing_input),
        "header_b64_len": len(header_b64),
        "payload_json": padded(payload_json, PAYLOAD_JSON_MAX),
        "payload_json_len": len(payload_json),
        "email_offset": offset(b'"email":"'),
        "nonce_offset": offset(b'"nonce":"'),
        "sub_offset": offset(b'"sub":"'),
        "email_verified_offset": offset(b'"email_verified":true'),
        "exp_offset": offset(b'"exp":'),
        "exp_len": len(str(EXP)),
        "iss_offset": offset(b'"iss":"https://accounts.google.com"'),
        "aud_offset": offset(b'"aud":"'),
        "email_bytes": padded(EMAIL, EMAIL_MAX),
        "email_len": len(EMAIL),
        "sub_bytes": padded(SUB, SUB_MAX),
        "sub_len": len(SUB),
        "audience_bytes": padded(AUDIENCE, AUDIENCE_MAX),
        "audience_len": len(AUDIENCE),
        "signature": limbs(key.sign(signing_input)),
        "redc": limbs((1 << (2 * MOD_BITS + BARRETT_OVERFLOW_BITS)) // key.modulus),
        "authorization_digest": list(DIGEST),
        "audience_hash": ["0x" + audience_hash[:16].hex(), "0x" + audience_hash[16:].hex()],
        "sub_packed": [packed(SUB)],
        "email_packed": [packed(EMAIL[:31]), packed(EMAIL[31:])],
        "exp": EXP,
        "modulus": limbs(key.modulus),
    }

    def toml(value) -> str:
        if isinstance(value, list):
            return "[" + ", ".join(toml(v) for v in value) + "]"
        return f'"{value}"' if isinstance(value, str) else str(value)

    lines = [
        "# Generated by scripts/oidc-google-witness.py: a Google-shaped ID token",
        "# signed by a synthetic RSA-2048 key. Edit the script, not this file.",
    ]
    lines += [f"{name} = {toml(value)}" for name, value in fields.items()]
    return "\n".join(lines) + "\n"


def main() -> int:
    args = sys.argv[1:]
    if args not in ([], ["--check"]):
        print(f"usage: {sys.argv[0]} [--check]", file=sys.stderr)
        return 2
    want = witness()
    if args == ["--check"]:
        if not WITNESS.is_file() or WITNESS.read_text() != want:
            print(f"{WITNESS} differs from what {sys.argv[0]} writes; run it.", file=sys.stderr)
            return 1
        return 0
    WITNESS.write_text(want)
    return 0


if __name__ == "__main__":
    sys.exit(main())
