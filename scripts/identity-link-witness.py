#!/usr/bin/env python3
"""Write a bearer-link-<platform> Prover.toml from an identity-link witness.

The witness is what libid-rs writes beside a ceremony record: the synthetic
`identity_link_witness` member of `<platform>-ceremony-session.json`
(`cargo run -p libid-tlsn --example ceremony_fixtures`), or the owner-only
`<platform>-identity-link-witness.secret.json` a real capture writes
(`--example capture_ceremony`). Either way: the bearer, the id and the handle
as the platform sent them, each with the blinder of its commitment.

The public inputs are computed here, with hashlib, from the raw values: each
commitment is SHA256(value || blinder) and must equal the one the witness
states (which libid-rs checked against the signed record); the nodes are
SHA256(tag || id) and SHA256(tag || folded handle). The circuit computes the
same things its own way; a disagreement fails `nargo execute`.

Usage:
  scripts/identity-link-witness.py <witness.json | session fixture> [--out Prover.toml]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

MAX_BEARER = 128
# The platform's buffers and tags. These are the circuit's, and the tags are
# handles.json's: lib/identity/src/table.nr is generated from it, and this
# reads them from there rather than restating them.
TABLE = pathlib.Path(__file__).resolve().parent.parent / "lib" / "identity" / "src" / "table.nr"


def table_constant(name: str) -> str:
    # nargo fmt wraps long constants, so read the declaration whole.
    found = re.search(rf"pub global {name}:[^=]*=\s*([^;]*);", TABLE.read_text())
    if found is None:
        raise SystemExit(f"{TABLE}: no {name}")
    return " ".join(found.group(1).split())


def table_bytes(name: str) -> bytes:
    inner = table_constant(name).strip("[]")
    return bytes(int(b, 16) for b in inner.split(",") if b.strip())


def halves(digest: bytes) -> list[str]:
    return [str(int.from_bytes(digest[:16], "big")), str(int.from_bytes(digest[16:], "big"))]


def padded(value: bytes, size: int) -> list[int]:
    if len(value) > size:
        raise SystemExit(f"value of {len(value)} bytes does not fit a {size}-byte buffer")
    return list(value) + [0] * (size - len(value))


def opened(entry: dict) -> tuple[bytes, bytes]:
    value = entry["value"].encode()
    blinder = bytes.fromhex(entry["blinder"].removeprefix("0x"))
    commitment = hashlib.sha256(value + blinder).digest()
    if "0x" + commitment.hex() != entry["commitment"]:
        raise SystemExit("a commitment in the witness is not SHA256(value || blinder)")
    return value, blinder


def toml_array(values) -> str:
    return "[" + ", ".join(f'"{v}"' for v in values) + "]"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("witness", type=pathlib.Path)
    parser.add_argument("--out", type=pathlib.Path)
    args = parser.parse_args()

    doc = json.loads(args.witness.read_text())
    witness = doc.get("identity_link_witness", doc)
    platform = witness["platform"].upper()

    bearer, blinder_token = opened(witness["token_bearer"])
    identity_bearer, blinder_identity = opened(witness["identity_bearer"])
    if bearer != identity_bearer:
        raise SystemExit("the two sessions carry different bearers")
    user_id, blinder_id = opened(witness["id"])
    handle, blinder_handle = opened(witness["handle"])

    max_id = int(table_constant(f"MAX_ID_{platform}"))
    max_handle = int(table_constant(f"MAX_HANDLE_{platform}"))
    id_tag = table_bytes(f"USER_ID_TAG_{platform}")
    handle_tag = table_bytes(f"HANDLE_TAG_{platform}")
    folded = bytes(b + 0x20 if 0x41 <= b <= 0x5A else b for b in handle)

    def commitment(entry) -> bytes:
        return bytes.fromhex(entry["commitment"].removeprefix("0x"))

    lines = [
        f"bearer = {toml_array(padded(bearer, MAX_BEARER))}",
        f'bearer_len = "{len(bearer)}"',
        f"blinder_token = {toml_array(blinder_token)}",
        f"blinder_identity = {toml_array(blinder_identity)}",
        f"id = {toml_array(padded(user_id, max_id))}",
        f'id_len = "{len(user_id)}"',
        f"blinder_id = {toml_array(blinder_id)}",
        f"handle = {toml_array(padded(handle, max_handle))}",
        f'handle_len = "{len(handle)}"',
        f"blinder_handle = {toml_array(blinder_handle)}",
        f"token_commitment = {toml_array(commitment(witness['token_bearer']))}",
        f"identity_commitment = {toml_array(commitment(witness['identity_bearer']))}",
        f"id_commitment = {toml_array(halves(commitment(witness['id'])))}",
        f"handle_commitment = {toml_array(halves(commitment(witness['handle'])))}",
        f"id_node = {toml_array(halves(hashlib.sha256(id_tag + user_id).digest()))}",
        f"handle_node = {toml_array(halves(hashlib.sha256(handle_tag + folded).digest()))}",
    ]
    text = "\n".join(lines) + "\n"
    if args.out:
        args.out.write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
