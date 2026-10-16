#!/usr/bin/env python3
"""Write a bearer-link Prover.toml from a synthetic X or GitHub
witness such as fixtures/*-identity-link-witness.json. Public inputs are
computed with hashlib, independently of the circuit.

Usage:
  scripts/identity-link-witness.py <session fixture> [--out Prover.toml]
"""
from __future__ import annotations

import argparse
import functools
import hashlib
import json
import pathlib
import sys

sys.dont_write_bytecode = True
import identity_table  # noqa: E402  (beside this script)


# The platforms bearer-link proves.
PLATFORMS = ("x", "github")


def synthetic_witness(path: pathlib.Path) -> dict:
    """The witness in `path`, a session file marked `"synthetic": true`."""
    doc = json.loads(path.read_text())
    provenance = doc.get("provenance") if isinstance(doc, dict) else None
    if not (isinstance(provenance, dict) and provenance.get("synthetic") is True
            and isinstance(doc.get("identity_link_witness"), dict)):
        raise SystemExit(
            f"{path}: not a synthetic session file (an `identity_link_witness` object "
            'beside `"provenance": {"synthetic": true}`); only synthetic fixtures are witnessed here'
        )
    return doc["identity_link_witness"]


def opened(witness: dict, name: str) -> tuple[bytes, bytes, bytes]:
    """The entry's value, blinder and the commitment they open."""
    entry = witness.get(name)
    if not isinstance(entry, dict) or not {"value", "blinder", "commitment"} <= entry.keys():
        raise SystemExit(f"witness entry `{name}` needs value, blinder and commitment")
    value = entry["value"].encode()
    blinder = bytes.fromhex(entry["blinder"].removeprefix("0x"))
    width = identity_table.integer("BLINDER_LEN", identity_table.LIB)
    if len(blinder) != width:
        raise SystemExit(f"witness entry `{name}`: the blinder is {len(blinder)} bytes; the circuit takes {width}")
    commitment = hashlib.sha256(value + blinder).digest()
    if "0x" + commitment.hex() != entry["commitment"]:
        raise SystemExit(
            f"witness entry `{name}`: commitment is not SHA256(value || blinder); "
            "check the fixture was not edited"
        )
    return value, blinder, commitment


toml_array = functools.partial(identity_table.toml_array, quoted=True)


def source_label(path: pathlib.Path) -> str:
    """The witness path as the header names it: repo-relative, else its name."""
    try:
        return str(path.resolve().relative_to(identity_table.ROOT))
    except ValueError:
        return path.name


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("witness", type=pathlib.Path)
    parser.add_argument("--out", type=pathlib.Path)
    args = parser.parse_args()

    witness = synthetic_witness(args.witness)

    platform = witness.get("platform")
    if platform not in PLATFORMS:
        raise SystemExit(
            f"{args.witness}: platform {platform!r} has no bearer-link circuit; "
            f"this script writes witnesses for {', '.join(PLATFORMS)} only"
        )
    suffix = platform.upper()

    bearer, blinder_token, token_commitment = opened(witness, "token_bearer")
    identity_bearer, blinder_identity, identity_commitment = opened(witness, "identity_bearer")
    if bearer != identity_bearer:
        raise SystemExit(
            "witness entries `token_bearer` and `identity_bearer` carry different bearers; "
            "both sessions of one ceremony must use the same token"
        )
    user_id, blinder_id, id_commitment = opened(witness, "id")
    handle, blinder_handle, handle_commitment = opened(witness, "handle")

    max_bearer = identity_table.integer("MAX_BEARER_LEN", identity_table.LIB)
    if len(bearer) > max_bearer:
        raise SystemExit(
            f"{args.witness}: the bearer is {len(bearer)} bytes; the bearer-link circuit "
            f"caps it at {max_bearer} (MAX_BEARER_LEN in lib/identity/src/lib.nr)"
        )
    max_id = identity_table.integer(f"MAX_ID_{suffix}")
    max_handle = identity_table.integer(f"MAX_HANDLE_{suffix}")
    id_tag = identity_table.byte_array(f"USER_ID_TAG_{suffix}")
    handle_tag = identity_table.byte_array(f"HANDLE_TAG_{suffix}")
    folded = identity_table.fold(handle)

    lines = [
        f"# Written by scripts/identity-link-witness.py from {source_label(args.witness)}:",
        f"# a synthetic {platform} ceremony witness. scripts/check-verifiers.sh proves it.",
        f"bearer = {toml_array(identity_table.padded('token_bearer', bearer, max_bearer))}",
        f'bearer_len = "{len(bearer)}"',
        f"blinder_token = {toml_array(blinder_token)}",
        f"blinder_identity = {toml_array(blinder_identity)}",
        f"id = {toml_array(identity_table.padded('id', user_id, max_id))}",
        f'id_len = "{len(user_id)}"',
        f"blinder_id = {toml_array(blinder_id)}",
        f"handle = {toml_array(identity_table.padded('handle', handle, max_handle))}",
        f'handle_len = "{len(handle)}"',
        f"blinder_handle = {toml_array(blinder_handle)}",
        f"token_commitment = {toml_array(identity_table.halves(token_commitment))}",
        f"identity_commitment = {toml_array(identity_table.halves(identity_commitment))}",
        f"id_commitment = {toml_array(identity_table.halves(id_commitment))}",
        f"handle_commitment = {toml_array(identity_table.halves(handle_commitment))}",
        f"id_node = {toml_array(identity_table.halves(hashlib.sha256(id_tag + user_id).digest()))}",
        f"handle_node = {toml_array(identity_table.halves(hashlib.sha256(handle_tag + folded).digest()))}",
        f'id_tag = "{identity_table.packed_tag(id_tag)}"',
        f'id_tag_len = "{len(id_tag)}"',
        f'handle_tag = "{identity_table.packed_tag(handle_tag)}"',
        f'handle_tag_len = "{len(handle_tag)}"',
    ]
    text = "\n".join(lines) + "\n"
    if args.out is None:
        sys.stdout.write(text)
    else:
        args.out.write_text(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
