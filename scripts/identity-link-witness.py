#!/usr/bin/env python3
"""Write a bearer-link-x or bearer-link-github Prover.toml from a synthetic
identity-link witness.

The input is a session file whose `identity_link_witness` member holds the
witness (the bearer, the id and the handle, each with the blinder of its
commitment) and whose `provenance` is an object with `"synthetic": true`, as
in this repo's fixtures/*-identity-link-witness.json. Anything else is
refused.

The platform must be `x` or `github`, the platforms with a bearer-link
circuit. The public inputs are computed here, with hashlib, from the raw
values: each commitment is SHA256(value || blinder) and must equal the one the
witness states; the nodes are SHA256(tag || id) and SHA256(tag || folded
handle). The circuit computes the same things its own way; a disagreement
fails `nargo execute`.

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


# The platforms with a bearer-link circuit, circuits/bearer-link-<platform>.
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


def opened(witness: dict, name: str) -> tuple[bytes, bytes]:
    entry = witness[name]
    value = entry["value"].encode()
    blinder = bytes.fromhex(entry["blinder"].removeprefix("0x"))
    commitment = hashlib.sha256(value + blinder).digest()
    if "0x" + commitment.hex() != entry["commitment"]:
        raise SystemExit(
            f"witness entry `{name}`: commitment is not SHA256(value || blinder); "
            "check the fixture was not edited"
        )
    return value, blinder


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

    bearer, blinder_token = opened(witness, "token_bearer")
    identity_bearer, blinder_identity = opened(witness, "identity_bearer")
    if bearer != identity_bearer:
        raise SystemExit(
            "witness entries `token_bearer` and `identity_bearer` carry different bearers; "
            "both sessions of one ceremony must use the same token"
        )
    user_id, blinder_id = opened(witness, "id")
    handle, blinder_handle = opened(witness, "handle")

    max_bearer = identity_table.integer(f"MAX_BEARER_LEN_{suffix}", identity_table.LIB)
    if len(bearer) > max_bearer:
        raise SystemExit(
            f"{args.witness}: the bearer is {len(bearer)} bytes; the bearer-link-{platform} circuit "
            f"caps it at {max_bearer} (MAX_BEARER_LEN_{suffix} in lib/identity/src/lib.nr)"
        )
    max_id = identity_table.integer(f"MAX_ID_{suffix}")
    max_handle = identity_table.integer(f"MAX_HANDLE_{suffix}")
    id_tag = identity_table.byte_array(f"USER_ID_TAG_{suffix}")
    handle_tag = identity_table.byte_array(f"HANDLE_TAG_{suffix}")
    folded = identity_table.fold(handle)

    def commitment(entry) -> bytes:
        return bytes.fromhex(entry["commitment"].removeprefix("0x"))

    lines = [
        f"# Written by scripts/identity-link-witness.py from {source_label(args.witness)}:",
        f"# a synthetic {witness['platform']} ceremony witness. scripts/check-verifiers.sh proves it.",
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
        f"token_commitment = {toml_array(identity_table.halves(commitment(witness['token_bearer'])))}",
        f"identity_commitment = {toml_array(identity_table.halves(commitment(witness['identity_bearer'])))}",
        f"id_commitment = {toml_array(identity_table.halves(commitment(witness['id'])))}",
        f"handle_commitment = {toml_array(identity_table.halves(commitment(witness['handle'])))}",
        f"id_node = {toml_array(identity_table.halves(hashlib.sha256(id_tag + user_id).digest()))}",
        f"handle_node = {toml_array(identity_table.halves(hashlib.sha256(handle_tag + folded).digest()))}",
    ]
    text = "\n".join(lines) + "\n"
    if args.out is None:
        sys.stdout.write(text)
    else:
        args.out.write_text(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
