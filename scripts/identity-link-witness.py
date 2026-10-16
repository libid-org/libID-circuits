#!/usr/bin/env python3
"""Write a bearer-link Prover.toml from a synthetic X or GitHub witness such
as fixtures/*-identity-link-witness.json. Public inputs are computed with
hashlib, independently of the circuit.

Usage:
  scripts/identity-link-witness.py <witness> [--out Prover.toml]

Without --out, an X witness writes circuits/bearer-link/Prover.toml and a
GitHub one Prover-github.toml, the files scripts/check-verifiers.sh proves.
"""
from __future__ import annotations

import argparse
import dataclasses
import functools
import hashlib
import json
import pathlib
import sys

sys.dont_write_bytecode = True
import identity_table  # noqa: E402  (beside this script)


# The platforms bearer-link proves, each with its committed prover file.
PROVER_FILES = {"x": "Prover.toml", "github": "Prover-github.toml"}
BEARER_LINK = identity_table.ROOT / "circuits" / "bearer-link"

toml_array = functools.partial(identity_table.toml_array, quoted=True)


@dataclasses.dataclass(frozen=True)
class Opening:
    """A committed value with the blinder that opens its commitment."""

    value: bytes
    blinder: bytes
    commitment: bytes

    @classmethod
    def of(cls, name: str, entry: object) -> Opening:
        """The witness entry `name`, checked to open its own commitment."""
        if not isinstance(entry, dict) or not {"value", "blinder", "commitment"} <= entry.keys():
            raise SystemExit(f"witness entry `{name}` needs value, blinder and commitment")
        opening = cls(
            entry["value"].encode(),
            bytes.fromhex(entry["blinder"].removeprefix("0x")),
            bytes.fromhex(entry["commitment"].removeprefix("0x")),
        )
        width = identity_table.integer("BLINDER_LEN", identity_table.LIB)
        if len(opening.blinder) != width:
            raise SystemExit(
                f"witness entry `{name}`: the blinder is {len(opening.blinder)} bytes; the circuit takes {width}"
            )
        if hashlib.sha256(opening.value + opening.blinder).digest() != opening.commitment:
            raise SystemExit(
                f"witness entry `{name}`: commitment is not SHA256(value || blinder); "
                "check the fixture was not edited"
            )
        return opening


@dataclasses.dataclass(frozen=True)
class Witness:
    """A synthetic identity-link witness: the platform and its four openings."""

    platform: str
    token_bearer: Opening
    identity_bearer: Opening
    user_id: Opening
    handle: Opening

    @classmethod
    def load(cls, path: pathlib.Path) -> Witness:
        """The witness in `path`, a session file marked `"synthetic": true`."""
        doc = json.loads(path.read_text())
        provenance = doc.get("provenance") if isinstance(doc, dict) else None
        witness = doc.get("identity_link_witness") if isinstance(doc, dict) else None
        if not (isinstance(provenance, dict) and provenance.get("synthetic") is True and isinstance(witness, dict)):
            raise SystemExit(
                f"{path}: not a synthetic session file (an `identity_link_witness` object "
                'beside `"provenance": {"synthetic": true}`); only synthetic fixtures are witnessed here'
            )
        platform = witness.get("platform")
        if platform not in PROVER_FILES:
            raise SystemExit(
                f"{path}: platform {platform!r} has no bearer-link circuit; "
                f"this script writes witnesses for {', '.join(PROVER_FILES)} only"
            )
        token_bearer = Opening.of("token_bearer", witness.get("token_bearer"))
        identity_bearer = Opening.of("identity_bearer", witness.get("identity_bearer"))
        if token_bearer.value != identity_bearer.value:
            raise SystemExit(
                "witness entries `token_bearer` and `identity_bearer` carry different bearers; "
                "both sessions of one ceremony must use the same token"
            )
        return cls(
            platform,
            token_bearer,
            identity_bearer,
            Opening.of("id", witness.get("id")),
            Opening.of("handle", witness.get("handle")),
        )

    def prover_toml(self, source: str) -> str:
        """The bearer-link Prover.toml for this witness; `source` names it in the header."""
        suffix = self.platform.upper()
        bearer = self.token_bearer.value
        max_bearer = identity_table.integer("MAX_BEARER_LEN", identity_table.LIB)
        if len(bearer) > max_bearer:
            raise SystemExit(
                f"{source}: the bearer is {len(bearer)} bytes; the bearer-link circuit "
                f"caps it at {max_bearer} (MAX_BEARER_LEN in lib/identity/src/lib.nr)"
            )
        max_id = identity_table.integer(f"MAX_ID_{suffix}")
        max_handle = identity_table.integer(f"MAX_HANDLE_{suffix}")
        id_tag = identity_table.byte_array(f"USER_ID_TAG_{suffix}")
        handle_tag = identity_table.byte_array(f"HANDLE_TAG_{suffix}")
        user_id = self.user_id.value
        handle = self.handle.value
        folded = identity_table.fold(handle)
        halves = identity_table.halves

        lines = [
            f"# Written by scripts/identity-link-witness.py from {source}:",
            f"# a synthetic {self.platform} ceremony witness. scripts/check-verifiers.sh proves it.",
            f"bearer = {toml_array(identity_table.padded('token_bearer', bearer, max_bearer))}",
            f'bearer_len = "{len(bearer)}"',
            f"blinder_token = {toml_array(self.token_bearer.blinder)}",
            f"blinder_identity = {toml_array(self.identity_bearer.blinder)}",
            f"id = {toml_array(identity_table.padded('id', user_id, max_id))}",
            f'id_len = "{len(user_id)}"',
            f"blinder_id = {toml_array(self.user_id.blinder)}",
            f"handle = {toml_array(identity_table.padded('handle', handle, max_handle))}",
            f'handle_len = "{len(handle)}"',
            f"blinder_handle = {toml_array(self.handle.blinder)}",
            f"token_commitment = {toml_array(halves(self.token_bearer.commitment))}",
            f"identity_commitment = {toml_array(halves(self.identity_bearer.commitment))}",
            f"id_commitment = {toml_array(halves(self.user_id.commitment))}",
            f"handle_commitment = {toml_array(halves(self.handle.commitment))}",
            f"id_node = {toml_array(halves(hashlib.sha256(id_tag + user_id).digest()))}",
            f"handle_node = {toml_array(halves(hashlib.sha256(handle_tag + folded).digest()))}",
            f'id_tag = "{identity_table.packed_tag(id_tag)}"',
            f'id_tag_len = "{len(id_tag)}"',
            f'handle_tag = "{identity_table.packed_tag(handle_tag)}"',
            f'handle_tag_len = "{len(handle_tag)}"',
        ]
        return "\n".join(lines) + "\n"


def source_label(path: pathlib.Path) -> str:
    """The witness path as the header names it: repo-relative, else its name."""
    try:
        return str(path.resolve().relative_to(identity_table.ROOT))
    except ValueError:
        return path.name


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("witness", type=pathlib.Path)
    parser.add_argument("--out", type=pathlib.Path, help="default: the platform's committed prover file")
    args = parser.parse_args()

    witness = Witness.load(args.witness)
    out = args.out or BEARER_LINK / PROVER_FILES[witness.platform]
    out.write_text(witness.prover_toml(source_label(args.witness)))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
