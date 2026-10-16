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
    """A witness entry as libid-rs writes it: a value, the blinder beside it
    and the 0x-hex commitment they open."""

    value: str
    blinder: str
    commitment: str

    def plaintext(self) -> bytes:
        return self.value.encode()

    def blinder_bytes(self) -> bytes:
        return bytes.fromhex(self.blinder.removeprefix("0x"))

    def commitment_bytes(self) -> bytes:
        return bytes.fromhex(self.commitment.removeprefix("0x"))

    def check(self, name: str) -> None:
        """Refuse a blinder of another width than the circuit's, or a
        commitment the value and blinder do not open."""
        width = identity_table.integer("BLINDER_LEN", identity_table.LIB)
        blinder = self.blinder_bytes()
        if len(blinder) != width:
            raise SystemExit(f"witness entry `{name}`: the blinder is {len(blinder)} bytes; the circuit takes {width}")
        if hashlib.sha256(self.plaintext() + blinder).digest() != self.commitment_bytes():
            raise SystemExit(
                f"witness entry `{name}`: commitment is not SHA256(value || blinder); "
                "check the fixture was not edited"
            )


@dataclasses.dataclass(frozen=True)
class Witness:
    """An identity-link witness: the platform and the four openings a ceremony commits."""

    platform: str
    token_bearer: Opening
    identity_bearer: Opening
    id: Opening
    handle: Opening

    def check(self) -> None:
        """Refuse a platform bearer-link does not prove, an entry that does
        not open, or two sessions with different bearers."""
        if self.platform not in PROVER_FILES:
            raise SystemExit(
                f"platform {self.platform!r} has no bearer-link circuit; "
                f"this script writes witnesses for {', '.join(PROVER_FILES)} only"
            )
        for name in ("token_bearer", "identity_bearer", "id", "handle"):
            getattr(self, name).check(name)
        if self.token_bearer.value != self.identity_bearer.value:
            raise SystemExit(
                "witness entries `token_bearer` and `identity_bearer` carry different bearers; "
                "both sessions of one ceremony must use the same token"
            )

    def prover_toml(self, source: str) -> str:
        """The bearer-link Prover.toml for this witness; `source` names it in the header."""
        suffix = self.platform.upper()
        bearer = self.token_bearer.plaintext()
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
        user_id = self.id.plaintext()
        handle = self.handle.plaintext()
        folded = identity_table.fold(handle)
        halves = identity_table.halves

        lines = [
            f"# Written by scripts/identity-link-witness.py from {source}:",
            f"# a synthetic {self.platform} ceremony witness. scripts/check-verifiers.sh proves it.",
            f"bearer = {toml_array(identity_table.padded('token_bearer', bearer, max_bearer))}",
            f'bearer_len = "{len(bearer)}"',
            f"blinder_token = {toml_array(self.token_bearer.blinder_bytes())}",
            f"blinder_identity = {toml_array(self.identity_bearer.blinder_bytes())}",
            f"id = {toml_array(identity_table.padded('id', user_id, max_id))}",
            f'id_len = "{len(user_id)}"',
            f"blinder_id = {toml_array(self.id.blinder_bytes())}",
            f"handle = {toml_array(identity_table.padded('handle', handle, max_handle))}",
            f'handle_len = "{len(handle)}"',
            f"blinder_handle = {toml_array(self.handle.blinder_bytes())}",
            f"token_commitment = {toml_array(halves(self.token_bearer.commitment_bytes()))}",
            f"identity_commitment = {toml_array(halves(self.identity_bearer.commitment_bytes()))}",
            f"id_commitment = {toml_array(halves(self.id.commitment_bytes()))}",
            f"handle_commitment = {toml_array(halves(self.handle.commitment_bytes()))}",
            f"id_node = {toml_array(halves(hashlib.sha256(id_tag + user_id).digest()))}",
            f"handle_node = {toml_array(halves(hashlib.sha256(handle_tag + folded).digest()))}",
            f'id_tag = "{identity_table.packed_tag(id_tag)}"',
            f'id_tag_len = "{len(id_tag)}"',
            f'handle_tag = "{identity_table.packed_tag(handle_tag)}"',
            f'handle_tag_len = "{len(handle_tag)}"',
        ]
        return "\n".join(lines) + "\n"


@dataclasses.dataclass(frozen=True)
class Provenance:
    """Where a vendored fixture comes from; `synthetic` marks one made without
    a real account or bearer."""

    synthetic: bool
    source: str


@dataclasses.dataclass(frozen=True)
class Fixture:
    """A vendored witness file, fixtures/<platform>-identity-link-witness.json."""

    provenance: Provenance
    identity_link_witness: Witness

    @classmethod
    def load(cls, path: pathlib.Path) -> Fixture:
        """The fixture in `path`, synthetic and with a witness that checks."""
        fixture = identity_table.of_json(cls, json.loads(path.read_text()), str(path))
        if not fixture.provenance.synthetic:
            raise SystemExit(f"{path}: `provenance.synthetic` is not true; only synthetic fixtures are witnessed here")
        fixture.identity_link_witness.check()
        return fixture


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

    witness = Fixture.load(args.witness).identity_link_witness
    out = args.out or BEARER_LINK / PROVER_FILES[witness.platform]
    out.write_text(witness.prover_toml(source_label(args.witness)))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
