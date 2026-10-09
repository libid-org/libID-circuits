#!/usr/bin/env python3
"""Write a bearer-link-x or bearer-link-github Prover.toml from an
identity-link witness.

The witness is what libid-rs writes beside a ceremony record: the bearer, the
id and the handle as the platform sent them, each with the blinder of its
commitment. It is secret unless the file says otherwise, never by file name:

- synthetic: a session file whose `identity_link_witness` member holds the
  witness and whose `provenance` is an object with `"synthetic": true`, as in
  this repo's fixtures/*-identity-link-witness.json. Its Prover.toml may go
  to stdout or any path.
- secret: everything else, a bare witness (`platform`, `token_bearer`, ... at
  the top level, what a real capture writes with `--example
  capture_ceremony`) or a session file without that marker. It holds a live
  bearer, and its blinders open the id and handle commitments the notary
  signed, so whoever holds them can link that record to the account, after
  the bearer is revoked too. So does the Prover.toml written from it: --out
  is required, the file is written with mode 0600 (a symlink is refused), and
  nothing goes to stdout. Write it outside the repo and delete it, and the
  solved witness, after proving.

The platform must be `x` or `github`, the platforms with a bearer-link
circuit. The public inputs are computed here, with hashlib, from the raw
values: each commitment is SHA256(value || blinder) and must equal the one the
witness states (which libid-rs checked against the signed record); the nodes
are SHA256(tag || id) and SHA256(tag || folded handle). The circuit computes
the same things its own way; a disagreement fails `nargo execute`.

Usage:
  scripts/identity-link-witness.py <session fixture | witness.json> [--out Prover.toml]
"""
from __future__ import annotations

import argparse
import functools
import hashlib
import json
import os
import pathlib
import sys

sys.dont_write_bytecode = True
import identity_table  # noqa: E402  (beside this script)


# The platforms with a bearer-link circuit, circuits/bearer-link-<platform>.
PLATFORMS = ("x", "github")


def classified(path: pathlib.Path) -> tuple[dict, bool]:
    """The witness in `path` and whether it is secret.

    Only a session file whose `provenance` is an object with `"synthetic":
    true` is synthetic; every other witness, bare or session-shaped, is
    secret.
    """
    doc = json.loads(path.read_text())
    if not isinstance(doc, dict):
        doc = {}
    if "identity_link_witness" in doc:
        provenance = doc.get("provenance")
        synthetic = isinstance(provenance, dict) and provenance.get("synthetic") is True
        witness = doc["identity_link_witness"]
    elif "token_bearer" in doc:
        synthetic, witness = False, doc
    else:
        raise SystemExit(
            f"{path}: neither a session file with an `identity_link_witness` member "
            "nor a bare witness with `token_bearer`"
        )
    if not isinstance(witness, dict):
        raise SystemExit(f"{path}: `identity_link_witness` is not a JSON object")
    return witness, not synthetic


def opened(witness: dict, name: str) -> tuple[bytes, bytes]:
    entry = witness[name]
    value = entry["value"].encode()
    blinder = bytes.fromhex(entry["blinder"].removeprefix("0x"))
    commitment = hashlib.sha256(value + blinder).digest()
    if "0x" + commitment.hex() != entry["commitment"]:
        raise SystemExit(
            f"witness entry `{name}`: commitment is not SHA256(value || blinder); "
            "recapture the witness or check it was not edited"
        )
    return value, blinder


toml_array = functools.partial(identity_table.toml_array, quoted=True)


def source_label(path: pathlib.Path) -> str:
    """The witness path as the header names it: repo-relative, else its name."""
    try:
        return str(path.resolve().relative_to(identity_table.ROOT))
    except ValueError:
        return path.name


def write_owner_only(out: pathlib.Path, text: str) -> None:
    """Write `text` to `out`, readable by the owner alone (0600)."""
    try:
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    except OSError as e:
        raise SystemExit(
            f"cannot write {out}: {e.strerror}; pass --out a regular file in an existing directory, not a symlink"
        ) from None
    with os.fdopen(fd, "w") as f:
        # The open mode applies only to a new file; an existing one keeps its
        # mode until this, which runs before any byte is written.
        os.fchmod(f.fileno(), 0o600)
        f.write(text)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("witness", type=pathlib.Path)
    parser.add_argument("--out", type=pathlib.Path)
    args = parser.parse_args()

    witness, secret = classified(args.witness)
    # A secret witness holds the live bearer; so does the Prover.toml written
    # from it, which therefore never goes to stdout.
    if secret and args.out is None:
        raise SystemExit(
            "the witness is secret (it holds a live bearer): "
            "pass --out <file> outside the repo; it is never written to stdout"
        )

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

    max_bearer = identity_table.integer("MAX_BEARER_LEN", identity_table.LIB)
    max_id = identity_table.integer(f"MAX_ID_{suffix}")
    max_handle = identity_table.integer(f"MAX_HANDLE_{suffix}")
    id_tag = identity_table.byte_array(f"USER_ID_TAG_{suffix}")
    handle_tag = identity_table.byte_array(f"HANDLE_TAG_{suffix}")
    folded = identity_table.fold(handle)

    def commitment(entry) -> bytes:
        return bytes.fromhex(entry["commitment"].removeprefix("0x"))

    if secret:
        header = [
            f"# Written by scripts/identity-link-witness.py from {args.witness.name}.",
            "# It holds a live bearer: delete it once the proof is made.",
        ]
    else:
        header = [
            f"# Written by scripts/identity-link-witness.py from {source_label(args.witness)}:",
            f"# a synthetic {witness['platform']} ceremony witness. scripts/check-verifiers.sh proves it.",
        ]
    lines = header + [
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
        f"token_commitment = {toml_array(commitment(witness['token_bearer']))}",
        f"identity_commitment = {toml_array(commitment(witness['identity_bearer']))}",
        f"id_commitment = {toml_array(identity_table.halves(commitment(witness['id'])))}",
        f"handle_commitment = {toml_array(identity_table.halves(commitment(witness['handle'])))}",
        f"id_node = {toml_array(identity_table.halves(hashlib.sha256(id_tag + user_id).digest()))}",
        f"handle_node = {toml_array(identity_table.halves(hashlib.sha256(handle_tag + folded).digest()))}",
    ]
    text = "\n".join(lines) + "\n"
    if args.out is None:
        sys.stdout.write(text)
    elif secret:
        write_owner_only(args.out, text)
        sys.stderr.write(f"wrote {args.out} (mode 0600); it holds a live bearer: delete it after proving\n")
    else:
        args.out.write_text(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
