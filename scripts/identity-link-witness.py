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

A `*.secret.json` witness holds a live bearer, and so does the Prover.toml
written from it. For one, --out is required, must not be a file git tracks,
and is written with mode 0600; nothing goes to stdout.

Usage:
  scripts/identity-link-witness.py <witness.json | session fixture> [--out Prover.toml]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys

sys.dont_write_bytecode = True
import identity_table  # noqa: E402  (beside this script)


def halves(digest: bytes) -> list[str]:
    return [str(int.from_bytes(digest[:16], "big")), str(int.from_bytes(digest[16:], "big"))]


def padded(name: str, value: bytes, size: int) -> list[int]:
    if len(value) > size:
        raise SystemExit(f"witness entry `{name}`: {len(value)} bytes do not fit the circuit's {size}-byte buffer")
    return list(value) + [0] * (size - len(value))


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


def toml_array(values) -> str:
    return "[" + ", ".join(f'"{v}"' for v in values) + "]"


def tracked_by_git(path: pathlib.Path) -> bool:
    """Whether git tracks `path`. Outside a work tree nothing is tracked."""
    path = path.resolve()
    try:
        result = subprocess.run(
            ["git", "-C", str(path.parent), "ls-files", "--error-unmatch", "--", path.name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        raise SystemExit("git is required to check that --out is not a tracked file; install git") from None
    return result.returncode == 0


def refuse_secret_destination(out: pathlib.Path | None) -> None:
    if out is None:
        raise SystemExit(
            "the witness is a *.secret.json capture and holds a live bearer: "
            "pass --out <file outside the repo>; it is never written to stdout"
        )
    if tracked_by_git(out):
        raise SystemExit(
            f"{out} is tracked by git and the witness holds a live bearer: "
            "pass --out <file outside the repo>, e.g. under $XDG_RUNTIME_DIR"
        )


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

    # A capture's witness holds the live bearer; so does the Prover.toml
    # written from it. Refuse every path that would leak it before reading.
    secret = args.witness.name.endswith(".secret.json")
    if secret:
        refuse_secret_destination(args.out)

    doc = json.loads(args.witness.read_text())
    witness = doc.get("identity_link_witness", doc)
    platform = witness["platform"].upper()

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
    max_id = identity_table.integer(f"MAX_ID_{platform}")
    max_handle = identity_table.integer(f"MAX_HANDLE_{platform}")
    id_tag = identity_table.byte_array(f"USER_ID_TAG_{platform}")
    handle_tag = identity_table.byte_array(f"HANDLE_TAG_{platform}")
    folded = identity_table.fold(handle)

    def commitment(entry) -> bytes:
        return bytes.fromhex(entry["commitment"].removeprefix("0x"))

    lines = [
        f"bearer = {toml_array(padded('token_bearer', bearer, max_bearer))}",
        f'bearer_len = "{len(bearer)}"',
        f"blinder_token = {toml_array(blinder_token)}",
        f"blinder_identity = {toml_array(blinder_identity)}",
        f"id = {toml_array(padded('id', user_id, max_id))}",
        f'id_len = "{len(user_id)}"',
        f"blinder_id = {toml_array(blinder_id)}",
        f"handle = {toml_array(padded('handle', handle, max_handle))}",
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
    if args.out is None:
        sys.stdout.write(text)
    elif secret:
        write_owner_only(args.out, text)
    else:
        args.out.write_text(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
