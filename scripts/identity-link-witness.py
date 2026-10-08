#!/usr/bin/env python3
"""Write a bearer-link-<platform> Prover.toml from an identity-link witness.

The witness is what libid-rs writes beside a ceremony record: the bearer, the
id and the handle as the platform sent them, each with the blinder of its
commitment. It comes in two forms, told apart by content, never by file name:

- a session file whose `identity_link_witness` member holds the witness:
  libid-rs' synthetic ceremony fixtures (`cargo run -p libid-tlsn --example
  ceremony_fixtures`) and this repo's fixtures/*-identity-link-witness.json
  copies of them. Synthetic: the Prover.toml may go to stdout or any path.
- a bare witness, `platform`, `token_bearer`, ... at the top level: what a
  real capture writes (`--example capture_ceremony`). It holds a live bearer,
  and its blinders open the id and handle commitments the notary signed, so
  whoever holds them can link that record to the account for as long as the
  record exists, after the bearer is revoked too. It is secret whatever its
  name, and so is the Prover.toml written from it: --out is required, must end
  in `.toml`, must lie outside every git work tree or be ignored by the one
  it is in, and is written with mode 0600; nothing goes to stdout. The script
  prints, on stderr, how to prove it without leaving a copy in the repo.

The public inputs are computed here, with hashlib, from the raw values: each
commitment is SHA256(value || blinder) and must equal the one the witness
states (which libid-rs checked against the signed record); the nodes are
SHA256(tag || id) and SHA256(tag || folded handle). The circuit computes the
same things its own way; a disagreement fails `nargo execute`.

Usage:
  scripts/identity-link-witness.py <session fixture | witness.json> [--out Prover.toml]
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


def git(directory: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["git", "-C", str(directory), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except FileNotFoundError:
        raise SystemExit("git is required to check where a secret witness's --out lies; install git") from None


def refuse_secret_destination(out: pathlib.Path | None) -> None:
    """Refuse every --out a secret Prover.toml could leak from.

    Inside a git work tree only a path its ignore rules match is accepted; a
    tracked path never matches them, so it is refused too.
    """
    if out is None:
        raise SystemExit(
            "the witness is a bare capture and holds a live bearer: "
            "pass --out <file>.toml outside the repo; it is never written to stdout"
        )
    if out.suffix != ".toml":
        raise SystemExit(f"{out}: nargo reads only <name>.toml; pass --out a path ending in .toml")
    parent = out.resolve().parent
    if not parent.is_dir():
        raise SystemExit(f"{parent} is not a directory; create it or pass --out into an existing one")
    inside = git(parent, "rev-parse", "--is-inside-work-tree")
    if inside.returncode != 0 or inside.stdout.strip() != "true":
        return
    if git(parent, "check-ignore", "-q", "--", out.name).returncode == 0:
        return
    top = git(parent, "rev-parse", "--show-toplevel").stdout.strip()
    raise SystemExit(
        f"{out} is in the git work tree {top} and not ignored by it, and the witness holds a live bearer: "
        "pass --out a path outside any git work tree, e.g. under $XDG_RUNTIME_DIR"
    )


def proving_instructions(out: pathlib.Path, platform: str) -> str:
    stem = out.resolve().with_suffix("")
    circuit = identity_table.ROOT / "circuits" / f"bearer-link-{platform.lower()}"
    return (
        f"wrote {out} (mode 0600). It holds a live bearer and the blinders that link the\n"
        "signed record to the account. Prove it without leaving a copy in the repo:\n"
        "  umask 077\n"
        f"  (cd {circuit} && nargo execute -p {stem} {stem})\n"
        f"nargo reads {stem}.toml and writes the solved witness to {stem}.gz.\n"
        f"Without the last argument it writes {circuit}/target/<package>.gz instead,\n"
        "keeping the mode of any earlier file there: delete that file after proving.\n"
        f"Delete {stem}.toml and {stem}.gz once the proof is made.\n"
    )


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

    doc = json.loads(args.witness.read_text())
    if "identity_link_witness" in doc:
        witness, secret = doc["identity_link_witness"], False
    elif "token_bearer" in doc:
        witness, secret = doc, True
    else:
        raise SystemExit(
            f"{args.witness}: neither a session file with an `identity_link_witness` member "
            "nor a bare witness with `token_bearer`"
        )
    # A bare witness holds the live bearer; so does the Prover.toml written
    # from it. Refuse every path that would leak it before writing anything.
    if secret:
        refuse_secret_destination(args.out)

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
        sys.stderr.write(proving_instructions(args.out, platform))
    else:
        args.out.write_text(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
