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
  signed, so whoever holds them can link that record to the account for as
  long as the record exists, after the bearer is revoked too. So does the
  Prover.toml written from it: --out is required, must end in `.toml` with no
  other `.` in the name, must lie outside every git work tree or be ignored
  by the one it is in, and is written with mode 0600; nothing goes to stdout.
  A path counts as inside a work tree unless git states it is in no
  repository and no parent directory holds a `.git` entry. The script prints,
  on stderr, how to prove it without leaving a copy in the repo.

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
import hashlib
import json
import os
import pathlib
import shlex
import subprocess
import sys

sys.dont_write_bytecode = True
import identity_table  # noqa: E402  (beside this script)


# The platforms with a bearer-link circuit, circuits/bearer-link-<platform>.
PLATFORMS = ("x", "github")


def halves(digest: bytes) -> list[str]:
    return [str(int.from_bytes(digest[:16], "big")), str(int.from_bytes(digest[16:], "big"))]


def padded(name: str, value: bytes, size: int) -> list[int]:
    if len(value) > size:
        raise SystemExit(f"witness entry `{name}`: {len(value)} bytes do not fit the circuit's {size}-byte buffer")
    return list(value) + [0] * (size - len(value))


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


def toml_array(values) -> str:
    return "[" + ", ".join(f'"{v}"' for v in values) + "]"


def git(directory: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["git", "-C", str(directory), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            # git's messages are matched below; keep them untranslated.
            env={**os.environ, "LC_ALL": "C"},
        )
    except FileNotFoundError:
        raise SystemExit("git is required to check where a secret witness's --out lies; install git") from None


def outside_every_work_tree(directory: pathlib.Path) -> bool:
    """True only when git says `directory` is in no repository and no parent
    holds a `.git` entry. Anything git cannot answer counts as inside."""
    probe = git(directory, "rev-parse", "--is-inside-work-tree")
    if probe.returncode == 0 or "not a git repository" not in probe.stderr:
        return False
    return not any((d / ".git").exists() for d in (directory, *directory.parents))


def refuse_secret_destination(out: pathlib.Path | None) -> None:
    """Refuse every --out a secret Prover.toml could leak from.

    A path counts as inside a git work tree unless git states that its
    directory is in no repository and no parent directory holds a `.git`
    entry; dubious ownership, a broken repository or a missing answer count
    as inside. Inside, only a path the work tree's ignore rules match is
    accepted; a tracked path never matches them, so it is refused too.
    """
    if out is None:
        raise SystemExit(
            "the witness is secret (it holds a live bearer): "
            "pass --out <file>.toml outside the repo; it is never written to stdout"
        )
    if out.suffix != ".toml":
        raise SystemExit(f"{out}: nargo reads only <name>.toml; pass --out a path ending in .toml")
    if "." in out.stem:
        raise SystemExit(
            f"{out}: nargo replaces the last `.` suffix of the name it is given, so it would "
            f"read {out.with_suffix('').with_suffix('.toml')} instead; "
            "pass --out a name with no `.` before `.toml`, e.g. x.toml"
        )
    parent = out.resolve().parent
    if not parent.is_dir():
        raise SystemExit(f"{parent} is not a directory; create it or pass --out into an existing one")
    if outside_every_work_tree(parent):
        return
    if git(parent, "check-ignore", "-q", "--", out.name).returncode == 0:
        return
    raise SystemExit(
        f"{out} may be in a git work tree (git places it in one, a parent directory holds `.git`, "
        "or git cannot tell) and no ignore rule matches it, and the witness holds a live bearer: "
        "pass --out a path outside any git work tree, e.g. in a directory from `mktemp -d`"
    )


def proving_instructions(out: pathlib.Path, circuit: pathlib.Path) -> str:
    """The commands that prove `out` without writing into the repo.

    `refuse_secret_destination` has refused a stem with a `.`, so nargo's
    `-p <stem>` reads `<stem>.toml`, which is `out`, and the witness name
    `<stem>` becomes `<stem>.gz`.
    """
    stem = out.resolve().with_suffix("")
    package = identity_table.package(circuit)
    artifacts = identity_table.ROOT / "artifacts" / circuit.name
    witness = stem.with_name(stem.name + ".gz")
    proof = stem.with_name(stem.name + "-proof")
    q = shlex.quote
    return (
        f"wrote {out} (mode 0600). It holds a live bearer and the blinders that link the\n"
        "signed record to the account. Prove it without leaving a copy in the repo\n"
        "(the bb step reads the artifacts scripts/build.sh writes):\n"
        f"  (umask 077 && cd {q(str(circuit))} && nargo execute -p {q(str(stem))} {q(str(stem))})\n"
        f"  (umask 077 && bb prove -b {q(str(artifacts / (package + '.json')))} -w {q(str(witness))} "
        f"-k {q(str(artifacts / 'vk'))} -o {q(str(proof))} -t evm)\n"
        f"nargo reads {out.resolve()} and writes the solved witness to {witness}.\n"
        f"Without the last argument it writes {circuit}/target/{package}.gz instead,\n"
        "keeping the mode of any earlier file there: delete that file after proving.\n"
        f"Once the proof is made: rm -f {q(str(out.resolve()))} {q(str(witness))}\n"
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

    witness, secret = classified(args.witness)
    # A secret witness holds the live bearer; so does the Prover.toml written
    # from it. Refuse every path that would leak it before writing anything.
    if secret:
        refuse_secret_destination(args.out)

    platform = witness.get("platform")
    if platform not in PLATFORMS:
        raise SystemExit(
            f"{args.witness}: platform {platform!r} has no bearer-link circuit; "
            f"this script writes witnesses for {', '.join(PLATFORMS)} only"
        )
    circuit = identity_table.ROOT / "circuits" / f"bearer-link-{platform}"
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
        sys.stderr.write(proving_instructions(args.out, circuit))
    else:
        args.out.write_text(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
