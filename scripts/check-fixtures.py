#!/usr/bin/env python3
"""Check the vendored fixtures against libID-contracts' ceremony session
fixtures: fixtures/{x,github}-identity-link-witness.json hold the sessions'
`identity_link_witness`, and scripts/google-fixture-witness.py's DIGEST is
their `authorization_digest`. CI runs it at the commit contracts.ref pins.

Usage: scripts/check-fixtures.py <libID-contracts checkout>
"""
from __future__ import annotations

import argparse
import dataclasses
import importlib.util
import json
import pathlib
import sys

sys.dont_write_bytecode = True
import identity_table  # noqa: E402  (beside this script)


def sibling(name: str):
    """The script `name` beside this one, as a module."""
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), pathlib.Path(__file__).with_name(f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


identity_link = sibling("identity-link-witness")
google = sibling("google-fixture-witness")


@dataclasses.dataclass(frozen=True)
class Session:
    """The members of a libID-contracts ceremony session fixture this repo vendors."""

    authorization_digest: str
    identity_link_witness: identity_link.Witness

    @classmethod
    def load(cls, path: pathlib.Path) -> Session:
        return identity_table.of_json(cls, json.loads(path.read_text()), str(path))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("contracts", type=pathlib.Path, help="a libID-contracts checkout")
    args = parser.parse_args()
    sessions = args.contracts / "solidity" / "contracts" / "ceremony" / "test" / "fixtures"

    failed = False
    for platform in identity_link.PROVER_FILES:
        session_path = sessions / f"{platform}-ceremony-session.json"
        vendored_path = identity_table.ROOT / "fixtures" / f"{platform}-identity-link-witness.json"
        session = Session.load(session_path)
        vendored = identity_link.Fixture.load(vendored_path)
        if vendored.identity_link_witness != session.identity_link_witness:
            print(f"error: {vendored_path} differs from {session_path}'s identity_link_witness; copy it again", file=sys.stderr)
            failed = True
        if session.authorization_digest != "0x" + google.DIGEST.hex():
            print(
                f"error: scripts/google-fixture-witness.py's DIGEST differs from {session_path}'s "
                f"authorization_digest {session.authorization_digest}",
                file=sys.stderr,
            )
            failed = True
    if failed:
        return 1
    print(f"the vendored fixtures and the Google digest match {sessions}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
