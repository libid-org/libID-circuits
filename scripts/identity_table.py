"""The identity circuits' constants, read from the Noir sources that define them.

`lib/identity/src/table.nr` is generated from libid-contracts'
`solidity/contracts/handles/handles.json`: the platform tags and the buffer
sizes. `lib/identity/src/lib.nr` holds the bearer cap. The witness scripts
read both here so no size or tag is written down twice.
"""
from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
TABLE = ROOT / "lib" / "identity" / "src" / "table.nr"
LIB = ROOT / "lib" / "identity" / "src" / "lib.nr"


def constant(name: str, source: pathlib.Path = TABLE) -> str:
    """The right-hand side of `pub global <name>`, whitespace collapsed."""
    # nargo fmt wraps long constants, so read the declaration whole.
    found = re.search(rf"pub global {name}:[^=]*=\s*([^;]*);", source.read_text())
    if found is None:
        raise SystemExit(f"{source}: no `pub global {name}`; regenerate or check the name")
    return " ".join(found.group(1).split())


def integer(name: str, source: pathlib.Path = TABLE) -> int:
    return int(constant(name, source))


def byte_array(name: str, source: pathlib.Path = TABLE) -> bytes:
    inner = constant(name, source).strip("[]")
    return bytes(int(b, 16) for b in inner.split(",") if b.strip())


def fold(value: bytes) -> bytes:
    """A-Z down to a-z, every other byte unchanged: lib.nr's `fold`."""
    return bytes(b + 0x20 if 0x41 <= b <= 0x5A else b for b in value)
