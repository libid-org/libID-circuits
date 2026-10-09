"""The circuits' constants, read from the Noir sources that define them.

`lib/identity/src/table.nr` is generated from libID-contracts'
`solidity/contracts/handles/handles.json`: the platform tags and the buffer
sizes. `lib/identity/src/lib.nr` holds each bearer-link circuit's bearer
cap, and `circuits/oidc-google/src/main.nr` the JWT buffers and the RSA limb
layout.
The witness scripts read them here so no size or tag is written down twice,
and share the encodings below: the fold, the `[high, low]` halves a circuit
takes a 32-byte value as, the zero-padded buffers, and the TOML arrays a
Prover.toml holds them in.
"""
from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
TABLE = ROOT / "lib" / "identity" / "src" / "table.nr"
LIB = ROOT / "lib" / "identity" / "src" / "lib.nr"
OIDC_GOOGLE = ROOT / "circuits" / "oidc-google" / "src" / "main.nr"


def constant(name: str, source: pathlib.Path = TABLE) -> str:
    """The right-hand side of `[pub] global <name>`, whitespace collapsed."""
    # nargo fmt wraps long constants, so read the declaration whole.
    found = re.search(rf"\bglobal\s+{re.escape(name)}\s*:[^=]*=\s*([^;]*);", source.read_text())
    if found is None:
        raise SystemExit(f"{source}: no `global {name}`; regenerate or check the name")
    return " ".join(found.group(1).split())


def integer(name: str, source: pathlib.Path = TABLE) -> int:
    return int(constant(name, source))


def byte_array(name: str, source: pathlib.Path = TABLE) -> bytes:
    inner = constant(name, source).strip("[]")
    return bytes(int(b, 16) for b in inner.split(",") if b.strip())


def fold(value: bytes) -> bytes:
    """A-Z down to a-z, every other byte unchanged: the fold table.nr's HANDLE_BYTES tables apply."""
    return bytes(b + 0x20 if 0x41 <= b <= 0x5A else b for b in value)


def halves(digest: bytes) -> tuple[int, int]:
    """A 32-byte digest as the circuits' `[high, low]` 16-byte big-endian halves."""
    return int.from_bytes(digest[:16], "big"), int.from_bytes(digest[16:], "big")


def padded(name: str, value: bytes, size: int) -> list[int]:
    """`value` in a `size`-byte circuit buffer, the tail zero."""
    if len(value) > size:
        raise SystemExit(f"`{name}`: {len(value)} bytes do not fit the circuit's {size}-byte buffer")
    return list(value) + [0] * (size - len(value))


def toml_array(values, *, quoted: bool = False) -> str:
    """A Prover.toml array. Strings are always quoted, numbers when `quoted`."""
    return "[" + ", ".join(f'"{v}"' if quoted or isinstance(v, str) else str(v) for v in values) + "]"
