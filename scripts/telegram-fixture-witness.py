#!/usr/bin/env python3
"""Write circuits/oidc-telegram/Prover*.toml: Telegram-shaped ID tokens signed
by the synthetic RSA-2048 key of scripts/oidc_fixture.py. Public
inputs are computed with hashlib, independently of the circuit.

With --check, execute those witnesses and the reject cases below against the
circuit instead of writing them: every accept must solve, every reject must
fail with its expected assertion. CHECK_JOBS (default 2) caps the
noir-execute processes run at once.

Usage: python3 -I scripts/telegram-fixture-witness.py [--check]
"""
from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import functools
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))  # -I drops it
import identity_table as it  # noqa: E402
import oidc_fixture  # noqa: E402
from oidc_fixture import DIGEST, D, N, Header, b64url, compact_json, pkcs1_sha256  # noqa: E402

CIRCUIT = it.ROOT / "circuits" / "oidc-telegram"
MAIN = CIRCUIT / "src" / "main.nr"
ARTIFACT = CIRCUIT / "target" / "oidc_telegram.json"
SIGNING_INPUT_MAX = it.integer("SIGNING_INPUT_MAX", MAIN)
NUM_LIMBS, MOD_BITS = oidc_fixture.rsa_layout(MAIN)
limbs = functools.partial(oidc_fixture.limbs, count=NUM_LIMBS)
# Each claim's window: whole payload groups from the one holding its offset.
WINDOWS = {k: it.integer(f"{k.upper()}_WINDOW", MAIN) for k in ("iss", "aud", "iat", "id", "username", "nonce")}
ID_TAG, HANDLE_TAG = it.byte_array("USER_ID_TAG_TELEGRAM"), it.byte_array("HANDLE_TAG_TELEGRAM")
PUBLIC = [("authorization_digest", 32), ("audience_hash", 2), ("id_node", 2), ("handle_node", 2), ("iat", 1),
          ("modulus", NUM_LIMBS)]

IAT, AUD, USERNAME = 1893452400, "7000000001", "Brynn_QX"
HEAD = b64url(compact_json(Header(kid="oidc-1")))
NONCE = b64url(DIGEST).decode()


@dataclasses.dataclass(frozen=True)
class Claims:
    """The ID token's claims, in the order Telegram writes them; `None` drops one."""

    sub: str = "zq-fixture-sub"
    aud: str = AUD
    exp: int = IAT + 30
    iat: int = IAT
    iss: str = "https://oauth.telegram.org"
    name: str = "Brynn Lowther"
    given_name: str = "Brynn"
    family_name: str = "Lowther"
    picture: str = "https://t.me/i/userpic/320/fixture.jpg"
    preferred_username: str | None = USERNAME
    id: str = "7051836294"
    nonce: str = NONCE


def encode(c: Claims, reverse: bool = False) -> bytes:
    """JSON as Telegram emits it: compact, non-ASCII as \\uXXXX, `/` as `\\/`.
    `reverse` writes the claims in reverse order."""
    items = [(k, v) for k, v in dataclasses.asdict(c).items() if v is not None]
    return json.dumps(dict(items[::-1] if reverse else items), separators=(",", ":")).replace("/", "\\/").encode()


@dataclasses.dataclass(frozen=True)
class Witness:
    """The circuit's inputs, in Prover.toml's order."""

    signing_input: list[int]
    signing_input_len: int
    header_b64_len: int
    iss_offset: int
    aud_offset: int
    audience_len: int
    iat_offset: int
    iat_len: int
    id_offset: int
    id_len: int
    username_offset: int
    username_len: int
    nonce_offset: int
    signature: list[str]
    redc: list[str]
    authorization_digest: list[int]
    audience_hash: list[str]
    id_node: list[str]
    handle_node: list[str]
    iat: int
    modulus: list[str]
    iss_window: list[int] = dataclasses.field(default_factory=list)
    aud_window: list[int] = dataclasses.field(default_factory=list)
    iat_window: list[int] = dataclasses.field(default_factory=list)
    id_window: list[int] = dataclasses.field(default_factory=list)
    username_window: list[int] = dataclasses.field(default_factory=list)
    nonce_window: list[int] = dataclasses.field(default_factory=list)


def buf(value: bytes | list, size: int) -> list[int]:
    """`value` in a `size` buffer: zero tail, truncated when longer (a reject)."""
    return list(value[:size]) + [0] * (size - len(value[:size]))


def sha256_halves(data: bytes) -> list[str]:
    return it.hex_halves(hashlib.sha256(data).digest())


def witness(c: Claims, payload: bytes | None = None, **over) -> Witness:
    """The circuit inputs for token `c` (or raw `payload`), then `over` replaced;
    each `<claim>_offset` in `over` moves that claim's window."""
    payload = encode(c) if payload is None else payload
    si = HEAD + b"." + b64url(payload)
    sig = pkcs1_sha256(si, N, D)
    at = lambda k: max(payload.find(f'"{k}":'.encode()), 1)  # noqa: E731  (a missing claim: 1)
    user = (USERNAME if c.preferred_username is None else c.preferred_username).encode()
    uid, aud = c.id.encode(), c.aud.encode()
    w = Witness(
        signing_input=buf(si, SIGNING_INPUT_MAX), signing_input_len=len(si), header_b64_len=len(HEAD),
        iss_offset=at("iss"), aud_offset=at("aud"), audience_len=len(aud), iat_offset=at("iat"),
        iat_len=len(str(c.iat)), id_offset=at("id"), id_len=len(uid), username_offset=at("preferred_username"),
        username_len=len(user), nonce_offset=at("nonce"),
        signature=limbs(sig), redc=limbs(oidc_fixture.redc(N, MOD_BITS)),
        authorization_digest=list(DIGEST), audience_hash=sha256_halves(aud),
        id_node=sha256_halves(ID_TAG + uid), handle_node=sha256_halves(HANDLE_TAG + it.fold(user)), iat=int(c.iat),
        modulus=limbs(N),
    )
    w = dataclasses.replace(w, **over)
    group = {k: getattr(w, f"{k}_offset") // 3 * 3 for k in WINDOWS}
    return dataclasses.replace(w, **{f"{k}_window": buf(payload[group[k]:group[k] + size], size)
                                     for k, size in WINDOWS.items()})


def toml(w: Witness, comment: str) -> str:
    lines = [f"# Written by scripts/telegram-fixture-witness.py: {comment}"]
    lines += [f"{k} = {it.toml_array(v)}" if isinstance(v, list) else f'{k} = "{v}"'
              for k, v in dataclasses.asdict(w).items()]
    return "\n".join(lines) + "\n"


def worst() -> Claims:
    """The largest real token: a 20-digit sub, 64+64 \\uXXXX-escaped names,
    a 74-char userpic URL, a 32-byte username, a 20-digit id."""
    g, f = "Ж" * 64, "й" * 64
    return Claims(sub="9" * 20, name=f"{g} {f}", given_name=g, family_name=f,
                  picture="https://t.me/i/userpic/320/" + "P" * 43 + ".jpg", preferred_username="A" * 31 + "z",
                  id="9" * 20)


def fill(c: Claims, size: int) -> Claims:
    """`c` with `picture` padded to a `size`-byte signing input."""
    pad = (size - len(HEAD) - 1) * 3 // 4 - len(encode(c))
    return dataclasses.replace(c, picture=c.picture + "p" * pad)


def accepts() -> dict[str, tuple[Witness, str]]:
    assert witness(worst()).signing_input_len <= SIGNING_INPUT_MAX
    assert witness(Claims(aud="1", iat=7)).audience_len == 1 == witness(Claims(iat=7)).iat_len
    big = witness(fill(worst(), SIGNING_INPUT_MAX))
    assert big.signing_input_len == SIGNING_INPUT_MAX
    reordered = Claims(preferred_username="a-B4", id="01234567890123456789")
    return {
        "Prover": (witness(Claims()), "the short token; username Brynn_QX folds to brynn_qx."),
        "Prover-max": (big, f"the largest real token padded to a {SIGNING_INPUT_MAX}-byte signing input."),
        "Prover-reordered": (witness(reordered, encode(reordered, reverse=True)),
                             "claims reversed; a 4-byte username with '-', a 20-digit id with a leading zero."),
    }


# A claim window's assertions, named after its claim.
PAT, VALUE, CLOSE = "{} claim pattern mismatch", "{} value not closed", "{} claim not followed by ',' or '}}'"
WINDOW, LONG = "{} window does not match the signed input", "{} value longer than its buffer"
WINDOW_START = "{} window starts outside the payload"
# noir_rsa's check carries no message.
RSA = "Failed to solve program: 'Cannot satisfy constraint'"


def rejects() -> dict[str, tuple[Witness, str]]:
    """Each reject and the assertion it must fail."""
    s = Claims()
    base, rep = witness(s), dataclasses.replace
    raw = lambda old, new, **over: witness(s, encode(s).replace(old, new), **over)  # noqa: E731
    other = witness(Claims(id="5000000002"))
    with_id = lambda i: witness(Claims(id=i))  # noqa: E731
    with_user = lambda u: witness(Claims(preferred_username=u))  # noqa: E731
    forged = Claims(name='Bob","id":"999')
    forged_g = Claims(given_name="Bob&quot;,&quot;id&quot;:&quot;999")
    fp, fgp = encode(forged), encode(forged_g)
    nouser = Claims(preferred_username=None, name="Brynn_QX")
    # The byte closing iss, which only the signature fixes, turned from ':' to ','.
    iss_key = raw(b'org",', b'org":')
    iss_window = list(iss_key.iss_window)
    iss_window[encode(s).index(b'org"') + 4 - iss_key.iss_offset // 3 * 3] = ord(",")
    aud_q = b'7000000001","x":"y'
    user_q = b'Ali"ce_'
    # A last claim `"uid":"999"`, whose suffix reads as `"id":"999"`.
    uid = encode(s)[:-1] + b',"uid":"999"}'
    # Stray base64url characters signed after the payload, leaving it 1 mod 4 long.
    si = HEAD + b"." + b64url(encode(s))
    si += b"A" * ((len(HEAD) + 2 - len(si)) % 4)
    return {
        "bad-signature": (rep(base, signature=limbs(pkcs1_sha256(b"x", N, D))), RSA),
        "payload-not-signed": (rep(other, signing_input=base.signing_input, signature=base.signature),
                               WINDOW.format("id")),
        "iss-google": (witness(Claims(iss="https://accounts.google.com")), PAT.format("iss")),
        "iss-unescaped": (raw(b"https:\\/\\/oauth", b"https://oauth"), PAT.format("iss")),
        "iss-suffix": (witness(Claims(iss="https://oauth.telegram.org.evil")), PAT.format("iss")),
        "id-forged-in-name": (witness(forged, id_offset=fp.index(b'\\"id') + 1, id_len=3,
                                      id_node=sha256_halves(ID_TAG + b"999")), PAT.format("id")),
        # Where `"id":"` starts once each &quot; reads as '"'.
        "id-forged-in-given-name": (witness(forged_g, id_offset=fgp.index(b"&quot;id"), id_len=3,
                                            id_node=sha256_halves(ID_TAG + b"999")), PAT.format("id")),
        "username-missing": (witness(nouser, username_offset=encode(nouser).index(b'"name"')), PAT.format("username")),
        "username-empty": (with_user(""), "handle is empty"),
        "username-33": (with_user("A" * 33), LONG.format("username")),
        "username-escape": (rep(with_user("alicé_tg"), username_len=13,
                                handle_node=sha256_halves(HANDLE_TAG + b"alic\\u00e9_tg")), "handle byte not allowed"),
        "username-quote": (rep(raw(b'"Brynn_QX"', b'"' + user_q + b'"'), username_len=len(user_q),
                               handle_node=sha256_halves(HANDLE_TAG + it.fold(user_q))), "handle byte not allowed"),
        "username-len-short": (rep(base, username_len=7, handle_node=sha256_halves(HANDLE_TAG + b"alice_t")),
                               VALUE.format("username")),
        "handle-node-unfolded": (rep(base, handle_node=sha256_halves(HANDLE_TAG + b"Brynn_QX")),
                                 "handle node mismatch"),
        "id-non-digit": (with_id("12a45"), "id byte not allowed"),
        "id-21-digits": (with_id("123456789012345678901"), LONG.format("id")),
        "id-len-short": (rep(base, id_len=9, id_node=sha256_halves(ID_TAG + b"500000000")), VALUE.format("id")),
        "id-node-other": (rep(base, id_node=sha256_halves(ID_TAG + b"5000000002")), "id node mismatch"),
        "id-window-other": (rep(base, id_window=other.id_window, id_node=other.id_node), WINDOW.format("id")),
        "nonce-other-digest": (witness(Claims(nonce=b64url(hashlib.sha256(DIGEST).digest()).decode())),
                               "nonce does not encode the authorization digest"),
        "nonce-44-chars": (witness(Claims(nonce=NONCE + "A")), VALUE.format("nonce")),
        "nonce-digest-other": (rep(base, authorization_digest=list(hashlib.sha256(DIGEST).digest())),
                               "nonce does not encode the authorization digest"),
        "iat-leading-zero": (rep(raw(f'"iat":{IAT}'.encode(), f'"iat":0{IAT}'.encode()), iat_len=len(str(IAT)) + 1),
                             "leading zero in iat"),
        "iat-quoted": (witness(Claims(iat=str(IAT))), "iat byte not a digit"),
        "iat-other": (rep(base, iat=IAT + 1), "iat mismatch"),
        "aud-other": (rep(base, audience_hash=sha256_halves(b"7000000002")), "audience mismatch"),
        "signing-input-over-max": (witness(fill(worst(), SIGNING_INPUT_MAX + 1)),
                                   "signing input longer than its buffer"),
        "payload-not-after-dot": (rep(base, header_b64_len=base.header_b64_len + 4,
                                      **{f"{k}_offset": getattr(base, f"{k}_offset") - 3 for k in WINDOWS}),
                                  "no '.' before the payload"),
        "payload-empty": (witness(s, b""), WINDOW_START.format("iss")),
        "payload-length-1-mod-4": (rep(base, signing_input=buf(si, SIGNING_INPUT_MAX), signing_input_len=len(si),
                                       signature=limbs(pkcs1_sha256(si, N, D))), "malformed base64url length"),
        "iss-close-unsigned": (rep(iss_key, iss_window=iss_window), WINDOW.format("iss")),
        "iss-as-key": (raw(b'org",', b'org":1,'), CLOSE.format("iss")),
        "id-key-suffix": (witness(s, uid, id_offset=uid.index(b'"uid"') + 1, id_len=3,
                                  id_node=sha256_halves(ID_TAG + b"999")), PAT.format("id")),
        "id-prefix-unquoted": (raw(b'"id":"', b'"id": '), PAT.format("id")),
        "id-closed-by-quote": (raw(b'7051836294",', b'7051836294"",'), CLOSE.format("id")),
        "aud-prefix": (witness(Claims(aud=AUD + "x,y"), audience_len=len(AUD),
                               audience_hash=sha256_halves(AUD.encode())), VALUE.format("aud")),
        "aud-empty": (witness(Claims(aud=""), audience_len=0, audience_hash=sha256_halves(b"")), "aud is empty"),
        "aud-quote": (rep(raw(b'"aud":"7000000001"', b'"aud":"' + aud_q + b'"'), audience_len=len(aud_q),
                          audience_hash=sha256_halves(aud_q)), "aud byte not allowed"),
        "aud-backslash": (witness(Claims(aud="70\\01"), audience_len=6, audience_hash=sha256_halves(b"70\\\\01")),
                          "aud byte not allowed"),
        "iat-empty": (rep(raw(f'"iat":{IAT}'.encode(), b'"iat":'), iat_len=0, iat=0), "iat length"),
        "iat-13-digits": (rep(raw(f'"iat":{IAT}'.encode(), f'"iat":{IAT}123'.encode()), iat_len=13,
                              iat=IAT * 100 + 12), "iat length"),
        "iat-colon-digit": (rep(raw(f'"iat":{IAT}'.encode(), f'"iat":{IAT // 10}:'.encode()), iat=IAT + 10),
                            "iat byte not a digit"),
        "iat-len-short": (rep(base, iat_len=9, iat=IAT // 10), CLOSE.format("iat")),
    }


def run(path: pathlib.Path) -> tuple[bool, str]:
    r = subprocess.run(["noir-execute", "execute", "-a", str(ARTIFACT), "-p", str(path)], capture_output=True, text=True)
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def check(tmp: pathlib.Path, files: list[pathlib.Path]) -> int:
    if shutil.which("noir-execute") is None:
        raise SystemExit("noir-execute not on PATH; noirup installs it beside nargo")
    subprocess.run(["nargo", "compile", "--silence-warnings"], cwd=CIRCUIT, check=True)
    abi = json.loads(ARTIFACT.read_text())["abi"]["parameters"]
    got = [(p["name"], p["type"].get("length", 1)) for p in abi if p["visibility"] == "public"]
    bad = [] if got == PUBLIC else [f"public inputs {got}, want {PUBLIC}"]
    cases = rejects()
    for name, (w, _) in cases.items():
        (tmp / f"reject-{name}.toml").write_text(toml(w, name))
    with concurrent.futures.ThreadPoolExecutor(int(os.environ.get("CHECK_JOBS", "2"))) as pool:
        accepted = list(pool.map(run, files))
        rejected = list(pool.map(run, (tmp / f"reject-{name}.toml" for name in cases)))
    bad += [f"accept {p.name}: {out[-300:]}" for p, (ok, out) in zip(files, accepted) if not ok]
    for (name, (_, want)), (ok, out) in zip(cases.items(), rejected):
        if ok or (want if want == RSA else f"Assertion failed: {want}") not in out:
            bad.append(f"reject {name}: want {want!r}, got {'ok' if ok else out[-300:]}")
    print("\n".join(bad) or "every accept solves; every reject fails its expected assertion")
    return 1 if bad else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=pathlib.Path, default=CIRCUIT, help="directory for Prover*.toml")
    parser.add_argument("--check", action="store_true", help="execute accepts and rejects with noir-execute; write nothing")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp) if args.check else args.out.resolve()
        files = []
        for name, (w, comment) in accepts().items():
            files.append(out / f"{name}.toml")
            files[-1].write_text(toml(w, comment))
        return check(out, files) if args.check else 0


if __name__ == "__main__":
    raise SystemExit(main())
