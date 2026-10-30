#!/usr/bin/env python3
"""Write circuits/oidc-telegram/Prover*.toml: Telegram-shaped ID tokens signed
by the synthetic RSA-2048 key of scripts/google-fixture-witness.py. Public
inputs are computed with hashlib, independently of the circuit.

With --check, also execute those witnesses and the reject cases below against
the circuit: every accept must solve, every reject must fail a constraint.

Usage: python3 -I scripts/telegram-fixture-witness.py [--check]
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))  # -I drops it
import identity_table as it  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402

_spec = importlib.util.spec_from_file_location("google_witness", it.ROOT / "scripts" / "google-fixture-witness.py")
google = sys.modules["google_witness"] = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(google)

CIRCUIT = it.ROOT / "circuits" / "oidc-telegram"
MAIN = CIRCUIT / "src" / "main.nr"
# The spec's buffers: the signing input's is the circuit's.
SIGNING_INPUT_MAX, PAYLOAD_JSON_MAX = 2624, 1920
# Each claim's window: whole payload groups from the one holding its offset.
WINDOWS = {k: it.integer(f"{k.upper()}_WINDOW", MAIN) for k in ("iss", "aud", "iat", "id", "username", "nonce")}
ID_TAG, HANDLE_TAG = it.byte_array("USER_ID_TAG_TELEGRAM"), it.byte_array("HANDLE_TAG_TELEGRAM")
PUBLIC = [("authorization_digest", 32), ("audience_hash", 2), ("id_node", 2), ("handle_node", 2), ("iat", 1), ("modulus", 18)]

DIGEST, IAT, AUD = google.DIGEST, 1893452400, "7000000001"
HEADER = {"alg": "RS256", "kid": "oidc-1", "typ": "JWT"}
NONCE = google.b64url(DIGEST).decode()


def claims(**over) -> dict:
    """Telegram's claims in Telegram's order; `None` drops one."""
    c = dict(sub="zq-fixture-sub", aud=AUD, exp=IAT + 30, iat=IAT, iss="https://oauth.telegram.org",
             name="Brynn Lowther", given_name="Brynn", family_name="Lowther",
             picture="https://t.me/i/userpic/320/fixture.jpg", preferred_username="Brynn_QX",
             id="7051836294", nonce=NONCE)
    c.update(over)
    return {k: v for k, v in c.items() if v is not None}


def encode(c: dict) -> bytes:
    """JSON as Telegram emits it: compact, non-ASCII as \\uXXXX, `/` as `\\/`."""
    return json.dumps(c, separators=(",", ":")).replace("/", "\\/").encode()


def buf(value: bytes | list, size: int) -> list[int]:
    """`value` in a `size` buffer: zero tail, truncated when longer (a reject)."""
    return list(value[:size]) + [0] * (size - len(value[:size]))


def halves(data: bytes) -> list[str]:
    return [f"0x{h:032x}" for h in it.halves(hashlib.sha256(data).digest())]


def witness(c: dict, payload: bytes | None = None, header: dict = HEADER, **over) -> dict:
    """The circuit inputs for token `c` (or raw `payload`), then `over` replaced;
    each `<claim>_offset` in `over` moves that claim's window."""
    payload = encode(c) if payload is None else payload
    head = google.b64url(json.dumps(header, separators=(",", ":")).encode())
    si = head + b"." + google.b64url(payload)
    sig = google.pkcs1_sha256(si, google.N, google.D)
    rsa.RSAPublicNumbers(google.E, google.N).public_key().verify(
        sig.to_bytes(256, "big"), si, padding.PKCS1v15(), hashes.SHA256())
    at = lambda k: max(payload.find(f'"{k}":'.encode()), 1)  # noqa: E731  (a missing claim: 1)
    user, uid = str(c.get("preferred_username", "Brynn_QX")).encode(), str(c["id"]).encode()
    w = dict(
        signing_input=buf(si, SIGNING_INPUT_MAX), signing_input_len=len(si), header_b64_len=len(head),
        iss_offset=at("iss"), aud_offset=at("aud"), audience_len=len(AUD), iat_offset=at("iat"),
        iat_len=len(str(IAT)), id_offset=at("id"), id_len=len(uid), username_offset=at("preferred_username"),
        username_len=len(user), nonce_offset=at("nonce"),
        signature=google.limbs(sig), redc=google.limbs((1 << (2 * 2048 + 6)) // google.N),
        authorization_digest=list(DIGEST), audience_hash=halves(AUD.encode()),
        id_node=halves(ID_TAG + uid), handle_node=halves(HANDLE_TAG + it.fold(user)), iat=IAT,
        modulus=google.limbs(google.N),
    )
    w.update(over)
    for k, size in WINDOWS.items():
        g = w[f"{k}_offset"] // 3 * 3
        w[f"{k}_window"] = buf(payload[g:g + size], size)
    return w


def toml(w: dict, comment: str) -> str:
    lines = [f"# Written by scripts/telegram-fixture-witness.py: {comment}"]
    lines += [f"{k} = {it.toml_array(v)}" if isinstance(v, list) else f'{k} = "{v}"' for k, v in w.items()]
    return "\n".join(lines) + "\n"


def worst(extra: int = 0, kid: str = "oidc-1-xxxx") -> tuple[dict, dict]:
    """64+64 escaped names, a 32-byte username, padded by `picture` to a
    1920-byte payload (+`extra`) under a 47-byte header: both buffers full."""
    g, f = "Ж" * 63 + "&quot;", "й" * 64
    c = claims(name=f'{g} "{f}"', given_name=g, family_name=f, preferred_username="A" * 31 + "z", id="1",
               picture="https://t.me/i/")
    c["picture"] += "p" * (PAYLOAD_JSON_MAX + extra - len(encode(c)))
    return c, dict(HEADER, kid=kid)


def accepts() -> dict[str, tuple[dict, str]]:
    c, h = worst()
    big = witness(c, header=h)
    assert (big["signing_input_len"], len(encode(c))) == (SIGNING_INPUT_MAX, PAYLOAD_JSON_MAX)
    reordered = dict(reversed(claims(preferred_username="ab_c5", id="12345678901234567890").items()))
    return {
        "Prover": (witness(claims()), "the short token; username Brynn_QX folds to brynn_qx."),
        "Prover-max": (big, "a 1920-byte payload in a 2624-byte signing input."),
        "Prover-reordered": (witness(reordered), "claims reversed; a 5-byte username, a 20-digit id."),
    }


def rejects() -> dict[str, dict]:
    base, s = witness(claims()), claims()
    raw = lambda old, new: witness(s, encode(s).replace(old, new))  # noqa: E731
    other = witness(claims(id="5000000002"))
    with_id = lambda i: witness(claims(id=i))  # noqa: E731
    with_user = lambda u: witness(claims(preferred_username=u))  # noqa: E731
    forged = claims(name='Bob","id":"999')
    forged_g = claims(given_name="Bob&quot;,&quot;id&quot;:&quot;999")
    fp, fgp = encode(forged), encode(forged_g)
    c, h = worst()
    nouser = claims(preferred_username=None, name="Brynn_QX")
    iss_key = raw(b'org",', b'org":')  # its close is the window's last byte, fixed only by the last character
    iss_key["iss_window"][-1] = ord(",")
    aud_q = b'7000000001","x":"y'
    return {
        "bad-signature": dict(base, signature=google.limbs(google.pkcs1_sha256(b"x", google.N, google.D))),
        "payload-not-signed": dict(other, **{k: base[k] for k in ("signing_input", "signature")}),
        "iss-google": witness(claims(iss="https://accounts.google.com")),
        "iss-unescaped": raw(b"https:\\/\\/oauth", b"https://oauth"),
        "iss-suffix": witness(claims(iss="https://oauth.telegram.org.evil")),
        "id-forged-in-name": witness(forged, id_offset=fp.index(b'\\"id') + 1, id_len=3,
                                     id_node=halves(ID_TAG + b"999")),
        "id-forged-in-given-name": witness(forged_g, id_offset=fgp.index(b"&quot;id"), id_len=3,
                                           id_node=halves(ID_TAG + b"999")),
        "username-missing": witness(nouser, username_offset=encode(nouser).index(b'"name"')),
        "username-4": with_user("abcd"),
        "username-33": with_user("A" * 33),
        "username-hyphen": with_user("alice-tg"),
        "username-escape": dict(with_user("alicé_tg"), username_len=13,
                                handle_node=halves(HANDLE_TAG + b"alic\\u00e9_tg")),
        "username-len-short": dict(base, username_len=7, handle_node=halves(HANDLE_TAG + b"alice_t")),
        "handle-node-unfolded": dict(base, handle_node=halves(HANDLE_TAG + b"Brynn_QX")),
        "id-leading-zero": with_id("0123456789"),
        "id-non-digit": with_id("12a45"),
        "id-21-digits": with_id("123456789012345678901"),
        "id-len-short": dict(base, id_len=9, id_node=halves(ID_TAG + b"500000000")),
        "id-node-other": dict(base, id_node=halves(ID_TAG + b"5000000002")),
        "id-window-other": dict(base, id_window=other["id_window"], id_node=other["id_node"]),
        "nonce-other-digest": witness(claims(nonce=google.b64url(hashlib.sha256(DIGEST).digest()).decode())),
        "nonce-44-chars": witness(claims(nonce=NONCE + "A")),
        "nonce-digest-other": dict(base, authorization_digest=list(hashlib.sha256(DIGEST).digest())),
        "iat-leading-zero": dict(raw(f'"iat":{IAT}'.encode(), f'"iat":0{IAT}'.encode()), iat_len=len(str(IAT)) + 1),
        "iat-quoted": witness(claims(iat=str(IAT))),
        "iat-other": dict(base, iat=IAT + 1),
        "aud-other": dict(base, audience_hash=halves(b"7000000002")),
        "payload-over-max": witness(worst(1)[0], header=h),
        "signing-input-over-max": witness(c, header=dict(h, kid=h["kid"] + "x")),
        "payload-not-after-dot": dict(base, header_b64_len=base["header_b64_len"] + 4,
                                      **{f"{k}_offset": base[f"{k}_offset"] - 3 for k in WINDOWS}),
        "iss-close-unsigned": iss_key,
        "iss-as-key": raw(b'org",', b'org":1,'),
        "id-key-suffix": witness(claims(uid="999"), id_offset=encode(claims(uid="999")).index(b'"uid"') + 1,
                                 id_len=3, id_node=halves(ID_TAG + b"999")),
        "id-prefix-unquoted": raw(b'"id":"', b'"id": '),
        "id-closed-by-quote": raw(b'7051836294",', b'7051836294"",'),
        "id-leading-zero-2": with_id("05"),
        "aud-prefix": witness(claims(aud=AUD + "x,y")),
        "aud-empty": witness(claims(aud=""), audience_len=0, audience_hash=halves(b"")),
        "aud-quote": dict(raw(b'"aud":"7000000001"', b'"aud":"' + aud_q + b'"'), audience_len=len(aud_q),
                          audience_hash=halves(aud_q)),
        "aud-backslash": witness(claims(aud="70\\01"), audience_len=6, audience_hash=halves(b"70\\\\01")),
        "iat-empty": dict(raw(f'"iat":{IAT}'.encode(), b'"iat":'), iat_len=0, iat=0),
        "iat-13-digits": dict(raw(f'"iat":{IAT}'.encode(), f'"iat":{IAT}123'.encode()), iat_len=13,
                              iat=IAT * 100 + 12),
        "iat-colon-digit": dict(raw(f'"iat":{IAT}'.encode(), f'"iat":{IAT // 10}:'.encode()), iat=IAT + 10),
        "iat-len-short": dict(base, iat_len=9, iat=IAT // 10),
        "username-hyphen-last": with_user("alice_t-"),
    }


def run(path: pathlib.Path) -> str:
    r = subprocess.run(["nargo", "execute", "--silence-warnings", "-p", str(path)], cwd=CIRCUIT,
                       capture_output=True, text=True)
    out = r.stdout + r.stderr
    failed = "Failed to solve program" in out or "Failed assertion" in out  # without, with a message
    return "ok" if r.returncode == 0 else "constraint" if failed else out.strip()


def check(files: list[pathlib.Path]) -> int:
    bad = [f"accept {p.name}: {r}" for p in files if (r := run(p)) != "ok"]
    abi = json.loads((CIRCUIT / "target" / "oidc_telegram.json").read_text())["abi"]["parameters"]
    got = [(p["name"], p["type"].get("length", 1)) for p in abi if p["visibility"] == "public"]
    bad += [] if got == PUBLIC else [f"public inputs {got}, want {PUBLIC}"]
    with tempfile.TemporaryDirectory() as tmp:
        for name, w in rejects().items():
            path = pathlib.Path(tmp) / f"{name}.toml"
            path.write_text(toml(w, name))
            if (r := run(path)) != "constraint":
                bad.append(f"reject {name}: {r}")
    print("\n".join(bad) or "every accept solves; every reject fails a constraint")
    return 1 if bad else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=pathlib.Path, default=CIRCUIT, help="directory for Prover*.toml")
    parser.add_argument("--check", action="store_true", help="execute accepts and rejects with nargo")
    args = parser.parse_args()
    files = []
    for name, (w, comment) in accepts().items():
        files.append(args.out / f"{name}.toml")
        files[-1].write_text(toml(w, comment))
    return check(files) if args.check else 0


if __name__ == "__main__":
    raise SystemExit(main())
