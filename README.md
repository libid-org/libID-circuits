# libID circuits

Noir zero-knowledge circuits for libID's login flows. The proving artifacts
(ACIR + verification keys) and the Solidity verifiers derived from them,
which [libid-contracts] compiles and deploys, are **not committed** — they
ship exclusively as GitHub Release assets, rebuilt from these sources by the
release workflow under the pinned toolchain. `bb` runs in this repo and
nowhere else.

[libid-contracts]: https://github.com/libid-org/libid-contracts

libID does not implement its own zero-knowledge language or proving system.
These circuits use [Noir](https://noir-lang.org/) with Aztec's
[Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/next/barretenberg)
proving backend. We are grateful to the Aztec team for developing and sharing
this stack as a public good, especially for its excellent browser proving
support, which fits libID's client-side proving use case almost perfectly.

## The circuits

| Circuit | Package | Proves |
|---|---|---|
| `circuits/bearer-link` | `bearer_link` | One hidden OAuth bearer opens both of a ceremony's blinded commitments — the token session's and the identity session's. Exactly two public inputs and nothing else: the credential never leaves the circuit, and the two sessions are tied together without publishing anything that identifies them. Serves X and GitHub, whose statements are byte-identical. |
| `circuits/oidc-google` | `oidc_google` | Possession of a Google OIDC JWT: verifies the RSASSA-PKCS1-v1_5 signature over `header.payload` and exposes the Authorization Digest carried in `nonce`, `SHA256(aud)`, `sub`, the raw `email` bytes, `exp`, and the modulus that verified. The Platform Verifier alone decides whether that modulus is trusted. |

Sources were extracted byte-verbatim from the original monorepo and then
formatted once with `nargo fmt` (verified to leave the vk byte-identical;
only debug metadata in the ACIR json moves); CI enforces `nargo fmt --check`
from there on.

## Toolchain

`toolchain.env` is the single source of truth:

```
NARGO_VERSION=1.0.0-beta.25
BB_VERSION=5.2.0
```

Install exactly those:

```sh
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup --version 1.0.0-beta.25
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash
bbup --version 5.2.0
```

The pins matter because the whole chain is deterministic in the toolchain:

```
src/main.nr --nargo compile--> ACIR json --bb write_vk--> vk --bb write_solidity_verifier--> Verifier.sol
```

The vk derives from the ACIR alone; the Solidity verifier from the vk alone.
Different toolchain versions produce different vks, and a different vk is a
different on-chain verifier — so **bumping either pin means the web prover
bundle and the deployed verifier contracts must roll together**. Both scripts
refuse to run under any other version.

`nargo compile` fetches the tag-pinned git dependencies in each `Nargo.toml`
(zkpassport/noir_rsa, noir-lang/bignum, sha256, noir_base64, keccak256) into
`~/nargo` on first run; after that the build works from the local cache.

## Building the artifacts

`scripts/build.sh` writes, per circuit, into a local gitignored
`artifacts/<circuit>/` (never committed):

- `<package>.json` — ACIR + ABI from `nargo compile`, with the absolute
  source paths nargo embeds in `file_map` normalized to relative form so the
  file is byte-identical regardless of the machine that built it (the
  `bytecode`, `abi`, `debug_symbols` and `hash` fields are machine-independent
  as produced);
- `vk` — Barretenberg verification key
  (`bb write_vk --oracle_hash keccak`, keccak because the consumer is EVM);
- `vk_hash` — its 32-byte hash;
- `<Contract>.sol` — the EVM Solidity verifier
  (`bb write_solidity_verifier` on the vk, plus the two rewrites described
  under "Regenerating a Solidity verifier"), the concrete contract named
  after the circuit directory: `bearer-link/BearerLinkHonkVerifier.sol`,
  `oidc-google/OidcGoogleHonkVerifier.sol`.

```sh
scripts/build.sh              # build into ./artifacts/ (requires the pinned toolchain)
scripts/build.sh --out <dir>  # build into <dir> (what the workflows use)
```

The output is byte-reproducible: with the pinned toolchain, any machine
produces identical bytes (the path normalization above removes the only
machine-specific content), so a release built in CI is byte-identical to a
local build from the same sources.

## Regenerating a Solidity verifier

`scripts/build.sh` writes every verifier. `scripts/gen-verifier.sh` is the
step it runs per circuit, and regenerates one from a vk alone — no nargo —
for example to byte-compare an unpacked release against a local `bb`:

```sh
scripts/gen-verifier.sh bearer-link                          # artifacts/bearer-link/BearerLinkHonkVerifier.sol
scripts/gen-verifier.sh oidc-google --artifacts ~/unpacked   # from a downloaded release's vk
scripts/gen-verifier.sh oidc-google Verifier.sol --contract-name HonkVerifier
```

The interchange format is raw `bb write_solidity_verifier` output plus
exactly two rewrites: every `assembly {` becomes `assembly ("memory-safe") {`
(required by via_ir consumers), and the concrete contract is renamed off
bb's fixed `HonkVerifier` to `<Circuit>HonkVerifier` (both verifiers must
compile in one project). The names the current circuits ship under are
pinned in the script and checked on every run, so renaming a circuit
directory fails the build instead of silently renaming the contract
consumers compile. **`forge fmt` is deliberately not run here** — this repo
carries no Foundry toolchain; the consumer formats the shipped file under
its own `foundry.toml` before compiling or committing it.

## Releases

Publishing a GitHub Release tagged `v<version>` builds the artifacts from
source with the pinned toolchain (`scripts/build.sh`) and attaches:

- `libid-circuits-<version>-<circuit>.tar.gz` — one per circuit, containing
  `<package>.json`, `vk`, `vk_hash`, `<Contract>.sol`;
- `manifest.json` — `{version, tag, toolchain: {nargo, bb}, tarballs:
  {<tarball>: {sha256, files: {<name>: sha256}}}}`.

## Consuming a release

Pin a release tag. Download the circuit's tarball and `manifest.json`, check
the tarball's sha256 against the manifest, unpack, check `<Contract>.sol`
against its entry in `files`, run `forge fmt` over it under your own
`foundry.toml`, and compile. No `bb`, no nargo: the verifier is derived
here, once, by the toolchain the manifest names.

Verification keys under the pinned toolchain (nargo 1.0.0-beta.25, bb 5.2.0),
for the release that drops `x-token`:

| Circuit | vk_hash |
|---|---|
| `bearer-link` | `0x1d161afb536683d31a3e426db0feaa30de8be89cc45510579f361266c20e078f` |
| `oidc-google` | `0x1b50bbf6d8ea6efc7ecc2547c25b285511704a10d9247466e84045095d9c3f77` |

The Google key has moved twice since the value this section cited before
2026-08-12: once when the proof was bound to the Authorization Digest
(REQ-PLAT-16B public inputs), and again with the REQ-COMMON-19 /
REQ-COMMON-19D constraints below. The deployed verifier rolls with the next
release.
