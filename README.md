# libID circuits

Noir zero-knowledge circuits for libID's login flows. The proving artifacts
(ACIR + verification keys) that the on-chain Solidity verifiers in
[libid-contracts] derive from, byte-for-byte, are **not committed** — they
ship exclusively as GitHub Release assets, rebuilt from these sources by the
release workflow under the pinned toolchain.

[libid-contracts]: https://github.com/libid-org/libid-contracts

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
- `vk_hash` — its 32-byte hash.

```sh
scripts/build.sh              # build into ./artifacts/ (requires the pinned toolchain)
scripts/build.sh --out <dir>  # build into <dir> (what the workflows use)
```

The output is byte-reproducible: with the pinned toolchain, any machine
produces identical bytes (the path normalization above removes the only
machine-specific content), so a release built in CI is byte-identical to a
local build from the same sources.

## Generating a Solidity verifier

```sh
scripts/gen-verifier.sh oidc-google Verifier.sol
scripts/gen-verifier.sh bearer-link BearerLinkHonkVerifier.sol \
  --contract-name BearerLinkHonkVerifier
```

This runs `bb write_solidity_verifier` on the locally built vk (run
`scripts/build.sh` first) and applies the
canonical post-processing: every `assembly {` becomes
`assembly ("memory-safe") {` (required by via_ir consumers), plus the
optional contract rename (bb always names the concrete contract
`HonkVerifier`; a consumer compiling both verifiers needs distinct names). **`forge fmt` is deliberately not run here** — this
repo carries no Foundry toolchain; the consumer formats the output under its
own `foundry.toml` before diffing or committing, which is exactly what
libid-contracts does.

## Releases

Publishing a GitHub Release tagged `v<version>` builds the artifacts from
source with the pinned toolchain (`scripts/build.sh`) and attaches:

- `libid-circuits-<version>-<circuit>.tar.gz` — one per circuit, containing
  `<package>.json`, `vk`, `vk_hash`;
- `manifest.json` — `{version, tag, toolchain: {nargo, bb}, tarballs:
  {<tarball>: {sha256, files: {<name>: sha256}}}}`.

## How consumers verify (the libid-contracts flow)

libid-contracts pins a release tag of this repo. Its CI downloads the
tarballs plus `manifest.json` from that release, checks the tarballs against
the manifest's sha256s, installs the bb version the manifest names,
regenerates its verifiers from the vks (write_solidity_verifier + memory-safe
rewrite + the contract rename), runs `forge fmt` over them, and byte-compares
against what it committed.

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
