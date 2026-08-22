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
| `circuits/jwt_email` | `jwt_email` | Possession of a Google OIDC JWT: verifies the RSA signature over the JWT and exposes the claims the login registry needs, without revealing the token. Source of the `HonkVerifier` in libid-contracts `solidity/contracts/login/oidc/Verifier.sol`. |
| `circuits/dyaka-noir-token` | `dyaka_noir_token` | An X (Twitter) OAuth bearer token binds two TLSN hash commitments: the same private bearer SHA-256-hashes to both notary commitments (`/token` and `/me`), plus a blinder-independent keccak nullifier for one-shot on-chain dedup per real bearer. Source of the `XHonkVerifier` in libid-contracts `solidity/contracts/login/zk/XHonkVerifier.sol`. |

Sources are byte-verbatim copies of the circuits extracted from the original
dyaka monorepo (and are therefore not `nargo fmt`-clean; reformatting was
verified to leave the compiled bytecode identical, but is deferred to a
deliberate future change so provenance stays byte-checkable).

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
scripts/gen-verifier.sh jwt_email Verifier.sol
scripts/gen-verifier.sh dyaka-noir-token XHonkVerifier.sol --contract-name XHonkVerifier
```

This runs `bb write_solidity_verifier` on the locally built vk (run
`scripts/build.sh` first) and applies the
canonical post-processing: every `assembly {` becomes
`assembly ("memory-safe") {` (required by via_ir consumers), plus the
optional contract rename (bb always names the concrete contract
`HonkVerifier`; a consumer compiling both verifiers needs distinct names,
hence `XHonkVerifier`). **`forge fmt` is deliberately not run here** — this
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

libid-contracts pins a release tag of this repo. Its CI downloads the two
tarballs plus `manifest.json` from that release, checks the tarballs against
the manifest's sha256s, installs the bb version the manifest names,
regenerates both verifiers from the vks (write_solidity_verifier +
memory-safe rewrite + `XHonkVerifier` rename), runs `forge fmt` over them,
and byte-compares against its committed `Verifier.sol` and
`XHonkVerifier.sol`. Reproducibility verified 2026-08-12 against the sources
as of that date (jwt_email vk_hash then `0x1a1fad94…d7d6ba08`). The jwt_email
circuit has since changed — the digest-bound REQ-PLAT-16B public inputs, then
the REQ-COMMON-19 / REQ-COMMON-19D trailing-structural-byte and canonical-`exp`
constraints — so the deployed verifier rolls with the next release; current
sources produce jwt_email vk_hash `0x1596b429…2af7a27c`.

## Historical note (provenance)

For anyone auditing the extraction from the dyaka monorepo:

- A `dyaka-noir-x-circuit` is referenced in old dyaka documentation but
  **never existed in git** — it is a phantom name. The X login circuit has
  always been `dyaka_noir_token` (this repo's `circuits/dyaka-noir-token`).
- `XHonkVerifier.sol` derives from `dyaka_noir_token`'s vk; the `X` prefix is
  only the collision-avoiding contract rename described above, not a
  different circuit.
- A `dyaka-noir-shared` library once existed and was inlined into the circuit
  sources before extraction; there is no shared package to look for.
- dyaka's tracked `web/public/circuit/dyaka_noir_token.json` was compiled on
  a developer machine: its `bytecode`, `abi`, `debug_symbols` and `hash`
  fields are identical to a fresh pinned-toolchain compile, and only the
  absolute paths in `file_map` differ — the motivation for the path
  normalization in `scripts/build.sh`.
