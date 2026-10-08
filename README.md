# libID-circuits

Noir zero-knowledge circuits for libID's login flows. The proving artifacts
(ACIR + verification keys) and the Solidity verifiers derived from them,
which [libID-contracts] compiles and deploys, are **not committed** — they
ship exclusively as GitHub Release assets, rebuilt from these sources by the
release workflow under the pinned toolchain. `bb` runs in this repo and
nowhere else.

[libID-contracts]: https://github.com/libid-org/libID-contracts

libID does not implement its own zero-knowledge language or proving system.
These circuits use [Noir](https://noir-lang.org/) with Aztec's
[Barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/next/barretenberg)
proving backend. We are grateful to the Aztec team for developing and sharing
this stack as a public good, especially for its excellent browser proving
support, which fits libID's client-side proving use case almost perfectly.

## The circuits

| Circuit | Package | Proves |
|---|---|---|
| `circuits/bearer-link-x` | `bearer_link_x` | X's bearer link plus the account as keys. The identity response reveals only the anchors around `id` and `username`; the circuit opens the two committed values as X sent them, checks them against X's rules, folds the handle, and outputs `idNode = SHA256("libid.x.user-id" \|\| id)` and `handleNode = SHA256("libid.x.handle" \|\| fold(handle))`. 72 public inputs: the two bearer commitments (64 bytes), then the id and handle commitments and the two nodes as 16-byte halves. Neither value reaches the chain. |
| `circuits/bearer-link-github` | `bearer_link_github` | The same relation for GitHub: the bearer link, and the committed `id` (a JSON integer, its digits alone) and `login` opened, checked against GitHub's rules, the login folded, and output as `SHA256("libid.github.user-id" \|\| id)` and `SHA256("libid.github.handle" \|\| fold(login))`. The same 72 public inputs. |
| `circuits/oidc-google` | `oidc_google` | Possession of a Google OIDC JWT: verifies the RSASSA-PKCS1-v1_5 signature over `header.payload` and exposes the Authorization Digest carried in `nonce`, `SHA256(aud)`, the id node `SHA256("libid.google.user-id" \|\| sub)`, the handle node `SHA256("libid.google.handle" \|\| fold(email))` (the `sub` and the address stay private; the address is checked against the Google rules and folded in the circuit), `exp`, and the modulus that verified. The Platform Verifier alone decides whether that modulus is trusted. |

CI enforces `nargo fmt --check` on every package.

`lib/identity` is the library the identity circuits share: commitment
openings, the tagged node hash, the handle and id rules, and `identity_link`,
the relation both bearer-link circuits run with their platform's constants. Its constants and
its test table, `src/table.nr`, are generated from libID-contracts'
`solidity/contracts/handles/handles.json`, the table Solidity, Rust and
TypeScript run too:

```sh
# from a libID-contracts checkout, with nargo on PATH
scripts/regen-identity-handles.py --noir-out ../libid-circuits/lib/identity/src/table.nr
```

`scripts/build.sh` copies the table into each identity circuit's artifacts as
`handles-table.nr`, so a consumer can tell a verifier built from another
table.

`contracts.ref` pins the libID-contracts commit whose `handles.json` this
table must match. CI checks out that commit and runs its
`scripts/regen-identity-handles.py --compare-noir` against
`lib/identity/src/table.nr`; it needs only Python. To move the pin after
regenerating the table from a newer `handles.json`, write the new commit's
full SHA, which must be pushed to libID-contracts:

```sh
git -C ../libid-contracts rev-parse HEAD > contracts.ref
(cd ../libid-contracts && scripts/regen-identity-handles.py --compare-noir "$OLDPWD/lib/identity/src/table.nr")
```

`scripts/identity-link-witness.py` writes a `bearer-link-x` or
`bearer-link-github` `Prover.toml` from the identity-link witness libid-rs
emits with a ceremony record. The committed ones are written from
`fixtures/x-identity-link-witness.json` and
`fixtures/github-identity-link-witness.json`: the `identity_link_witness`
members of libID-contracts' synthetic
`solidity/contracts/ceremony/test/fixtures/{x,github}-ceremony-session.json`
(libid-rs' `cargo run -p libid-tlsn --example ceremony_fixtures`), whose
handles (`Alice_1`, `OctoCat`) exercise the fold. CI regenerates both and
fails on a difference.

### Proving a real capture

The script tells the two forms apart by content, not by file name. A session
file, with the witness in its `identity_link_witness` member, is synthetic. A
bare witness, with `platform` and `token_bearer` at the top level, is what a
real capture writes, and is secret:

- it holds a live bearer until the platform revokes it;
- its id and handle blinders open the commitments the notary signed, so
  whoever holds them can link that signed record to the account for as long
  as the record exists. Revoking the bearer does not undo that.

For a bare witness the script writes only to an `--out` path ending in
`.toml` that lies outside every git work tree, or that the work tree's ignore
rules match, with mode 0600, and never to stdout. It then prints how to prove
it. Prove from outside the repo, naming both the input and the solved
witness by absolute path, so nothing lands in `target/`:

```sh
umask 077
dir="${XDG_RUNTIME_DIR:?}/libid"; mkdir -p "$dir"
scripts/identity-link-witness.py ~/capture/x-identity-link-witness.secret.json --out "$dir/x.toml"
(cd circuits/bearer-link-x && nargo execute -p "$dir/x" "$dir/x")   # reads x.toml, writes x.gz
# ... prove from "$dir/x.gz" ...
rm -f "$dir/x.toml" "$dir/x.gz"
```

`nargo execute` appends `.toml` to the `-p` name and `.gz` to the witness
name. Without the witness name it writes the solved witness, which holds the
bearer too, to `circuits/<circuit>/target/<package>.gz`, under the umask for a
new file and keeping the mode of an existing one (group-readable after an
ordinary build): delete `target/*.gz` after proving.

## Toolchain

`toolchain.env` is the single source of truth:

```
NARGO_VERSION=1.0.0-rc.3
BB_VERSION=6.0.0-rc.2
```

Install exactly those:

```sh
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup --version 1.0.0-rc.3
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash
bbup --version 6.0.0-rc.2
```

The two pins are one pair: a Barretenberg release builds against a single
Noir commit (`noir/noir-repo` in aztec-packages at the bb tag) and reads only
the ACIR that compiler writes. bb 6.0.0-rc.2 builds against Noir 1.0.0-rc.3.

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
  (`bb write_solidity_verifier -t evm --optimized` on the vk, see
  "Regenerating a Solidity verifier"), the contract named after the circuit
  directory: `bearer-link-x/BearerLinkXHonkVerifier.sol`,
  `bearer-link-github/BearerLinkGithubHonkVerifier.sol`,
  `oidc-google/OidcGoogleHonkVerifier.sol`;
- `handles-table.nr` — identity circuits only: the generated table the
  circuit's rules and tags come from.

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
scripts/gen-verifier.sh bearer-link-x                        # artifacts/bearer-link-x/BearerLinkXHonkVerifier.sol
scripts/gen-verifier.sh oidc-google --artifacts ~/unpacked   # from a downloaded release's vk
scripts/gen-verifier.sh oidc-google Verifier.sol --contract-name HonkVerifier
```

The verifier is bb's optimized template with zero knowledge (`-t evm
--optimized`): one contract, `<Circuit>HonkVerifier is IVerifier`, deployed
without linking. The Proving Circuit is zero-knowledge by specification, so
the target is never `evm-no-zk`.

The interchange format is raw `bb write_solidity_verifier` output plus
exactly one rewrite: the contract is renamed off bb's fixed `HonkVerifier`
to `<Circuit>HonkVerifier` (all three verifiers compile in one project). The
names the current circuits ship under are pinned in the script and checked
on every run, so renaming a circuit directory fails the build instead of
silently renaming the contract consumers compile. `forge fmt` is the
consumer's: it formats the shipped file under its own `foundry.toml` before
compiling it.

## Compiling a verifier

Compile the verifiers **without via_ir**, for EVM version `cancun` or later:

- solc's IR pipeline cannot lay out the stack of the verifier's assembly
  (solc 0.8.33: "Could not create stack layout after 1000 iterations"); the
  legacy pipeline compiles it;
- the assembly uses `MCOPY`, a Cancun opcode.

The switch is solc's `--via-ir` (standard JSON `settings.viaIR`), Foundry's
`via_ir`. A Foundry project that builds everything else via IR keeps it on
and compiles only the verifiers on the legacy pipeline:

```toml
[profile.default]
via_ir = true
additional_compiler_profiles = [{ name = "verifiers", via_ir = false }]
compilation_restrictions = [{ paths = "contracts/circuits/*HonkVerifier.sol", via_ir = false }]
```

All three fit EIP-170's runtime size limit on the legacy pipeline with the
optimizer on.

`scripts/check-verifiers.sh` compiles every verifier that way, then proves
each circuit's committed witness, `circuits/<circuit>/Prover.toml`: the
proof must verify with `bb verify` and with the verifier deployed to anvil,
and fail with one bit flipped. CI runs it after every build. It needs
Foundry (`forge`, `anvil`, `cast`) besides the pinned nargo and bb:

```sh
scripts/build.sh && scripts/check-verifiers.sh
```

`circuits/oidc-google/Prover.toml` is written by
`scripts/google-fixture-witness.py`: a Google-shaped ID token signed by a
seeded synthetic RSA-2048 key, for the fixture `sub` 100000000000000000001 and
`email` Fixture@Example.com, mixed case so the fold is exercised.

## Releases

Publishing a GitHub Release tagged `v<version>` builds the artifacts from
source with the pinned toolchain (`scripts/build.sh`) and attaches:

- `libid-circuits-<version>-<circuit>.tar.gz` — one per circuit, containing
  `<package>.json`, `vk`, `vk_hash`, `<Contract>.sol`, and for the identity
  circuits (`bearer-link-x`, `bearer-link-github`, `oidc-google`)
  `handles-table.nr`;
- `manifest.json` — `{version, tag, toolchain: {nargo, bb}, tarballs:
  {<tarball>: {sha256, files: {<name>: sha256}}}}`.

## Consuming a release

Pin a release tag. Download the circuit's tarball and `manifest.json`, check
the tarball's sha256 against the manifest, unpack, check `<Contract>.sol`
against its entry in `files`, run `forge fmt` over it under your own
`foundry.toml`, and compile it without via_ir (see "Compiling a verifier").
No `bb`, no nargo: the verifier is derived here, once, by the toolchain the
manifest names.

For an identity circuit, also check `handles-table.nr` against your
`handles.json` with libID-contracts'
`scripts/regen-identity-handles.py --compare-noir handles-table.nr`. A
mismatch means the verifier keys handles by another table.

Verification keys under the pinned toolchain (nargo 1.0.0-rc.3, bb 6.0.0-rc.2):

| Circuit | vk_hash |
|---|---|
| `bearer-link-x` | `0x1f09866b4c8feca602a2d394a5c8c924d3b8d964696f0214252ab97c9213775d` |
| `bearer-link-github` | `0x1168344f46c63b1fa251c174f4b4d4e7c104cf65ab38d36fcbcf66108e626770` |
| `oidc-google` | `0x2b2c5f9b3301f9ba7b6d69db7baaebc124b09959b7fb7ae87734ecb56667a488` |
