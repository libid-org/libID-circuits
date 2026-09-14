#!/usr/bin/env bash
# Build the proving artifacts for every circuit in circuits/.
#
# Artifacts are NEVER committed to this repo — they ship exclusively as
# release assets, rebuilt from source by the release workflow. This script is
# the single build path: developers run it locally, CI runs it to prove the
# circuits compile and the vks generate, and the release workflow runs it to
# produce the assets it packages.
#
# For each circuit this produces, under <out>/<circuit>/:
#   <package>.json  ACIR + ABI from `nargo compile`, with file_map paths
#                   normalized (see below) so the file is byte-identical no
#                   matter which machine built it
#   vk              Barretenberg verification key
#                   (`bb write_vk --oracle_hash keccak` — keccak because the
#                   consumer is an EVM Solidity verifier)
#   vk_hash         32-byte hash of the vk, as written by the same command
#   <Contract>.sol  the EVM Solidity verifier bb derives from the vk, with
#                   the memory-safe rewrite applied and the concrete contract
#                   named after the circuit (bearer-link ->
#                   BearerLinkHonkVerifier); see scripts/gen-verifier.sh.
#                   Ships so that consumers compile it and never run bb.
#
# The vk derives from the ACIR bytecode alone, and the Solidity verifier from
# the vk alone — so a release tarball is the complete, sufficient input for
# reproducing every byte of the on-chain verifier.
#
# Path normalization: nargo embeds absolute source paths in the ACIR json's
# file_map (used only for diagnostics; the bytecode, abi, debug_symbols and
# hash fields are machine-independent — verified empirically). We rewrite
#   <repo root>/…        -> …            (circuit sources)
#   $HOME/nargo/…        -> nargo/…      (git dependency cache)
# so the json is byte-reproducible across machines — critical so a
# release-time CI build produces exactly the bytes a local pinned-toolchain
# build produces. The json is re-emitted by jq (stable formatting) as part of
# the same normalization.
#
# Usage:
#   scripts/build.sh              build into ./artifacts/ (gitignored)
#   scripts/build.sh --out <dir>  build into <dir>
#
# Requires the pinned toolchain from toolchain.env; refuses to run otherwise,
# because artifacts built by any other version are not comparable.
# `nargo compile` fetches git dependencies (zkpassport/noir-lang) over the
# network on a cold cache.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../toolchain.env
# shellcheck disable=SC1091
source "$ROOT/toolchain.env"

OUT="$ROOT/artifacts"
if [[ "${1:-}" == "--out" ]]; then
  OUT="${2:?--out needs a directory}"
  mkdir -p "$OUT"
  OUT="$(cd "$OUT" && pwd)"
elif [[ $# -gt 0 ]]; then
  echo "usage: $0 [--out <dir>]" >&2
  exit 2
fi

# --- Toolchain gate ----------------------------------------------------------
have_nargo="$(nargo --version 2>/dev/null | sed -n 's/^nargo version = //p')"
if [[ "$have_nargo" != "$NARGO_VERSION" ]]; then
  echo "error: nargo $NARGO_VERSION required (toolchain.env), found '${have_nargo:-not installed}'." >&2
  echo "  install: noirup --version $NARGO_VERSION" >&2
  exit 1
fi
have_bb="$(bb --version 2>/dev/null | tail -1)"
if [[ "$have_bb" != "$BB_VERSION" ]]; then
  echo "error: bb $BB_VERSION required (toolchain.env), found '${have_bb:-not installed}'." >&2
  echo "  install: bbup --version $BB_VERSION" >&2
  exit 1
fi

# --- Build -------------------------------------------------------------------
for dir in "$ROOT"/circuits/*/; do
  circuit="$(basename "$dir")"
  pkg="$(sed -n 's/^name *= *"\(.*\)"/\1/p' "$dir/Nargo.toml")"
  echo "==> $circuit (package $pkg)"

  (cd "$dir" && nargo compile --silence-warnings)

  mkdir -p "$OUT/$circuit"

  # Normalize file_map paths (machine-specific absolute paths -> stable
  # relative forms), re-emitting through jq for stable byte layout.
  jq --arg root "$ROOT/" --arg cache "$HOME/nargo/" '
    .file_map |= with_entries(
      .value.path |= (
        if   startswith($root)  then ltrimstr($root)
        elif startswith($cache) then "nargo/" + ltrimstr($cache)
        else . end
      )
    )' "$dir/target/$pkg.json" > "$OUT/$circuit/$pkg.json"

  # vk + vk_hash from the raw compile output (bb reads only the bytecode, so
  # raw vs normalized json is equivalent; raw is what bb documents).
  vk_tmp="$(mktemp -d)"
  bb write_vk -b "$dir/target/$pkg.json" -o "$vk_tmp" --oracle_hash keccak
  mv "$vk_tmp/vk" "$OUT/$circuit/vk"
  mv "$vk_tmp/vk_hash" "$OUT/$circuit/vk_hash"
  rmdir "$vk_tmp"

  # The Solidity verifier, next to the vk it derives from. gen-verifier.sh
  # names the contract after the circuit directory and checks the pinned
  # names, so a renamed directory fails here instead of at a consumer.
  "$ROOT/scripts/gen-verifier.sh" "$circuit" --artifacts "$OUT"
done

echo "OK: artifacts written to $OUT"
