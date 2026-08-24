#!/usr/bin/env bash
# Generate an EVM Solidity verifier from a locally built verification key
# (run scripts/build.sh first — artifacts are never committed to this repo).
#
#   scripts/gen-verifier.sh <circuit> <out.sol> [--contract-name X]
#
#   <circuit>          directory name under artifacts/ (e.g. oidc-google,
#                      x-token)
#   <out.sol>          output path for the Solidity source
#   --contract-name X  rename the concrete verifier contract from bb's fixed
#                      `HonkVerifier` to X (e.g. XHonkVerifier — needed when a
#                      consumer compiles two bb verifiers in one project and
#                      the names would collide)
#
# Canonical post-processing (matches what the committed libid-contracts
# verifiers were built with):
#   1. every `assembly {` becomes `assembly ("memory-safe") {` — required for
#      consumers compiling via_ir;
#   2. the optional contract rename above.
#
# Deliberately NOT done here: `forge fmt`. This repo carries no Foundry
# toolchain; the consumer runs `forge fmt` over the output under its own
# foundry.toml before comparing/committing (libid-contracts does exactly
# that). Raw bb output + the two rewrites above is the interchange format.
#
# The verifier derives from the vk ALONE, so this needs only bb (pinned via
# toolchain.env) and artifacts/<circuit>/vk — no nargo, no recompile.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../toolchain.env
# shellcheck disable=SC1091
source "$ROOT/toolchain.env"

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <circuit> <out.sol> [--contract-name X]" >&2
  exit 2
fi
circuit="$1"
out="$2"
contract_name=""
if [[ "${3:-}" == "--contract-name" ]]; then
  contract_name="${4:?--contract-name needs a value}"
elif [[ $# -gt 2 ]]; then
  echo "usage: $0 <circuit> <out.sol> [--contract-name X]" >&2
  exit 2
fi

vk="$ROOT/artifacts/$circuit/vk"
if [[ ! -f "$vk" ]]; then
  echo "error: no vk at $vk — unknown circuit '$circuit'? (run scripts/build.sh first)" >&2
  exit 1
fi

have_bb="$(bb --version 2>/dev/null | tail -1)"
if [[ "$have_bb" != "$BB_VERSION" ]]; then
  echo "error: bb $BB_VERSION required (toolchain.env), found '${have_bb:-not installed}'." >&2
  echo "  install: bbup --version $BB_VERSION" >&2
  exit 1
fi

bb write_solidity_verifier -k "$vk" -o "$out" -t evm

# via_ir consumers need the memory-safe annotation on every assembly block.
perl -i -pe 's/assembly \{/assembly ("memory-safe") \{/g' "$out"

if [[ -n "$contract_name" ]]; then
  # Only the concrete contract is renamed; the abstract base keeps its name.
  perl -i -pe "s/contract HonkVerifier is BaseZKHonkVerifier/contract ${contract_name} is BaseZKHonkVerifier/g" "$out"
fi

echo "wrote $out (contract $( [[ -n "$contract_name" ]] && echo "$contract_name" || echo HonkVerifier )); run 'forge fmt' in the consumer before diffing/committing."
