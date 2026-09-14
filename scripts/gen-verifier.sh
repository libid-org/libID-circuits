#!/usr/bin/env bash
# Generate the EVM Solidity verifier for one circuit from its verification
# key. scripts/build.sh runs this for every circuit, so the verifier ships in
# the release tarball next to the vk it derives from; consumers compile what
# ships and never run bb themselves.
#
#   scripts/gen-verifier.sh <circuit> [<out.sol>] [--artifacts <dir>] [--contract-name X]
#
#   <circuit>          directory name under circuits/ and <artifacts>/
#                      (bearer-link, oidc-google)
#   <out.sol>          output path; default <artifacts>/<circuit>/<Contract>.sol,
#                      next to the vk, which is the release layout
#   --artifacts <dir>  where scripts/build.sh wrote (default ./artifacts);
#                      point it at an unpacked release to regenerate and
#                      byte-compare against what shipped
#   --contract-name X  rename the concrete verifier contract from bb's fixed
#                      `HonkVerifier` to X; default derived from <circuit>
#                      (see below)
#
# Contract name: bb always emits `HonkVerifier`, and a consumer compiling
# both verifiers in one project needs distinct names, so the concrete
# contract is renamed to <Circuit>HonkVerifier with the directory name in
# PascalCase: bearer-link -> BearerLinkHonkVerifier. The names the current
# circuits ship under are pinned in KNOWN_VERIFIERS below and checked on
# every run: renaming a circuit directory renames the contract every
# consumer compiles, so it fails here instead of shipping.
#
# Post-processing — this is the interchange format, raw bb output plus
# exactly these two rewrites:
#   1. every `assembly {` becomes `assembly ("memory-safe") {` — required for
#      consumers compiling via_ir;
#   2. the contract rename above.
#
# Deliberately NOT done here: `forge fmt`. This repo carries no Foundry
# toolchain; the consumer runs `forge fmt` over the shipped file under its
# own foundry.toml before compiling or committing it.
#
# The verifier derives from the vk ALONE, so this needs only bb (pinned via
# toolchain.env) and <artifacts>/<circuit>/vk — no nargo, no recompile.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../toolchain.env
# shellcheck disable=SC1091
source "$ROOT/toolchain.env"

# The contract names consumers compile by. Derived by verifier_name, pinned
# here so a renamed directory fails loudly instead of silently shipping a
# differently-named contract. A new circuit needs no entry; a rename of one
# listed here is a breaking change for every consumer and must be deliberate.
KNOWN_VERIFIERS=(
  bearer-link=BearerLinkHonkVerifier
  oidc-google=OidcGoogleHonkVerifier
)

# bearer-link -> BearerLinkHonkVerifier
verifier_name() {
  local pascal
  pascal="$(printf '%s' "$1" | perl -pe 's/(?:^|-)(\w)/\u$1/g')"
  printf '%sHonkVerifier' "$pascal"
}

usage() {
  echo "usage: $0 <circuit> [<out.sol>] [--artifacts <dir>] [--contract-name X]" >&2
  exit 2
}

circuit=""
out=""
artifacts="$ROOT/artifacts"
contract_name=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifacts) artifacts="${2:?--artifacts needs a directory}"; shift 2 ;;
    --contract-name) contract_name="${2:?--contract-name needs a value}"; shift 2 ;;
    -*) usage ;;
    *)
      if [[ -z "$circuit" ]]; then
        circuit="$1"
      elif [[ -z "$out" ]]; then
        out="$1"
      else
        usage
      fi
      shift ;;
  esac
done
[[ -n "$circuit" ]] || usage

for entry in "${KNOWN_VERIFIERS[@]}"; do
  known="${entry%%=*}"
  want="${entry##*=}"
  if [[ ! -d "$ROOT/circuits/$known" ]]; then
    echo "error: circuits/$known is gone, but consumers compile it as $want." >&2
    echo "  A renamed circuit directory renames the shipped contract; change KNOWN_VERIFIERS in $0 deliberately." >&2
    exit 1
  fi
  got="$(verifier_name "$known")"
  if [[ "$got" != "$want" ]]; then
    echo "error: circuits/$known derives to $got, but consumers compile $want." >&2
    exit 1
  fi
done

[[ -n "$contract_name" ]] || contract_name="$(verifier_name "$circuit")"
[[ -n "$out" ]] || out="$artifacts/$circuit/$contract_name.sol"

vk="$artifacts/$circuit/vk"
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

# Only the concrete contract is renamed; the abstract base keeps its name.
perl -i -pe "s/contract HonkVerifier is BaseZKHonkVerifier/contract ${contract_name} is BaseZKHonkVerifier/g" "$out"

# Fail loudly if bb's output shape moved under the rewrites: consumers look
# the contract up by name and compile under via_ir, so a silently missed
# rewrite breaks them, not us.
concrete="$(grep -c '^contract .* is BaseZKHonkVerifier' "$out" || true)"
if [[ "$concrete" != 1 ]] || ! grep -q "^contract ${contract_name} is BaseZKHonkVerifier" "$out"; then
  echo "error: $out: expected exactly one 'contract ${contract_name} is BaseZKHonkVerifier', found $concrete concrete contract(s)." >&2
  exit 1
fi
if grep -qE 'assembly[[:space:]]*\{' "$out"; then
  echo "error: $out: an assembly block escaped the memory-safe rewrite." >&2
  exit 1
fi

echo "wrote $out (contract $contract_name); consumers run 'forge fmt' under their own foundry.toml before compiling."
