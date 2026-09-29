#!/usr/bin/env bash
# Check the Solidity verifiers scripts/build.sh wrote, the way a consumer
# uses them:
#
#   1. every <Contract>.sol compiles with solc $SOLC_VERSION on the legacy
#      pipeline (via_ir off, optimizer at 200 runs, EVM cancun, no CBOR
#      metadata) and fits EIP-170's runtime size limit;
#   2. every circuit with a committed witness, circuits/<circuit>/Prover.toml,
#      proves under the pinned toolchain; the proof verifies with `bb verify`,
#      and the verifier deployed to anvil (hardfork osaka) accepts it and
#      rejects it with one bit flipped.
#
#   scripts/check-verifiers.sh [--artifacts <dir>]
#
#   --artifacts <dir>  where scripts/build.sh wrote (default ./artifacts)
#
# Requires the pinned nargo and bb (toolchain.env), Foundry's forge, anvil
# and cast, jq and perl. forge fetches solc $SOLC_VERSION on first use.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../toolchain.env
# shellcheck disable=SC1091
source "$ROOT/toolchain.env"

# The compiler libID-contracts builds the verifiers with.
SOLC_VERSION=0.8.33

usage() {
  echo "usage: $0 [--artifacts <dir>]" >&2
  exit 2
}

artifacts="$ROOT/artifacts"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifacts) artifacts="${2:?--artifacts needs a directory}"; shift 2 ;;
    *) usage ;;
  esac
done
artifacts="$(cd "$artifacts" && pwd)"

for tool in nargo bb forge anvil cast jq perl; do
  command -v "$tool" >/dev/null || { echo "error: $tool is required" >&2; exit 1; }
done
have_nargo="$(nargo --version 2>/dev/null | sed -n 's/^nargo version = //p')"
have_bb="$(bb --version 2>/dev/null | tail -1)"
if [[ "$have_nargo" != "$NARGO_VERSION" || "$have_bb" != "$BB_VERSION" ]]; then
  echo "error: nargo $NARGO_VERSION and bb $BB_VERSION required (toolchain.env), found '$have_nargo' and '$have_bb'." >&2
  exit 1
fi

work="$(mktemp -d)"
anvil_pid=""
cleanup() {
  [[ -z "$anvil_pid" ]] || kill "$anvil_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

# --- Compile ------------------------------------------------------------------
# The settings libID-contracts compiles the verifiers with.
project="$work/project"
mkdir -p "$project/src"
cat > "$project/foundry.toml" <<EOF
[profile.default]
src = "src"
out = "out"
libs = []
solc = "$SOLC_VERSION"
evm_version = "cancun"
via_ir = false
optimizer = true
optimizer_runs = 200
bytecode_hash = "none"
cbor_metadata = false
EOF
contracts=()
for sol in "$artifacts"/*/*HonkVerifier.sol; do
  cp "$sol" "$project/src/"
  contracts+=("$(basename "$sol" .sol)")
done
[[ ${#contracts[@]} -gt 0 ]] || { echo "error: no verifiers under $artifacts (run scripts/build.sh first)" >&2; exit 1; }

echo "==> compile ${contracts[*]} with solc $SOLC_VERSION, legacy pipeline"
# --sizes fails the build when a runtime exceeds EIP-170.
forge build --root "$project" --sizes

# --- Prove and verify ---------------------------------------------------------
rpc="$work/anvil.ipc"
anvil --hardfork osaka --ipc "$rpc" --silent &
anvil_pid=$!
for _ in $(seq 1 100); do
  cast chain-id --rpc-url "$rpc" >/dev/null 2>&1 && break
  sleep 0.1
done
deployer="$(cast rpc --rpc-url "$rpc" eth_accounts | jq -r '.[0]')"

for dir in "$ROOT"/circuits/*/; do
  circuit="$(basename "$dir")"
  [[ -f "$dir/Prover.toml" ]] || continue
  pkg="$(sed -n 's/^name *= *"\(.*\)"/\1/p' "$dir/Nargo.toml")"
  contract="$(basename "$artifacts/$circuit"/*HonkVerifier.sol .sol)"
  out="$work/proof-$circuit"
  echo "==> $circuit: prove circuits/$circuit/Prover.toml"

  (cd "$dir" && nargo execute --silence-warnings "$pkg")
  bb prove -b "$artifacts/$circuit/$pkg.json" -w "$dir/target/$pkg.gz" \
    -k "$artifacts/$circuit/vk" -o "$out" -t evm
  bb verify -p "$out/proof" -i "$out/public_inputs" -k "$artifacts/$circuit/vk" -t evm

  bytecode="$(jq -r '.bytecode.object' "$project/out/$contract.sol/$contract.json")"
  verifier="$(cast send --rpc-url "$rpc" --unlocked --from "$deployer" --json \
    --create "$bytecode" | jq -r '.contractAddress')"

  proof="0x$(perl -0777 -ne 'print unpack("H*", $_)' "$out/proof")"
  inputs="[$(perl -0777 -ne 'print join(",", map { "0x$_" } unpack("(H64)*", $_))' "$out/public_inputs")]"
  accepted="$(cast call --rpc-url "$rpc" "$verifier" 'verify(bytes,bytes32[])(bool)' "$proof" "$inputs")"
  if [[ "$accepted" != true ]]; then
    echo "error: $contract rejected a proof bb verify accepted" >&2
    exit 1
  fi
  gas="$(cast estimate --rpc-url "$rpc" "$verifier" 'verify(bytes,bytes32[])' "$proof" "$inputs")"
  echo "$contract accepts the proof: $gas gas"

  # One bit flipped in the middle of the proof.
  at=$(( ${#proof} / 2 ))
  tampered="${proof:0:at}$(printf '%x' $(( 0x${proof:at:1} ^ 1 )))${proof:at+1}"
  if rejected="$(cast call --rpc-url "$rpc" "$verifier" 'verify(bytes,bytes32[])(bool)' "$tampered" "$inputs" 2>/dev/null)" \
    && [[ "$rejected" == true ]]; then
    echo "error: $contract accepted a tampered proof" >&2
    exit 1
  fi
  echo "$contract rejects the proof with one bit flipped"
done

echo "OK: every verifier compiles; every committed witness proves and verifies on chain"
