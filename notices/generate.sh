#!/usr/bin/env bash
# Prints the release's THIRD-PARTY-NOTICES.txt: the licences of the crates, and of the C they bundle,
# compiled into each library artifacts.yml builds, counted over that library's own dependencies for the
# systems it's built for. So nothing else counts: not the validator, the fuzz crate or a dev-dependency.
# Usage: notices/generate.sh <commit>, with cargo-about 0.9.3 and jq on the PATH.
set -euo pipefail

commit=${1:?usage: notices/generate.sh <commit>}
cd "$(dirname "$0")/.."
[ "$(cargo about --version)" = "cargo-about 0.9.3" ] || { echo "notices/generate.sh takes cargo-about 0.9.3" >&2; exit 1; }
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

# A library's manifest, then each system artifacts.yml builds it for, one run each: given several,
# cargo-about would also count a dependency one system has of a crate only another has. It fails on a
# licence about.toml doesn't accept. Its log, which warns of the clarifications of crates a run doesn't
# have, is shown when it fails.
library() {
  local manifest=$1 target run
  shift
  for target in "$@"; do
    run="$out/$(basename "$(dirname "$manifest")")-$target"
    cargo about generate --locked --fail --format json --config about.toml --manifest-path "$manifest" \
      --target "$target" --output-file "$run.json" 2> "$run.log" || { cat "$run.log" >&2; return 1; }
  done
}
library crates/duvet-e2e-ffi/Cargo.toml x86_64-unknown-linux-gnu x86_64-pc-windows-gnu aarch64-apple-darwin
library flutter/duvet_e2e/rust/Cargo.toml x86_64-unknown-linux-gnu aarch64-apple-darwin aarch64-linux-android aarch64-apple-ios aarch64-apple-ios-sim
library crates/duvet-e2e-wasm/Cargo.toml wasm32-unknown-unknown

# A licence that names its holders falls back to its standard text only for a crate with no licence file
# of its own: when a crate has one, cargo-about missed it, and about.toml must clarify it.
missed=$(jq -rs '[.[].licenses[] | select(.source_path == null and (.id | IN("MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Zlib", "Unicode-3.0")))
    | .used_by[].crate | "\(.name) \(.version) \(.manifest_path)"] | unique | .[]' "$out"/*.json |
  while read -r name version manifest; do
    files=$(find "$(dirname "$manifest")" -maxdepth 1 \( -iname 'licen[cs]e*' -o -iname 'copying*' -o -iname 'copyright*' \))
    if [ -n "$files" ]; then echo "$name $version"; fi
  done)
[ -z "$missed" ] || { printf 'cargo-about read none of the licence files of these crates, which about.toml must clarify:\n%s\n' "$missed" >&2; exit 1; }

# sqlite-wasm-rs compiles musl's C into the WebAssembly, copied from Emscripten's tree with its changes (the
# repository's shim/musl/README.md), and ships neither musl's COPYRIGHT nor Emscripten's licence. notices/musl
# holds both from https://github.com/emscripten-core/emscripten/tree/ac87d25f7fe06fbfe2460206cd54976bc13618d5,
# its main on 2025-11-06, when 0.6.3's copy came in: system/lib/libc/musl/COPYRIGHT (musl 1.2.5's) and LICENSE.
# Another version may have taken other files: see where they came from, then update notices/musl and these lines.
musl_crate="sqlite-wasm-rs 0.6.3"
found=$(jq -rs '[.[].licenses[].used_by[].crate | select(.name == "sqlite-wasm-rs") | "\(.name) \(.version)"] | unique | join(", ")' "$out"/*.json)
[ "$found" = "$musl_crate" ] || { echo "notices/musl is for $musl_crate, and the release has ${found:-no sqlite-wasm-rs}" >&2; exit 1; }
(cd notices/musl && sha256sum --quiet -c) <<'SUMS'
f9bc4423732350eb0b3f7ed7e91d530298476f8fec0c6c427a1c04ade22655af  COPYRIGHT
620a78084fc7ca97c0b5dea9abf891f3ffcadfdbf305276f099c9c4e12fc1d86  EMSCRIPTEN-LICENSE
SUMS
extra=$(jq -n --arg name "${musl_crate% *}" --arg version "${musl_crate#* }" \
  --rawfile musl notices/musl/COPYRIGHT --rawfile emscripten notices/musl/EMSCRIPTEN-LICENSE \
  '[{name: "musl'"'"'s MIT License", text: $musl}, {name: "Emscripten'"'"'s MIT License", text: $emscripten}]
    | map(. + {id: "MIT", crates: [{name: $name, version: $version}]})')

jq -rs --arg commit "$commit" --argjson clarified "$(sed -n 's/^\[\(.*\)\.clarify\]$/\1/p' about.toml | jq -Rnc '[inputs]')" \
  --argjson extra "$extra" -f notices/render.jq "$out"/*.json
