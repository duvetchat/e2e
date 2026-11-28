# THIRD-PARTY-NOTICES.txt from cargo-about's JSON for each library the release ships, slurped: each licence
# text once, after the crates it covers. $commit is the release's commit, $clarified the crates
# about.toml clarifies, each of which must have given a text, and $extra the texts no crate ships, which
# notices/generate.sh adds.

# A text cargo-about found keeps its full path; one a clarification gave keeps its path in the crate.
def from_clarification: (.source_path // "/") | startswith("/") | not;
# Texts that differ only in their spacing are one.
def words: gsub("\\s+"; " ") | ltrimstr(" ") | rtrimstr(" ");

def entry:
  "\n================================================================================\n"
  + "\(.name) (\(.id))\n\nUsed by:\n"
  + (.crates | map("    \(.name) \(.version)\n") | add)
  # MPL-2.0 has the source of the files it covers offered with the program.
  + (if .id == "MPL-2.0" then
      "\nSource code: this release is built from https://github.com/duvetchat/e2e/tree/\($commit), whose"
      + " Cargo.lock pins these crates. crates.io publishes the source of each:\n"
      + (.crates | map("    https://static.crates.io/crates/\(.name)/\(.name)-\(.version).crate\n") | add)
    else "" end)
  + "\n\(.text | gsub("\r\n?"; "\n") | rtrimstr("\n"))\n";

[.[].licenses[]]
| ($clarified - [.[] | select(from_clarification) | .used_by[].crate.name]) as $unmatched
| if $unmatched != [] then
    error("no text came from about.toml's clarification of \($unmatched | join(", ")): its files changed, or the crate is gone")
  else . end
| group_by([.id, (.text | words)])
| map({id: .[0].id, name: .[0].name, text: .[0].text, crates: ([.[].used_by[].crate | {name, version}] | unique)})
| . + $extra
| sort_by(.id, .crates[0].name)
| "Third-party notices for Duvet's end-to-end encryption core\n\n"
  + "This release of the core is built from https://github.com/duvetchat/e2e at commit \($commit), as its"
  + " C ABI (duvet-e2e-ffi), its Flutter plugin (duvet_e2e) and its WebAssembly (duvet-e2e-wasm). Below are"
  + " the licences of the crates compiled into them, and of the C libraries some of those crates bundle,"
  + " each licence's text after the crates it covers. A crate that offers a choice of licences is listed"
  + " under the one this release takes.\n"
  + (map(entry) | add)
