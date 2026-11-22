# duvet-e2e

Duvet's end-to-end encryption core: MLS (RFC 9420, through OpenMLS) for DMs and groups, the local encrypted database, and the formats around them: envelopes, attachment parts, device-to-device messages, backups and shared history.

It has no network of its own. Clients hand it what the server sent, and send what it returns. Its one entry point takes and returns JSON: `Core::open`, `Core::handle` and `Core::close`.

## Crates

| Crate | What it is |
|---|---|
| `duvet-e2e-rules` | Duvet's group rules, without SQLite: the core checks every commit with them as it applies it, and the API's validator as it accepts it. |
| `duvet-e2e` | The core. |
| `duvet-e2e-validator` | The API's commit validator, a `wasm32-wasip1` module the API runs under wazero. |
| `duvet-e2e-ffi` | The C ABI the desktop's Bun loads. |
| `duvet-e2e-wasm` | The core's WebAssembly build, for the web's worker. |
| `duvet_e2e` (`flutter/duvet_e2e/rust`) | The Flutter plugin's crate, for the mobile app: flutter_rust_bridge over the core, built by cargokit. |

## Building

The native build compiles SQLCipher and OpenSSL from source, which takes a C compiler, make and perl (on Windows, a native Perl and NASM). The WebAssembly build compiles SQLCipher with clang for `wasm32`.

CI runs every job in `rust:1.99.1-bookworm` (`.github/workflows/ci.yml`). To run the same anywhere with podman or docker, add clang to that image and mount the checkout:

```sh
podman run --rm -v "$PWD:/w" -w /w docker.io/library/rust:1.99.1-bookworm cargo test --workspace
```
