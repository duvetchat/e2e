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
| `duvet_e2e` (`flutter/duvet_e2e/rust`) | The Flutter plugin's crate, for the mobile app: flutter_rust_bridge over the core, built by cargokit with `rust-toolchain.toml`'s toolchain and `--locked` (its `builder.dart` is patched for them). |

## Building

The native build compiles SQLCipher and OpenSSL from source, which takes a C compiler, make and perl (on Windows, a native Perl and NASM). The WebAssembly build compiles SQLCipher with clang for `wasm32`.

CI runs every job in `rust:1.99.1-bookworm` (`.github/workflows/ci.yml`). To run the same anywhere with podman or docker, add clang to that image and mount the checkout:

```sh
podman run --rm -v "$PWD:/w" -w /w docker.io/library/rust:1.99.1-bookworm cargo test --workspace
```

## Artifacts

The clients never compile Rust: they take the core as files CI builds. `.github/workflows/artifacts.yml`, started by hand on `main`, builds them with `--release --locked`: Apple's on GitHub's macOS runner, in a job that can't write to the repository, and the rest in `rust:1.99.1-bookworm` on GitHub's Linux runner, whose job then publishes them all as the release `artifacts-<the commit's first 7 characters>`, with one `SHA256SUMS`, once per commit. On a pull request that changes the workflow, it builds and checks them without publishing.

| File | What it is | Who takes it |
|---|---|---|
| `libduvet_e2e_ffi.so` | The C ABI for Linux x64 | The desktop's tests and the API's suites |
| `duvet_e2e_ffi.dll` | The C ABI for Windows x64, cross-compiled with mingw-w64 | The desktop app on Windows |
| `duvet_e2e_wasm.js`, `duvet_e2e_wasm_bg.wasm` | The core in WebAssembly, through `wasm-bindgen --target web` | The web's worker |
| `libduvet_e2e.so` | The Flutter plugin for Linux x64 | The mobile app's Dart tests |
| `android-arm64-v8a-libduvet_e2e.so` | The Flutter plugin for Android arm64-v8a, linked with the runner's NDK for 16 KiB pages | The mobile app, as `jniLibs/arm64-v8a/libduvet_e2e.so` |
| `macos-arm64-libduvet_e2e_ffi.dylib` | The C ABI for macOS 14 and later on arm64 | The desktop app on macOS, and its tests on a Mac |
| `macos-arm64-libduvet_e2e.dylib` | The Flutter plugin for macOS 14 and later on arm64 | The mobile app's Dart tests on a Mac |
| `ios-duvet_e2e.xcframework.zip` | The Flutter plugin for iOS: an XCFramework of one dynamic `duvet_e2e.framework` (named `@rpath/duvet_e2e.framework/duvet_e2e`, as flutter_rust_bridge opens it) for `ios-arm64`, iOS 13 and later, and one for `ios-arm64-simulator`, iOS 14 and later (the first with arm64 simulators) | The mobile app on iOS |

The run fails if the DLL imports anything but Windows' own DLLs (a user's PC has none of mingw-w64's runtime), if the Android library needs anything but `libc`, `libm`, `libdl` and `liblog` or has a segment that isn't aligned to 16 KiB, or if an Apple library needs anything but the system's own (`/usr/lib/`, `/System/Library/`), isn't built for the system and minimum above, isn't arm64 alone or has no valid signature (an ad hoc one at least). Its summary gives each file's size, the checksums, the glibc the Linux libraries need and the system each Apple library is built for.

`.github/workflows/windows.yml`, started by hand with a release's tag, runs `host-tests/bun` against that release's DLL on GitHub's Windows runner, under Bun 1.3.9 (the one Electrobun 1.15.1 ships), with only Windows' own folders on the `PATH`. `.github/workflows/macos.yml` runs the binding's clippy and tests on GitHub's macOS runner, then `host-tests/bun` under Bun 1.3.9: on a pull request that changes the binding or the host tests, against the library it builds, and started by hand with a release's tag, against that release's `macos-arm64-libduvet_e2e_ffi.dylib`.

The host tests' keyring cases run against each system's own keyring: Windows' Credential Manager, macOS's Keychain, and on Linux a Secret Service, in CI's `ffi` job, which runs the tests twice: with no session bus, where the key goes to a file, and under `dbus-run-session` with gnome-keyring unlocked and `DUVET_E2E_SECRET_SERVICE=1`. On macOS they also check that an entry the Keychain refuses to hand over is `storage`, never `bad_key`.
