# duvet_e2e

The core's Flutter plugin, for the mobile app: `rust/` is a crate of the workspace that wraps
`crates/duvet-e2e` through flutter_rust_bridge 2.13.0 (made with
`flutter_rust_bridge_codegen create duvet_e2e --template plugin`), and cargokit builds it for each
Android ABI as the app builds.

```dart
final core = await DuvetE2e.open(jsonEncode({'path': path}), dbKey); // 32 raw bytes
final reply = await core.handle('{"cmd":"status"}');
await core.close();
```

A failed `open` throws `DuvetE2eException`, whose `reply` is the core's error reply and `code` its
code (`locked`, `bad_key`, `bad_command`...).

`await DuvetE2e.destroy(jsonEncode({'path': path}))` deletes a closed database and SQLite's files
beside it, under the lock an open holds (`locked` while one has it open), and syncs the folder. It
leaves the lock file, and no key: the app deletes the database's key after it returns.

- After changing `rust/src/api`, run `flutter_rust_bridge_codegen generate` here.
- `test/` runs against the core built for the host: `cargo build -p duvet_e2e --release` at the
  workspace's root, then `flutter test` (`DUVET_E2E_LIB` names another library).
- `example/` opens a database and shows its `status`: `flutter build apk --debug` there.
