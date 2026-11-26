// The plugin over the core built for this host: `cargo build -p duvet_e2e --release`, then
// `flutter test` with DUVET_E2E_LIB naming the library (it defaults to the workspace's target).
import 'dart:convert';
import 'dart:io';

import 'package:duvet_e2e/duvet_e2e.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';
import 'package:flutter_test/flutter_test.dart';

const status = '{"cmd":"status"}';

void main() {
  setUpAll(() async {
    final library = Platform.environment['DUVET_E2E_LIB'] ?? '../../target/release/libduvet_e2e.so';
    await DuvetE2e.init(library: ExternalLibrary.open(library));
  });

  String database() => '${Directory.systemTemp.createTempSync('duvet-e2e-').path}/core.db';
  final key = Uint8List.fromList(List.filled(32, 7));

  test('status through the plugin', () async {
    final core = await DuvetE2e.open(jsonEncode({'path': database()}), key);
    final reply = jsonDecode(await core.handle(status)) as Map<String, dynamic>;
    expect(reply['ok']['protocol'], 1);
    expect(reply['ok']['key_storage'], 'provided');
    await core.close();

    final closed = jsonDecode(await core.handle(status)) as Map<String, dynamic>;
    expect(closed['error']['code'], 'not_found');
  });

  test('a second open of the same database is locked', () async {
    final config = jsonEncode({'path': database()});
    final core = await DuvetE2e.open(config, key);
    await expectLater(
      DuvetE2e.open(config, key),
      throwsA(isA<DuvetE2eException>().having((error) => error.code, 'code', 'locked')),
    );
    await core.close();
    await (await DuvetE2e.open(config, key)).close();
  });

  test('destroy deletes a closed database and the files beside it, and leaves its lock', () async {
    final path = database();
    final config = jsonEncode({'path': path});
    final core = await DuvetE2e.open(config, key);
    await expectLater(
      DuvetE2e.destroy(config),
      throwsA(isA<DuvetE2eException>().having((error) => error.code, 'code', 'locked')),
    );
    expect(File(path).existsSync(), isTrue);
    await core.close();

    const beside = ['', '-journal', '-wal', '-shm'];
    for (final suffix in beside.skip(1)) {
      File('$path$suffix').writeAsStringSync("a crash's $suffix");
    }
    await DuvetE2e.destroy(config);
    for (final suffix in beside) {
      expect(File('$path$suffix').existsSync(), isFalse, reason: 'core.db$suffix');
    }
    expect(File('$path.lock').existsSync(), isTrue);

    // Nothing is left to delete, and an open makes a new database.
    await DuvetE2e.destroy(config);
    final fresh = await DuvetE2e.open(config, key);
    final reply = jsonDecode(await fresh.handle(status)) as Map<String, dynamic>;
    expect(reply['ok']['device_id'], isNull);
    await fresh.close();

    await expectLater(
      DuvetE2e.destroy('{}'),
      throwsA(isA<DuvetE2eException>().having((error) => error.code, 'code', 'bad_command')),
    );
  });

  test('a key that is not 32 bytes is bad_command', () async {
    await expectLater(
      DuvetE2e.open(jsonEncode({'path': database()}), Uint8List(31)),
      throwsA(isA<DuvetE2eException>().having((error) => error.code, 'code', 'bad_command')),
    );
  });
}
