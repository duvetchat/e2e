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

  test('destroy without its folder has nothing to delete', () async {
    final missing = '${Directory.systemTemp.createTempSync('duvet-e2e-').path}/gone';
    await DuvetE2e.destroy(jsonEncode({'path': '$missing/core.db'}));
    expect(Directory(missing).existsSync(), isFalse);
  });

  // A group command through the same JSON: a device founds a DM alone, with no key package of the
  // other member's, types a message there and forgets it, which leaves the message stale (groups.rs'
  // a_lone_device_forgets_the_group_it_founded).
  test("forget_group answers the group's members, and the group is gone", () async {
    final core = await DuvetE2e.open(jsonEncode({'path': database()}), key);
    Future<Map<String, dynamic>> run(Map<String, Object?> command) async =>
        jsonDecode(await core.handle(jsonEncode(command))) as Map<String, dynamic>;
    const user = '01930000-0000-7000-8000-000000000551';
    const other = '01930000-0000-7000-8000-000000000552';
    const conversation = '01930000-0000-7000-8000-000000000553';
    const device = '01930000-0000-7000-8000-000000000554';
    expect((await run({'cmd': 'create_device', 'user_id': user, 'device_id': device}))['ok'], isNotNull);
    expect((await run({'cmd': 'create_identity'}))['ok'], isNotNull);
    final create = {
      'cmd': 'create_group',
      'conversation_id': conversation,
      'kind': 'dm',
      'members': [user, other],
      'external_sender': base64Encode(List.filled(32, 9)),
    };
    expect((await run(create))['ok']['generation'], 0);
    final taken = await run({'cmd': 'commit_result', 'conversation_id': conversation, 'accepted': true, 'seq': 1});
    expect(taken['ok']['epoch'], 1);
    final typed = {
      'cmd': 'encrypt',
      'conversation_id': conversation,
      'nonce': 'typed',
      'envelope': {'text': 'hello'},
    };
    expect((await run(typed))['ok']['epoch'], 1);

    final forget = {'cmd': 'forget_group', 'conversation_id': conversation};
    expect(await run(forget), {
      'ok': {
        'expected': {
          'members': [user, other],
        },
      },
    });
    final stale = await run(typed);
    expect(stale['error'], containsPair('rule', 'stale_message'));
    final gone = await run({'cmd': 'group', 'conversation_id': conversation});
    expect(gone['error'], containsPair('what', 'group'));
    expect((await run(forget))['error'], containsPair('code', 'not_found'));
    // Founded again at generation 0, the group ID the forgotten one had.
    final again = await run({
      ...create,
      'expected': {
        'members': [user, other],
      },
    });
    expect(again['ok']['generation'], 0);
    await core.close();
  });

  test('a key that is not 32 bytes is bad_command', () async {
    await expectLater(
      DuvetE2e.open(jsonEncode({'path': database()}), Uint8List(31)),
      throwsA(isA<DuvetE2eException>().having((error) => error.code, 'code', 'bad_command')),
    );
  });
}
