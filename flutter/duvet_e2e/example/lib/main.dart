import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:duvet_e2e/duvet_e2e.dart';
import 'package:flutter/material.dart';

/// Opens a database in a new temporary folder, with a random key, and shows its `status`.
Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final random = Random.secure();
  final key = Uint8List.fromList(List.generate(32, (_) => random.nextInt(256)));
  final folder = await Directory.systemTemp.createTemp('duvet-e2e-');

  String status;
  try {
    final core = await DuvetE2e.open(jsonEncode({'path': '${folder.path}/core.db'}), key);
    status = await core.handle('{"cmd":"status"}');
    await core.close();
  } on DuvetE2eException catch (error) {
    status = error.reply;
  }

  runApp(
    MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('duvet_e2e')),
        body: Padding(padding: const EdgeInsets.all(16), child: SelectableText(status)),
      ),
    ),
  );
}
