import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:nsd/nsd.dart';
import 'package:sqflite/sqflite.dart';
import 'package:uuid/uuid.dart';

import 'database.dart';
import 'encryption_service.dart';

class PairedDevice {
  final String host;
  final int port;
  final String fingerprint;
  final String sharedSecret;

  PairedDevice({
    required this.host,
    required this.port,
    required this.fingerprint,
    required this.sharedSecret,
  });
}

class SyncClient {
  SyncClient(this._db, this._encryptionService);

  final DatabaseProvider _db;
  final EncryptionService _encryptionService;
  static const _serviceName = '_expensetracker._tcp';

  Future<Service?> discoverDesktop({Duration timeout = const Duration(seconds: 10)}) async {
    final discovery = await startDiscovery(_serviceName, autoResolve: true);
    try {
      return await discovery.services.first.timeout(timeout);
    } on TimeoutException {
      await stopDiscovery(discovery);
      return null;
    } finally {
      await stopDiscovery(discovery);
    }
  }

  /// Parses QR content of form: { "host": "...", "port": 1234, "fingerprint": "...", "secret": "base64" }
  PairedDevice pairFromQr(String qrContent) {
    final decoded = jsonDecode(qrContent) as Map<String, dynamic>;
    return PairedDevice(
      host: decoded['host'] as String,
      port: decoded['port'] as int,
      fingerprint: decoded['fingerprint'] as String,
      sharedSecret: decoded['secret'] as String,
    );
  }

  Future<void> sync(PairedDevice device) async {
    final db = await _db.database;
    final deviceId = await _localDeviceId(db);
    final lastSyncRows = await db.query('sync_state', limit: 1);
    final lastSync = lastSyncRows.isNotEmpty && lastSyncRows.first['last_sync'] != null
        ? DateTime.parse(lastSyncRows.first['last_sync'] as String)
        : DateTime.fromMillisecondsSinceEpoch(0, isUtc: true);

    final deltas = await _db.fetchDeltas(lastSync);
    final categories = await db.query('categories', where: 'updated_at > ?', whereArgs: [lastSync.toIso8601String()]);
    final settings = await db.query('settings');

    final payload = {
      'meta': {
        'device_id': deviceId,
        'last_sync': lastSync.toIso8601String(),
        'row_counts': await _rowCountsPerMonth(),
      },
      'secret': device.sharedSecret,
      'transactions': deltas,
      'categories': categories,
      'settings': settings,
    };

    final socket = await SecureSocket.connect(
      device.host,
      device.port,
      onBadCertificate: (cert) {
        final fp = _fingerprintFromCert(cert);
        return fp == device.fingerprint;
      },
      supportedProtocols: ['tls13'],
    );

    final encoded = const JsonEncoder().convert(payload);
    socket.write(encoded);
    socket.write('\n');

    final response = await socket.transform(utf8.decoder).join();
    if (response.trim().isEmpty) {
      await socket.close();
      return;
    }
    final Map<String, dynamic> remotePayload = jsonDecode(response);
    await _applyRemote(remotePayload);
    await socket.close();

    final now = DateTime.now().toUtc().toIso8601String();
    final remoteMeta = remotePayload['meta'] as Map<String, dynamic>?;
    final remoteDeviceId = remoteMeta != null ? remoteMeta['device_id'] : null;
    await db.insert(
      'sync_state',
      {
        'device_id': remoteDeviceId ?? deviceId,
        'last_sync': now,
        'peer_device_name': device.host,
        'peer_cert_fingerprint': device.fingerprint,
      },
      conflictAlgorithm: ConflictAlgorithm.replace,
    );

    await _db.updateSyncedAt('transactions', deltas.map((e) => e['id'] as String).toList());
    await _db.updateSyncedAt('categories', categories.map((e) => e['id'] as String).toList());
  }

  Future<Map<String, int>> _rowCountsPerMonth() async {
    final db = await _db.database;
    final rows =
        await db.rawQuery('SELECT month, COUNT(*) as count FROM transactions GROUP BY month');
    return {for (final row in rows) row['month'] as String: row['count'] as int};
  }

  Future<void> _applyRemote(Map<String, dynamic> payload) async {
    final db = await _db.database;
    final batch = db.batch();

    for (final cat in payload['categories'] as List<dynamic>? ?? []) {
      batch.insert('categories', Map<String, Object?>.from(cat as Map), conflictAlgorithm: ConflictAlgorithm.replace);
    }

    for (final txn in payload['transactions'] as List<dynamic>? ?? []) {
      batch.insert('transactions', Map<String, Object?>.from(txn as Map),
          conflictAlgorithm: ConflictAlgorithm.replace);
    }

    for (final setting in payload['settings'] as List<dynamic>? ?? []) {
      batch.insert('settings', Map<String, Object?>.from(setting as Map),
          conflictAlgorithm: ConflictAlgorithm.replace);
    }

    await batch.commit(noResult: true);
  }

  String _fingerprintFromCert(X509Certificate cert) {
    final der = cert.der;
    final digest = sha256.convert(der).bytes;
    final buffer = StringBuffer();
    for (final b in digest) {
      buffer.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return buffer.toString();
  }

  Future<String> _localDeviceId(Database db) async {
    final existing =
        await db.query('settings', where: 'key = ?', whereArgs: ['device_id'], limit: 1);
    if (existing.isNotEmpty) {
      return existing.first['value'] as String;
    }
    final newId = const Uuid().v4();
    await db.insert(
      'settings',
      {'key': 'device_id', 'value': newId},
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
    return newId;
  }
}
