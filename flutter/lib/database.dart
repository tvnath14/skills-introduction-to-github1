import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;
import 'package:sqflite/sqflite.dart';
import 'package:uuid/uuid.dart';
import 'package:flutter/services.dart' show rootBundle;

import 'encryption_service.dart';

class DatabaseProvider {
  DatabaseProvider._internal(this._encryptionService);

  static final DatabaseProvider _instance =
      DatabaseProvider._internal(EncryptionService());

  factory DatabaseProvider() => _instance;

  final EncryptionService _encryptionService;
  Database? _db;

  Future<Database> get database async {
    if (_db != null) return _db!;
    _db = await _open();
    return _db!;
  }

  Future<Database> _open() async {
    final dbDir = await getDatabasesPath();
    final path = p.join(dbDir, 'expense_tracker.db');
    final key = await _encryptionService.obtainDatabaseKey();

    return openDatabase(
      path,
      version: 1,
      onConfigure: (db) async {
        await db.execute("PRAGMA key = \"x'${EncryptionService.keyToHex(key)}'\";");
        await db.execute('PRAGMA foreign_keys = ON;');
      },
      onCreate: (db, version) async => _migrate(db),
      onUpgrade: (db, oldVersion, newVersion) async => _migrate(db),
    );
  }

  Future<void> _migrate(Database db) async {
    await db.execute('''
      CREATE TABLE IF NOT EXISTS transactions (
        id TEXT PRIMARY KEY,
        date TEXT NOT NULL,
        amount REAL NOT NULL,
        type TEXT NOT NULL CHECK(type IN ('debit','credit')),
        merchant TEXT,
        description TEXT,
        category_id TEXT NOT NULL,
        raw_sms TEXT,
        source TEXT NOT NULL CHECK(source IN ('sms','manual')),
        confidence REAL,
        flagged INTEGER DEFAULT 0,
        month TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        synced_at TEXT
      )
    ''');
    await db.execute('''
      CREATE TABLE IF NOT EXISTS categories (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        icon TEXT,
        is_default INTEGER DEFAULT 0,
        keywords TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    ''');
    await db.execute('''
      CREATE TABLE IF NOT EXISTS sync_state (
        device_id TEXT PRIMARY KEY,
        last_sync TEXT,
        peer_device_name TEXT,
        peer_cert_fingerprint TEXT
      )
    ''');
    await db.execute('''
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      )
    ''');

    await _seedCategories(db);
  }

  Future<void> _seedCategories(Database db) async {
    final now = DateTime.now().toUtc().toIso8601String();
    final defaultsJson = await rootBundle.loadString('shared/default_categories.json');
    final defaults = (jsonDecode(defaultsJson) as List<dynamic>).cast<String>();
    final batch = db.batch();
    for (final name in defaults) {
      batch.insert(
        'categories',
        {
          'id': const Uuid().v4(),
          'name': name,
          'icon': null,
          'is_default': 1,
          'keywords': null,
          'created_at': now,
          'updated_at': now,
        },
        conflictAlgorithm: ConflictAlgorithm.ignore,
      );
    }
    await batch.commit(noResult: true);
  }

  Future<void> insertTransaction(Map<String, dynamic> data) async {
    final db = await database;
    final now = DateTime.now().toUtc().toIso8601String();
    final payload = Map<String, dynamic>.from(data);
    payload['id'] ??= const Uuid().v4();
    payload['created_at'] ??= now;
    payload['updated_at'] = now;
    payload['month'] ??= _deriveMonth(payload['date']);

    final rawSms = payload['raw_sms'];
    if (rawSms is String) {
      payload['raw_sms'] = await _encryptionService.encryptString(rawSms);
    }
    await db.insert('transactions', payload, conflictAlgorithm: ConflictAlgorithm.replace);
  }

  Future<List<Map<String, dynamic>>> fetchDeltas(DateTime lastSync) async {
    final db = await database;
    final iso = lastSync.toUtc().toIso8601String();
    final rows =
        await db.query('transactions', where: 'updated_at > ?', whereArgs: [iso]);
    return rows;
  }

  Future<void> upsertCategory(Map<String, dynamic> data) async {
    final db = await database;
    final now = DateTime.now().toUtc().toIso8601String();
    final payload = Map<String, dynamic>.from(data);
    payload['updated_at'] = now;
    payload['created_at'] ??= now;
    payload['id'] ??= const Uuid().v4();
    await db.insert('categories', payload, conflictAlgorithm: ConflictAlgorithm.replace);
  }

  Future<void> updateSyncedAt(String table, List<String> ids) async {
    if (ids.isEmpty) return;
    final db = await database;
    final now = DateTime.now().toUtc().toIso8601String();
    final placeholders = List.filled(ids.length, '?').join(',');
    await db.update(
      table,
      {'synced_at': now},
      where: 'id IN ($placeholders)',
      whereArgs: ids,
    );
  }

  String? _deriveMonth(dynamic date) {
    if (date == null) return null;
    if (date is String && date.length >= 7) {
      return date.substring(0, 7);
    }
    if (date is DateTime) {
      return date.toIso8601String().substring(0, 7);
    }
    final parsed = DateTime.tryParse(date.toString());
    if (parsed != null) {
      final iso = parsed.toIso8601String();
      return iso.length >= 7 ? iso.substring(0, 7) : null;
    }
    return null;
  }
}
