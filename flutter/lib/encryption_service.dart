import 'dart:convert';
import 'dart:math';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Handles database key generation and per-column AES-GCM encryption for
/// sensitive fields (raw_sms).
class EncryptionService {
  static const _dbKeyStorageKey = 'db_aes_key_v1';
  static const _rawSmsKeyStorageKey = 'raw_sms_key_v1';

  final FlutterSecureStorage _secureStorage;
  final Random _random;
  final AesGcm _aesGcm;

  EncryptionService({
    FlutterSecureStorage? secureStorage,
    Random? random,
    AesGcm? aesGcm,
  })  : _secureStorage =
            secureStorage ?? const FlutterSecureStorage(aOptions: AndroidOptions(encryptedSharedPreferences: true)),
        _random = random ?? Random.secure(),
        _aesGcm = aesGcm ?? AesGcm.with256bits();

  /// Returns a 256-bit key for SQLCipher. Stored only in the Android Keystore
  /// backed secure storage.
  Future<List<int>> obtainDatabaseKey() async {
    final existing = await _secureStorage.read(key: _dbKeyStorageKey);
    if (existing != null) {
      return base64Decode(existing);
    }
    final key = _generateKey();
    await _secureStorage.write(key: _dbKeyStorageKey, value: base64Encode(key));
    return key;
  }

  /// Returns a separate AES-GCM key for encrypting raw_sms column data.
  Future<SecretKey> obtainColumnKey() async {
    final existing = await _secureStorage.read(key: _rawSmsKeyStorageKey);
    if (existing != null) {
      return SecretKey(base64Decode(existing));
    }
    final key = _generateKey();
    await _secureStorage.write(key: _rawSmsKeyStorageKey, value: base64Encode(key));
    return SecretKey(key);
  }

  /// Encrypts the provided plaintext using AES-GCM with a unique nonce.
  Future<String> encryptString(String plaintext) async {
    final secretKey = await obtainColumnKey();
    final nonce = _randomBytes(12);
    final secretBox =
        await _aesGcm.encrypt(utf8.encode(plaintext), secretKey: secretKey, nonce: nonce);
    final payload = <int>[
      ...nonce,
      ...secretBox.cipherText,
      ...secretBox.mac.bytes,
    ];
    return base64Encode(payload);
  }

  /// Decrypts a previously encrypted payload produced by [encryptString].
  Future<String> decryptString(String encodedPayload) async {
    final bytes = base64Decode(encodedPayload);
    final nonce = bytes.sublist(0, 12);
    final mac = Mac(bytes.sublist(bytes.length - 16));
    final cipherText = bytes.sublist(12, bytes.length - 16);
    final secretKey = await obtainColumnKey();
    final secretBox = SecretBox(cipherText, nonce: nonce, mac: mac);
    final clear = await _aesGcm.decrypt(secretBox, secretKey: secretKey);
    return utf8.decode(clear);
  }

  List<int> _generateKey() => List<int>.generate(32, (_) => _random.nextInt(256));

  List<int> _randomBytes(int length) => List<int>.generate(length, (_) => _random.nextInt(256));

  /// Encodes a SQLCipher key as a hex string usable in `PRAGMA key`.
  static String keyToHex(List<int> key) => key.map((e) => e.toRadixString(16).padLeft(2, '0')).join();
}
