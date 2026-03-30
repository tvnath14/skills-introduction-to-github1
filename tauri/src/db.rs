use anyhow::{anyhow, Context, Result};
use rusqlite::{params, Connection, OpenFlags};
use serde_json;
use std::path::Path;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::encryption::{derive_master_key, encrypt_string};

const SCHEMA: &[&str] = &[
    r#"CREATE TABLE IF NOT EXISTS transactions (
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
    )"#,
    r#"CREATE TABLE IF NOT EXISTS categories (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      icon TEXT,
      is_default INTEGER DEFAULT 0,
      keywords TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )"#,
    r#"CREATE TABLE IF NOT EXISTS sync_state (
      device_id TEXT PRIMARY KEY,
      last_sync TEXT,
      peer_device_name TEXT,
      peer_cert_fingerprint TEXT
    )"#,
    r#"CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )"#,
];

pub fn open_encrypted_db(master_password: &str, salt_path: &Path, db_path: &Path) -> Result<Connection> {
    let master = derive_master_key(master_password, salt_path)?;
    let conn = Connection::open_with_flags(db_path, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE)
        .context("opening database")?;
    let hex_key = to_hex(&master.key);
    conn.pragma_update(None, "key", format!("x'{hex_key}'")).context("applying SQLCipher key")?;
    migrate(&conn)?;
    Ok(conn)
}

fn migrate(conn: &Connection) -> Result<()> {
    for stmt in SCHEMA {
        conn.execute(stmt, [])?;
    }
    seed_categories(conn)?;
    Ok(())
}

fn seed_categories(conn: &Connection) -> Result<()> {
    let now = OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?;
    let defaults: Vec<String> =
        serde_json::from_str(include_str!("../../shared/default_categories.json"))?;
    let tx = conn.transaction()?;
    for name in defaults {
        tx.execute(
            "INSERT OR IGNORE INTO categories (id, name, icon, is_default, keywords, created_at, updated_at) VALUES (?1, ?2, NULL, 1, NULL, ?3, ?3)",
            params![Uuid::new_v4().to_string(), name, now],
        )?;
    }
    tx.commit()?;
    Ok(())
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn insert_transaction(conn: &Connection, mut txn: serde_json::Value, aes_key: &[u8]) -> Result<()> {
    let now = OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?;
    let obj = txn.as_object_mut().ok_or_else(|| anyhow!("transaction must be object"))?;
    obj.entry("id").or_insert_with(|| serde_json::Value::String(Uuid::new_v4().to_string()));
    obj.insert("updated_at".into(), serde_json::Value::String(now.clone()));
    obj.entry("created_at").or_insert_with(|| serde_json::Value::String(now.clone()));
    if let Some(raw_sms) = obj.get("raw_sms").and_then(|v| v.as_str()) {
        let encrypted = encrypt_string(aes_key, raw_sms)?;
        obj.insert("raw_sms".into(), serde_json::Value::String(encrypted));
    }
    conn.execute(
        "INSERT OR REPLACE INTO transactions (id, date, amount, type, merchant, description, category_id, raw_sms, source, confidence, flagged, month, created_at, updated_at, synced_at) VALUES (:id, :date, :amount, :type, :merchant, :description, :category_id, :raw_sms, :source, :confidence, :flagged, :month, :created_at, :updated_at, :synced_at)",
        rusqlite::named_params! {
            ":id": obj.get("id"),
            ":date": obj.get("date"),
            ":amount": obj.get("amount"),
            ":type": obj.get("type"),
            ":merchant": obj.get("merchant"),
            ":description": obj.get("description"),
            ":category_id": obj.get("category_id"),
            ":raw_sms": obj.get("raw_sms"),
            ":source": obj.get("source"),
            ":confidence": obj.get("confidence"),
            ":flagged": obj.get("flagged"),
            ":month": obj.get("month"),
            ":created_at": obj.get("created_at"),
            ":updated_at": obj.get("updated_at"),
            ":synced_at": obj.get("synced_at"),
        },
    )?;
    Ok(())
}
