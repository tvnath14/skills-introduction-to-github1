use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use data_encoding::HEXLOWER;
use dirs;
use mdns::{RecordKind, Service};
use rand::RngCore;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, SanType};
use rustls::{pki_types::PrivateKeyDer, server::ServerConfig};
use rustls::{pki_types::CertificateDer};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

use crate::db::open_encrypted_db;

#[derive(Serialize, Deserialize)]
struct SyncMeta {
    device_id: String,
    last_sync: String,
    row_counts: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
struct SyncPayload {
    meta: SyncMeta,
    transactions: Vec<serde_json::Value>,
    categories: Vec<serde_json::Value>,
    settings: Vec<serde_json::Value>,
    secret: String,
}

pub struct SyncServer {
    pub fingerprint: String,
    pub shared_secret: String,
    pub port: u16,
}

pub async fn run_sync_server(master_password: &str) -> Result<SyncServer> {
    let db_path = dirs::data_local_dir()
        .ok_or_else(|| anyhow!("missing data dir"))?
        .join("expense_tracker.db");
    let salt_path = dirs::data_local_dir()
        .ok_or_else(|| anyhow!("missing data dir"))?
        .join("expense_tracker_salt");
    // Ensure database exists and is migrated.
    let _ = open_encrypted_db(master_password, &salt_path, &db_path)?;

    let (cert, key, fingerprint) = generate_certificate()?;
    let shared_secret = random_secret();

    let tls_config = tls_config(cert.clone(), key.clone())?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind("0.0.0.0:0").await?;
    let port = listener.local_addr()?.port();
    let _mdns = broadcast_mdns(port)?;

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => continue,
            };
            let acceptor = acceptor.clone();
            let shared_secret = shared_secret.clone();
            let db_path = db_path.clone();
            let salt_path = salt_path.clone();
            let master_password = master_password.to_string();
            tokio::spawn(async move {
                let result = handle_client(
                    stream,
                    acceptor,
                    &master_password,
                    &salt_path,
                    &db_path,
                    &shared_secret,
                )
                .await;
                if let Err(err) = result {
                    eprintln!("sync session failed: {err:?}");
                }
            });
        }
    });

    Ok(SyncServer {
        fingerprint,
        shared_secret,
        port,
    })
}

fn tls_config(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> Result<ServerConfig> {
    let certs = vec![cert];
    let mut config = ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .context("protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building tls config")?;
    config.alpn_protocols.push(b"tls13".to_vec());
    Ok(config)
}

fn generate_certificate() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>, String)> {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "ExpenseTrackerLAN");
    params
        .subject_alt_names
        .push(SanType::DnsName("expensetracker.local".into()));
    let cert = Certificate::from_params(params)?;
    let key = PrivateKeyDer::Pkcs8(cert.serialize_private_key_der().into());
    let cert_der: CertificateDer<'static> = cert.serialize_der()?.into();
    let fingerprint = sha256_fingerprint(&cert_der);
    Ok((cert_der, key, fingerprint))
}

fn sha256_fingerprint(cert: &CertificateDer<'_>) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(cert);
    let digest = hasher.finalize();
    HEXLOWER.encode(&digest)
}

fn random_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    HEXLOWER.encode(&bytes)
}

fn broadcast_mdns(port: u16) -> Result<mdns::ServiceDaemon> {
    let mdns = mdns::ServiceDaemon::new().context("start mdns daemon")?;
    let service_type = "_expensetracker._tcp".to_string();
    let service_name = "desktop".to_string();
    let service = Service::new(service_name, service_type, port, &["version=1"])?;
    mdns.register(service)?;
    Ok(mdns)
}

async fn handle_client(
    stream: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    master_password: &str,
    salt_path: &std::path::Path,
    db_path: &std::path::Path,
    shared_secret: &str,
) -> Result<()> {
    let tls_stream = acceptor.accept(stream).await?;
    let peer_cert_fp = tls_stream
        .get_ref()
        .0
        .peer_certificates()
        .and_then(|mut certs| certs.pop())
        .map(|cert| sha256_fingerprint(&cert));
    let (reader, mut writer) = tokio::io::split(tls_stream);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    if line.trim().is_empty() {
        return Ok(());
    }
    let payload: SyncPayload = serde_json::from_str(&line)?;
    if payload.secret != shared_secret {
        return Err(anyhow!("shared secret mismatch"));
    }
    if let Some(fp) = &peer_cert_fp {
        let conn = open_encrypted_db(master_password, salt_path, db_path)?;
        let stored: Option<String> = conn
            .query_row(
                "SELECT peer_cert_fingerprint FROM sync_state WHERE device_id = ?1",
                [payload.meta.device_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .context("fetching stored fingerprint")?;
        if let Some(stored_fp) = stored {
            if stored_fp != *fp {
                return Err(anyhow!("pinned certificate mismatch"));
            }
        }
    } else {
        return Err(anyhow!("missing client certificate"));
    }

    let conn = open_encrypted_db(master_password, salt_path, db_path)?;
    conn.execute(
        "INSERT OR REPLACE INTO sync_state (device_id, last_sync, peer_device_name, peer_cert_fingerprint) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![payload.meta.device_id, payload.meta.last_sync, "mobile", peer_cert_fp],
    )?;

    let response = build_payload(&conn, &payload.meta.last_sync)?;
    let serialized = serde_json::to_string(&response)?;
    writer.write_all(serialized.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

fn build_payload(conn: &rusqlite::Connection, since: &str) -> Result<serde_json::Value> {
    let txn_rows = rows_to_json(conn, "SELECT * FROM transactions WHERE updated_at > ?1", &[since])?;
    let cat_rows = rows_to_json(conn, "SELECT * FROM categories WHERE updated_at > ?1", &[since])?;
    let settings = rows_to_json(conn, "SELECT * FROM settings", &[])?;

    let row_counts = conn
        .prepare("SELECT month, COUNT(*) as count FROM transactions GROUP BY month")?
        .query_map([], |row| {
            let month: String = row.get("month")?;
            let count: i64 = row.get("count")?;
            Ok((month, count))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut row_counts_json = serde_json::Map::new();
    for (month, count) in row_counts {
        row_counts_json.insert(month, json!(count));
    }

    Ok(json!({
      "meta": {
        "device_id": Uuid::new_v4().to_string(),
        "last_sync": since,
        "row_counts": row_counts_json
      },
      "transactions": txn_rows,
      "categories": cat_rows,
      "settings": settings
    }))
}

fn rows_to_json(
    conn: &rusqlite::Connection,
    sql: &str,
    params: &[&str],
) -> Result<Vec<serde_json::Value>> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt
        .query_map(params, |row| {
            let mut obj = serde_json::Map::new();
            for (idx, name) in row.as_ref().column_names().iter().enumerate() {
                let value: rusqlite::types::Value = row.get(idx)?;
                let json_value = match value {
                    rusqlite::types::Value::Null => serde_json::Value::Null,
                    rusqlite::types::Value::Integer(v) => json!(v),
                    rusqlite::types::Value::Real(v) => json!(v),
                    rusqlite::types::Value::Text(v) => json!(v),
                    rusqlite::types::Value::Blob(v) => json!(base64::encode(v)),
                };
                obj.insert(name.to_string(), json_value);
            }
            Ok(serde_json::Value::Object(obj))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}
