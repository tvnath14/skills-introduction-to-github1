use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Context, Result};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use std::fs;
use std::io::Write;
use std::path::Path;

pub struct MasterKey {
    pub key: Vec<u8>,
    pub salt: Vec<u8>,
}

const PBKDF2_ITERATIONS: u32 = 100_000;
const SALT_LEN: usize = 16;

pub fn derive_master_key(master_password: &str, salt_path: &Path) -> Result<MasterKey> {
    let salt = if salt_path.exists() {
        fs::read(salt_path).context("reading salt file")?
    } else {
        let mut salt = vec![0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let mut f = fs::File::create(salt_path).context("creating salt file")?;
        f.write_all(&salt).context("writing salt file")?;
        salt
    };

    let mut key = vec![0u8; 32];
    pbkdf2_hmac::<Sha256>(
        master_password.as_bytes(),
        &salt,
        PBKDF2_ITERATIONS,
        &mut key,
    );
    Ok(MasterKey { key, salt })
}

pub fn encrypt_string(key: &[u8], plaintext: &str) -> Result<String> {
    let cipher = Aes256Gcm::new_from_slice(key)?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes())?;
    let mut payload = Vec::from(nonce_bytes);
    payload.extend(ciphertext);
    Ok(base64::encode(payload))
}

pub fn decrypt_string(key: &[u8], payload: &str) -> Result<String> {
    let bytes = base64::decode(payload)?;
    let (nonce_bytes, ciphertext) = bytes.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key)?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let clear = cipher.decrypt(nonce, ciphertext)?;
    Ok(String::from_utf8(clear)?)
}
