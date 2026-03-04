// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::path::PathBuf;

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};

use keyring::Entry;
use rand::RngCore;
use std::sync::OnceLock;

/// Returns the encryption key derived from the OS keyring, or falls back to a local file.
/// Generates a random 256-bit key and stores it securely if it doesn't exist.
fn get_or_create_key() -> anyhow::Result<[u8; 32]> {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();

    if let Some(key) = KEY.get() {
        return Ok(*key);
    }

    use base64::{engine::general_purpose::STANDARD, Engine as _};

    // cache_key stores the candidate in the OnceLock and returns whatever value
    // the lock actually holds.  When two threads race to initialize the lock,
    // the loser's candidate is discarded and both threads end up with the
    // winner's key — keeping encrypt/decrypt consistent within a process.
    let cache_key = |candidate: [u8; 32]| -> [u8; 32] {
        if KEY.set(candidate).is_ok() {
            candidate
        } else {
            *KEY.get()
                .expect("OnceLock must be initialized if set() failed")
        }
    };

    let username = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown-user".to_string());

    // The local file is the canonical persistent store. The OS keyring is used
    // as a secondary store when available, but we do not rely on it for
    // cross-process stability because some keyring backends (e.g. the in-memory
    // mock used when no platform feature is enabled) do not survive process
    // restarts, and native backends may require interactive prompts before
    // returning.
    let key_file = crate::auth_commands::config_dir().join(".encryption_key");

    // --- 1. Try file first (primary, always available) ---
    if key_file.exists() {
        if let Ok(b64_key) = std::fs::read_to_string(&key_file) {
            if let Ok(decoded) = STANDARD.decode(b64_key.trim()) {
                if decoded.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&decoded);
                    return Ok(cache_key(arr));
                }
            }
        }
    }

    // --- 2. File not found: try the OS keyring as a fallback source ---
    let entry = Entry::new("gws-cli", &username);
    if let Ok(ref entry) = entry {
        if let Ok(b64_key) = entry.get_password() {
            if let Ok(decoded) = STANDARD.decode(b64_key.trim()) {
                if decoded.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&decoded);
                    // Persist to file so future runs do not need the keyring.
                    write_key_file(&key_file, &b64_key);
                    return Ok(cache_key(arr));
                }
            }
        }
    }

    // --- 3. Neither source has a key: generate a new one ---
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    let b64_key = STANDARD.encode(key);

    // Always write to file first (the reliable persistent store).
    write_key_file(&key_file, &b64_key);

    // Best-effort: also store in the OS keyring for native backends.
    if let Ok(ref entry) = entry {
        let _ = entry.set_password(&b64_key);
    }

    Ok(cache_key(key))
}

/// Writes the base-64 key to the local key file with restrictive permissions.
fn write_key_file(key_file: &std::path::Path, b64_key: &str) {
    if let Some(parent) = key_file.parent() {
        let _ = std::fs::create_dir_all(parent);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        if let Ok(mut file) = options.open(key_file) {
            let _ = file.write_all(b64_key.as_bytes());
        }
    }
    #[cfg(not(unix))]
    {
        let _ = std::fs::write(key_file, b64_key);
    }
}

/// Encrypts plaintext bytes using AES-256-GCM with a machine-derived key.
/// Returns nonce (12 bytes) || ciphertext.
pub fn encrypt(plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let key = get_or_create_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("Failed to create cipher: {e}"))?;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;

    // Prepend nonce to ciphertext
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypts data produced by `encrypt()`.
pub fn decrypt(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    if data.len() < 12 {
        anyhow::bail!("Encrypted data too short");
    }

    let key = get_or_create_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("Failed to create cipher: {e}"))?;

    let nonce = Nonce::from_slice(&data[..12]);
    let plaintext = cipher.decrypt(nonce, &data[12..]).map_err(|_| {
        anyhow::anyhow!(
            "Decryption failed. Credentials may have been created on a different machine. \
                 Run `gws auth logout` and `gws auth login` to re-authenticate."
        )
    })?;

    Ok(plaintext)
}

/// Returns the path for encrypted credentials.
pub fn encrypted_credentials_path() -> PathBuf {
    crate::auth_commands::config_dir().join("credentials.enc")
}

/// Saves credentials JSON to an encrypted file.
pub fn save_encrypted(json: &str) -> anyhow::Result<PathBuf> {
    let path = encrypted_credentials_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }

    let encrypted = encrypt(json.as_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        let mut file = options.open(&path)?;
        use std::io::Write;
        file.write_all(&encrypted)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, encrypted)?;
    }

    Ok(path)
}

/// Loads and decrypts credentials JSON from a specific path.
pub fn load_encrypted_from_path(path: &std::path::Path) -> anyhow::Result<String> {
    let data = std::fs::read(path)?;
    let plaintext = decrypt(&data)?;
    Ok(String::from_utf8(plaintext)?)
}

/// Loads and decrypts credentials JSON from the default encrypted file.
pub fn load_encrypted() -> anyhow::Result<String> {
    load_encrypted_from_path(&encrypted_credentials_path())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let plaintext = b"hello, world!";
        let encrypted = encrypt(plaintext).expect("encryption should succeed");

        // Encrypted data should be different from plaintext
        assert_ne!(&encrypted, plaintext);

        // Should be nonce (12) + ciphertext (plaintext + 16 byte tag)
        assert_eq!(encrypted.len(), 12 + plaintext.len() + 16);

        let decrypted = decrypt(&encrypted).expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_empty() {
        let plaintext = b"";
        let encrypted = encrypt(plaintext).expect("encryption should succeed");
        let decrypted = decrypt(&encrypted).expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_json_credentials() {
        let json = r#"{"type":"authorized_user","client_id":"test.apps.googleusercontent.com","client_secret":"secret","refresh_token":"1//token"}"#;
        let encrypted = encrypt(json.as_bytes()).expect("encryption should succeed");
        let decrypted = decrypt(&encrypted).expect("decryption should succeed");
        assert_eq!(String::from_utf8(decrypted).unwrap(), json);
    }

    #[test]
    fn encrypt_decrypt_large_payload() {
        let plaintext: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
        let encrypted = encrypt(&plaintext).expect("encryption should succeed");
        let decrypted = decrypt(&encrypted).expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_rejects_short_data() {
        let result = decrypt(&[0u8; 11]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let encrypted = encrypt(b"secret data").expect("encryption should succeed");

        // Tamper with the ciphertext (after the 12-byte nonce)
        let mut tampered = encrypted.clone();
        if tampered.len() > 12 {
            tampered[12] ^= 0xFF;
        }

        let result = decrypt(&tampered);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Decryption failed"));
    }

    #[test]
    fn decrypt_rejects_tampered_nonce() {
        let encrypted = encrypt(b"secret data").expect("encryption should succeed");

        let mut tampered = encrypted.clone();
        tampered[0] ^= 0xFF;

        let result = decrypt(&tampered);
        assert!(result.is_err());
    }

    #[test]
    fn each_encryption_produces_different_output() {
        let plaintext = b"same input";
        let enc1 = encrypt(plaintext).expect("encryption should succeed");
        let enc2 = encrypt(plaintext).expect("encryption should succeed");

        // Different nonces should produce different ciphertext
        assert_ne!(enc1, enc2);

        // But both should decrypt to the same plaintext
        let dec1 = decrypt(&enc1).unwrap();
        let dec2 = decrypt(&enc2).unwrap();
        assert_eq!(dec1, dec2);
        assert_eq!(dec1, plaintext);
    }

    #[test]
    fn get_or_create_key_is_deterministic() {
        let key1 = get_or_create_key().unwrap();
        let key2 = get_or_create_key().unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn get_or_create_key_produces_256_bits() {
        let key = get_or_create_key().unwrap();
        assert_eq!(key.len(), 32);
    }
}
