use std::{fs, path::Path};

use anyhow::{Context, anyhow};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use aws_lc_rs::hkdf::{self, KeyType};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use rand::{RngCore, rngs::OsRng};

#[derive(Clone)]
pub struct MasterKey(pub [u8; 32]);

const CONTEXT_BLOB_MAGIC: &[u8; 4] = b"WBC2";
const CONTEXT_BLOB_SALT: &[u8] = b"website-buu:blob-context:v1";
/// File prefix for DPAPI-protected master key blobs.
const DPAPI_PREFIX: &str = "DPAPI1:";

// ── Windows DPAPI helpers ────────────────────────────────────────────────────

#[cfg(windows)]
fn dpapi_protect(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB};

    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    unsafe {
        let ok = CryptProtectData(
            &in_blob,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            0,
            &mut out_blob,
        );
        if ok == 0 {
            return Err(anyhow!("CryptProtectData failed: {}", std::io::Error::last_os_error()));
        }
        let len = out_blob.cbData as usize;
        let result = std::slice::from_raw_parts(out_blob.pbData, len).to_vec();
        LocalFree(out_blob.pbData as *mut _);
        Ok(result)
    }
}

#[cfg(windows)]
fn dpapi_unprotect(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    unsafe {
        let ok = CryptUnprotectData(
            &in_blob,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            0,
            &mut out_blob,
        );
        if ok == 0 {
            return Err(anyhow!("CryptUnprotectData failed: {}", std::io::Error::last_os_error()));
        }
        let len = out_blob.cbData as usize;
        let result = std::slice::from_raw_parts(out_blob.pbData, len).to_vec();
        LocalFree(out_blob.pbData as *mut _);
        Ok(result)
    }
}

/// Encode key bytes → DPAPI-protected file content (on Windows) or plain base64 (non-Windows).
fn protect_master_key(key: &[u8]) -> anyhow::Result<String> {
    #[cfg(windows)]
    {
        let blob = dpapi_protect(key).context("DPAPI protect master key")?;
        Ok(format!("{}{}", DPAPI_PREFIX, STANDARD.encode(&blob)))
    }
    #[cfg(not(windows))]
    {
        Ok(STANDARD.encode(key))
    }
}

/// Decode master key from file content; auto-detect DPAPI vs legacy plaintext.
fn unprotect_master_key(raw: &str) -> anyhow::Result<Vec<u8>> {
    let trimmed = raw.trim();
    if let Some(b64) = trimmed.strip_prefix(DPAPI_PREFIX) {
        #[cfg(windows)]
        {
            let blob = STANDARD.decode(b64).context("base64 decode DPAPI blob")?;
            return dpapi_unprotect(&blob).context("DPAPI unprotect master key");
        }
        #[cfg(not(windows))]
        {
            // Shouldn't happen, but fall through to error.
            let _ = b64;
            return Err(anyhow!("DPAPI-protected key found but not running on Windows"));
        }
    }
    // Legacy: plain base64
    STANDARD.decode(trimmed).context("base64 decode plain master key")
}

// ────────────────────────────────────────────────────────────────────────────

struct BlobKeyLen;

impl KeyType for BlobKeyLen {
    fn len(&self) -> usize {
        32
    }
}

impl MasterKey {
    pub fn load_or_create(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            let raw = fs::read_to_string(path).context("failed to read master key")?;
            let bytes = unprotect_master_key(&raw)?;
            let key: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow!("master key must be 32 bytes"))?;
            // Migrate plaintext → DPAPI-protected if the file didn't already have the prefix.
            if !raw.trim().starts_with(DPAPI_PREFIX) {
                let protected = protect_master_key(&key)?;
                let _ = fs::write(path, &protected); // best-effort migration
            }
            return Ok(Self(key));
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context("failed to create key directory")?;
        }

        let mut key = [0_u8; 32];
        OsRng.fill_bytes(&mut key);
        let protected = protect_master_key(&key)?;
        fs::write(path, &protected).context("failed to persist master key")?;
        Ok(Self(key))
    }
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| anyhow!("failed to hash password"))?
        .to_string())
}

pub fn verify_password(hash: &str, password: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

pub fn random_token(length: usize) -> String {
    let mut bytes = vec![0_u8; length];
    OsRng.fill_bytes(&mut bytes);
    STANDARD.encode(bytes)
}

pub fn encrypt_blob(master_key: &MasterKey, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new((&master_key.0).into());
    let mut nonce_bytes = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let mut encrypted = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| anyhow!("failed to encrypt data blob"))?;

    let mut output = nonce_bytes.to_vec();
    output.append(&mut encrypted);
    Ok(output)
}

pub fn decrypt_blob(master_key: &MasterKey, encrypted: &[u8]) -> anyhow::Result<Vec<u8>> {
    if encrypted.len() < 24 {
        return Err(anyhow!("encrypted blob is too small"));
    }
    let (nonce_bytes, ciphertext) = encrypted.split_at(24);
    let cipher = XChaCha20Poly1305::new((&master_key.0).into());
    cipher
        .decrypt(XNonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| anyhow!("failed to decrypt data blob"))
}

fn derive_context_blob_key(master_key: &MasterKey, context: &str) -> anyhow::Result<[u8; 32]> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, CONTEXT_BLOB_SALT);
    let prk = salt.extract(&master_key.0);
    let info = [context.as_bytes()];
    let okm = prk
        .expand(&info, BlobKeyLen)
        .map_err(|_| anyhow!("failed to derive blob key"))?;
    let mut derived = [0_u8; 32];
    okm.fill(&mut derived)
        .map_err(|_| anyhow!("failed to materialize blob key"))?;
    Ok(derived)
}

pub fn encrypt_blob_with_context(
    master_key: &MasterKey,
    context: &str,
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let derived_key = derive_context_blob_key(master_key, context)?;
    let cipher = XChaCha20Poly1305::new((&derived_key).into());
    let mut nonce_bytes = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let mut encrypted = cipher
        .encrypt(XNonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| anyhow!("failed to encrypt data blob"))?;

    let mut output = CONTEXT_BLOB_MAGIC.to_vec();
    output.extend_from_slice(&nonce_bytes);
    output.append(&mut encrypted);
    Ok(output)
}

pub fn decrypt_blob_with_context(
    master_key: &MasterKey,
    context: &str,
    encrypted: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if let Some(payload) = encrypted.strip_prefix(CONTEXT_BLOB_MAGIC) {
        if payload.len() < 24 {
            return Err(anyhow!("encrypted blob is too small"));
        }

        let derived_key = derive_context_blob_key(master_key, context)?;
        let (nonce_bytes, ciphertext) = payload.split_at(24);
        let cipher = XChaCha20Poly1305::new((&derived_key).into());
        return cipher
            .decrypt(XNonce::from_slice(nonce_bytes), ciphertext)
            .map_err(|_| anyhow!("failed to decrypt data blob"));
    }

    decrypt_blob(master_key, encrypted)
}

#[cfg(test)]
mod tests {
    use super::{MasterKey, decrypt_blob_with_context, encrypt_blob, encrypt_blob_with_context};

    #[test]
    fn contextual_blob_roundtrip_uses_unique_context_key() {
        let master_key = MasterKey([7_u8; 32]);
        let plaintext = b"confidential table bytes";
        let encrypted =
            encrypt_blob_with_context(&master_key, "main::documents.feather.enc", plaintext)
                .expect("encrypt blob");

        assert_eq!(
            decrypt_blob_with_context(&master_key, "main::documents.feather.enc", &encrypted)
                .expect("decrypt blob"),
            plaintext,
        );
        assert!(
            decrypt_blob_with_context(&master_key, "cache::documents.feather.enc", &encrypted)
                .is_err()
        );
    }

    #[test]
    fn contextual_reader_accepts_legacy_blob_format() {
        let master_key = MasterKey([9_u8; 32]);
        let plaintext = b"legacy bytes";
        let encrypted = encrypt_blob(&master_key, plaintext).expect("encrypt legacy blob");

        assert_eq!(
            decrypt_blob_with_context(&master_key, "main::users.feather.enc", &encrypted)
                .expect("decrypt legacy blob"),
            plaintext,
        );
    }
}
