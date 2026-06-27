//! Minimal user-data lane: client-side encrypted documents authenticated by XMSS.
//!
//! Design (post-PLONK):
//!
//! * Site data is split into two classes:
//!   - **Static site data** (markup, CSS, JS, demo seed) lives in source code
//!     and `runtime/data` and is served as-is.
//!   - **User data** (per-user files, settings, anything secret) flows through
//!     this module. The plaintext is encrypted client-side with
//!     XChaCha20-Poly1305 using a key the client owns; the server only ever
//!     sees the ciphertext.
//!
//! * Authentication uses **XMSS only**. Each user registers an XMSS public key
//!   and signs every submission with it. The server verifies the signature and
//!   rejects any whose index is not strictly greater than the previously stored
//!   one (replay/reuse protection). No PLONK, no SRS, no proof generation.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    models::{new_id, now_string},
    xmss_support::{
        N, SIGNATURE_SIZE, Sha256Hasher, Xmss, XmssPublicKey, XmssSecretKey, XmssSignature,
    },
};

const USERS_FILE_NAME: &str = "external_users.json";
const DOCUMENTS_FILE_NAME: &str = "ciphertext_documents.json";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
pub struct ExternalZkUser {
    pub user_id: String,
    pub display_name: String,
    pub xmss_public_key_b64: String,
    pub last_verified_signature_index: Option<u32>,
    pub status: String,
    pub registered_at: String,
    pub last_seen_at: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ZkUserRegistration {
    pub display_name: String,
    pub xmss_public_key_b64: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ClientXmssIdentity {
    pub display_name: String,
    pub xmss_seed_b64: String,
    pub xmss_public_key_b64: String,
    pub next_index: u32,
    pub server_user_id: Option<String>,
    pub last_submission_at: Option<String>,
    #[serde(skip)]
    pub xmss_secret_key: Option<XmssSecretKey>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CiphertextManifest {
    pub owner_user_id: String,
    pub title: String,
    pub file_name: String,
    pub mime_type: String,
    pub nonce_b64: String,
    pub ciphertext_sha256_b64: String,
    pub uploaded_at: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ClientCiphertextSubmission {
    pub owner_user_id: String,
    pub title: String,
    pub file_name: String,
    pub mime_type: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
    pub ciphertext_sha256_b64: String,
    pub uploaded_at: String,
    pub xmss_public_key_b64: String,
    pub xmss_signature_b64: String,
}

#[derive(Clone)]
pub struct PreparedCiphertextSubmission {
    pub submission: ClientCiphertextSubmission,
    pub decryption_key_b64: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredCiphertextDocument {
    pub document_id: String,
    pub owner_user_id: String,
    pub title: String,
    pub file_name: String,
    pub mime_type: String,
    pub nonce_b64: String,
    pub ciphertext_sha256_b64: String,
    pub ciphertext_path: String,
    pub uploaded_at: String,
    pub stored_at: String,
    pub xmss_public_key_b64: String,
    pub xmss_signature_b64: String,
    pub xmss_signature_idx: u32,
}

/// Wire format returned by `/zk/documents/{id}/package` — combines the stored
/// metadata with the ciphertext bytes so the rightful client can decrypt locally.
#[derive(Clone, Serialize, Deserialize)]
pub struct CiphertextDocumentPackage {
    #[serde(flatten)]
    pub document: StoredCiphertextDocument,
    pub ciphertext_b64: String,
}

// ---------------------------------------------------------------------------
// Server state
// ---------------------------------------------------------------------------

pub struct ZkState {
    base_dir: PathBuf,
    ciphertext_dir: PathBuf,
    users: Vec<ExternalZkUser>,
    documents: Vec<StoredCiphertextDocument>,
}

impl ZkState {
    pub fn load_or_create(base_dir: impl AsRef<Path>) -> anyhow::Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();
        let ciphertext_dir = base_dir.join("ciphertexts");
        fs::create_dir_all(&ciphertext_dir).context("failed to create zk ciphertext directory")?;

        let users_path = base_dir.join(USERS_FILE_NAME);
        let users = if users_path.exists() {
            serde_json::from_slice::<Vec<ExternalZkUser>>(
                &fs::read(&users_path).context("failed to read zk users")?,
            )
            .unwrap_or_default()
        } else {
            fs::write(&users_path, b"[]").context("failed to initialize zk users")?;
            Vec::new()
        };

        let documents_path = base_dir.join(DOCUMENTS_FILE_NAME);
        let documents = if documents_path.exists() {
            serde_json::from_slice::<Vec<StoredCiphertextDocument>>(
                &fs::read(&documents_path).context("failed to read zk documents")?,
            )
            .unwrap_or_default()
        } else {
            fs::write(&documents_path, b"[]")
                .context("failed to initialize zk document metadata")?;
            Vec::new()
        };

        Ok(Self {
            base_dir,
            ciphertext_dir,
            users,
            documents,
        })
    }

    pub fn register_user(
        &mut self,
        registration: ZkUserRegistration,
    ) -> anyhow::Result<ExternalZkUser> {
        if self
            .users
            .iter()
            .any(|user| user.xmss_public_key_b64 == registration.xmss_public_key_b64)
        {
            return Err(anyhow!("XMSS public key is already registered"));
        }
        decode_public_key(&registration.xmss_public_key_b64)?;

        let now = now_string();
        let user = ExternalZkUser {
            user_id: new_id("extuser"),
            display_name: registration.display_name,
            xmss_public_key_b64: registration.xmss_public_key_b64,
            last_verified_signature_index: None,
            status: "online".to_owned(),
            registered_at: now.clone(),
            last_seen_at: now,
        };
        self.users.push(user.clone());
        self.persist_users()?;
        Ok(user)
    }

    pub fn public_users(&self) -> &[ExternalZkUser] {
        &self.users
    }

    pub fn documents(&self) -> &[StoredCiphertextDocument] {
        &self.documents
    }

    pub fn verify_and_store_submission(
        &mut self,
        submission: ClientCiphertextSubmission,
    ) -> anyhow::Result<StoredCiphertextDocument> {
        let Some(user_index) = self
            .users
            .iter()
            .position(|item| item.user_id == submission.owner_user_id)
        else {
            return Err(anyhow!("unknown zk user"));
        };
        if self.users[user_index].xmss_public_key_b64 != submission.xmss_public_key_b64 {
            return Err(anyhow!("submitted XMSS public key does not match registry"));
        }

        let ciphertext = STANDARD
            .decode(submission.ciphertext_b64.as_bytes())
            .context("failed to decode ciphertext payload")?;
        if sha256_b64(&ciphertext) != submission.ciphertext_sha256_b64 {
            return Err(anyhow!("ciphertext hash mismatch"));
        }

        let manifest = CiphertextManifest {
            owner_user_id: submission.owner_user_id.clone(),
            title: submission.title.clone(),
            file_name: submission.file_name.clone(),
            mime_type: submission.mime_type.clone(),
            nonce_b64: submission.nonce_b64.clone(),
            ciphertext_sha256_b64: submission.ciphertext_sha256_b64.clone(),
            uploaded_at: submission.uploaded_at.clone(),
        };
        let signature = verify_manifest_signature(
            &submission.xmss_public_key_b64,
            &submission.xmss_signature_b64,
            &manifest,
        )?;
        if let Some(last_index) = self.users[user_index].last_verified_signature_index
            && signature.idx <= last_index
        {
            return Err(anyhow!("XMSS signature index reuse detected"));
        }

        let document_id = new_id("zkdoc");
        let ciphertext_path = self.ciphertext_dir.join(format!("{}.bin", document_id));
        fs::write(&ciphertext_path, &ciphertext)
            .with_context(|| format!("failed to write {}", ciphertext_path.display()))?;

        let stored = StoredCiphertextDocument {
            document_id,
            owner_user_id: submission.owner_user_id,
            title: submission.title,
            file_name: submission.file_name,
            mime_type: submission.mime_type,
            nonce_b64: submission.nonce_b64,
            ciphertext_sha256_b64: submission.ciphertext_sha256_b64,
            ciphertext_path: ciphertext_path.display().to_string(),
            uploaded_at: submission.uploaded_at,
            stored_at: now_string(),
            xmss_public_key_b64: submission.xmss_public_key_b64,
            xmss_signature_b64: submission.xmss_signature_b64,
            xmss_signature_idx: signature.idx,
        };
        self.documents.push(stored.clone());
        self.users[user_index].last_verified_signature_index = Some(signature.idx);
        self.users[user_index].last_seen_at = now_string();
        self.persist_users()?;
        self.persist_documents()?;
        Ok(stored)
    }

    pub fn ciphertext_package(
        &self,
        document_id: &str,
    ) -> anyhow::Result<CiphertextDocumentPackage> {
        let document = self
            .documents
            .iter()
            .find(|item| item.document_id == document_id)
            .ok_or_else(|| anyhow!("unknown zk document"))?
            .clone();
        let ciphertext = fs::read(&document.ciphertext_path)
            .with_context(|| format!("failed to read {}", document.ciphertext_path))?;
        Ok(CiphertextDocumentPackage {
            document,
            ciphertext_b64: STANDARD.encode(ciphertext),
        })
    }

    fn persist_users(&self) -> anyhow::Result<()> {
        fs::write(
            self.base_dir.join(USERS_FILE_NAME),
            serde_json::to_vec_pretty(&self.users).context("failed to encode zk users")?,
        )
        .context("failed to persist zk users")?;
        Ok(())
    }

    fn persist_documents(&self) -> anyhow::Result<()> {
        fs::write(
            self.base_dir.join(DOCUMENTS_FILE_NAME),
            serde_json::to_vec_pretty(&self.documents).context("failed to encode zk documents")?,
        )
        .context("failed to persist zk documents")?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Client helpers
// ---------------------------------------------------------------------------

pub fn create_client_identity(display_name: &str) -> anyhow::Result<ClientXmssIdentity> {
    let xmss = Xmss::new(Sha256Hasher::new());
    let mut seed = [0_u8; 96];
    OsRng.fill_bytes(&mut seed);
    let (public_key, secret_key) = xmss.keygen(&seed);
    Ok(ClientXmssIdentity {
        display_name: display_name.trim().to_owned(),
        xmss_seed_b64: STANDARD.encode(seed),
        xmss_public_key_b64: STANDARD.encode(public_key.to_bytes()),
        next_index: 0,
        server_user_id: None,
        last_submission_at: None,
        xmss_secret_key: Some(secret_key),
    })
}

pub fn create_prepared_submission(
    identity: &mut ClientXmssIdentity,
    owner_user_id: &str,
    title: &str,
    file_name: &str,
    mime_type: &str,
    plaintext: &[u8],
) -> anyhow::Result<PreparedCiphertextSubmission> {
    let mut key = [0_u8; 32];
    OsRng.fill_bytes(&mut key);
    let (nonce_b64, ciphertext_b64, ciphertext_sha256_b64) =
        encrypt_plaintext_with_key(plaintext, &key)?;
    let uploaded_at = now_string();
    let manifest = CiphertextManifest {
        owner_user_id: owner_user_id.to_owned(),
        title: title.to_owned(),
        file_name: file_name.to_owned(),
        mime_type: mime_type.to_owned(),
        nonce_b64: nonce_b64.clone(),
        ciphertext_sha256_b64: ciphertext_sha256_b64.clone(),
        uploaded_at: uploaded_at.clone(),
    };
    let xmss_signature_b64 = sign_manifest(identity, &manifest)?;
    identity.last_submission_at = Some(now_string());
    Ok(PreparedCiphertextSubmission {
        submission: ClientCiphertextSubmission {
            owner_user_id: owner_user_id.to_owned(),
            title: title.to_owned(),
            file_name: file_name.to_owned(),
            mime_type: mime_type.to_owned(),
            nonce_b64,
            ciphertext_b64,
            ciphertext_sha256_b64,
            uploaded_at,
            xmss_public_key_b64: identity.xmss_public_key_b64.clone(),
            xmss_signature_b64,
        },
        decryption_key_b64: STANDARD.encode(key),
    })
}

pub fn decrypt_ciphertext_package(
    package: &CiphertextDocumentPackage,
    decryption_key_b64: &str,
) -> anyhow::Result<Vec<u8>> {
    let key_bytes = STANDARD
        .decode(decryption_key_b64.as_bytes())
        .map_err(|_| anyhow!("failed to decode submission decryption key"))?;
    if key_bytes.len() != 32 {
        return Err(anyhow!("submission decryption key must be 32 bytes"));
    }
    let nonce = STANDARD
        .decode(package.document.nonce_b64.as_bytes())
        .map_err(|_| anyhow!("failed to decode submission nonce"))?;
    let ciphertext = STANDARD
        .decode(package.ciphertext_b64.as_bytes())
        .map_err(|_| anyhow!("failed to decode submission ciphertext"))?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key_bytes)
        .map_err(|_| anyhow!("invalid submission decryption key"))?;
    cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| anyhow!("failed to decrypt submission package"))
}

fn encrypt_plaintext_with_key(
    plaintext: &[u8],
    key: &[u8; 32],
) -> anyhow::Result<(String, String, String)> {
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new((&key[..]).into());
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow!("failed to encrypt client payload"))?;
    Ok((
        STANDARD.encode(nonce),
        STANDARD.encode(&ciphertext),
        sha256_b64(&ciphertext),
    ))
}

// ---------------------------------------------------------------------------
// XMSS + util helpers
// ---------------------------------------------------------------------------

fn sign_manifest(
    identity: &mut ClientXmssIdentity,
    manifest: &CiphertextManifest,
) -> anyhow::Result<String> {
    let xmss = Xmss::new(Sha256Hasher::new());
    let secret_key = identity
        .xmss_secret_key
        .get_or_insert(reconstruct_secret_key(
            &identity.xmss_seed_b64,
            identity.next_index,
        )?);
    let signature = xmss
        .sign(&manifest_bytes(manifest)?, secret_key)
        .map_err(|error| anyhow!("failed to sign XMSS manifest: {error}"))?;
    identity.next_index = secret_key.idx;
    Ok(STANDARD.encode(signature.to_bytes()))
}

fn verify_manifest_signature(
    public_key_b64: &str,
    signature_b64: &str,
    manifest: &CiphertextManifest,
) -> anyhow::Result<XmssSignature> {
    let xmss = Xmss::new(Sha256Hasher::new());
    let public_key = decode_public_key(public_key_b64)?;
    let signature = decode_signature(signature_b64)?;
    if !xmss.verify(&manifest_bytes(manifest)?, &signature, &public_key) {
        return Err(anyhow!("invalid XMSS signature for ciphertext manifest"));
    }
    Ok(signature)
}

fn decode_public_key(public_key_b64: &str) -> anyhow::Result<XmssPublicKey> {
    let bytes = STANDARD
        .decode(public_key_b64.as_bytes())
        .context("failed to decode XMSS public key")?;
    let bytes: [u8; 2 * N] = bytes
        .try_into()
        .map_err(|_| anyhow!("unexpected XMSS public key size"))?;
    Ok(XmssPublicKey::from_bytes(&bytes))
}

fn reconstruct_secret_key(seed_b64: &str, next_index: u32) -> anyhow::Result<XmssSecretKey> {
    let seed = STANDARD
        .decode(seed_b64.as_bytes())
        .context("failed to decode XMSS seed")?;
    let seed: [u8; 96] = seed
        .try_into()
        .map_err(|_| anyhow!("XMSS seed must be 96 bytes"))?;
    let xmss = Xmss::new(Sha256Hasher::new());
    let (_public_key, mut secret_key) = xmss.keygen(&seed);
    secret_key.idx = next_index;
    Ok(secret_key)
}

fn decode_signature(signature_b64: &str) -> anyhow::Result<XmssSignature> {
    let bytes = STANDARD
        .decode(signature_b64.as_bytes())
        .context("failed to decode XMSS signature")?;
    let bytes: [u8; SIGNATURE_SIZE] = bytes
        .try_into()
        .map_err(|_| anyhow!("unexpected XMSS signature size"))?;
    Ok(XmssSignature::from_bytes(&bytes))
}

fn manifest_bytes(manifest: &CiphertextManifest) -> anyhow::Result<Vec<u8>> {
    serde_json::to_vec(manifest).context("failed to serialize ciphertext manifest")
}

fn sha256_b64(bytes: &[u8]) -> String {
    STANDARD.encode(Sha256::digest(bytes))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_xmss_user_and_round_trips_ciphertext() {
        let base_dir =
            std::env::temp_dir().join(format!("website_buu_zk_test_{}", std::process::id()));
        if base_dir.exists() {
            let _ = std::fs::remove_dir_all(&base_dir);
        }

        let mut state = ZkState::load_or_create(&base_dir).expect("load zk state");
        let mut identity = create_client_identity("Client Alpha").expect("identity");
        let registered = state
            .register_user(ZkUserRegistration {
                display_name: identity.display_name.clone(),
                xmss_public_key_b64: identity.xmss_public_key_b64.clone(),
            })
            .expect("register public user");

        let first_plaintext = b"client side plaintext only";
        let first = create_prepared_submission(
            &mut identity,
            &registered.user_id,
            "ZK demo file",
            "zk-demo.txt",
            "text/plain",
            first_plaintext,
        )
        .expect("signed submission");
        let stored = state
            .verify_and_store_submission(first.submission)
            .expect("store verified submission");

        let package = state
            .ciphertext_package(&stored.document_id)
            .expect("load ciphertext package");
        let decrypted =
            decrypt_ciphertext_package(&package, &first.decryption_key_b64).expect("decrypt");
        assert_eq!(decrypted.as_slice(), first_plaintext);

        let second_plaintext = b"client side plaintext only, second version";
        let second = create_prepared_submission(
            &mut identity,
            &registered.user_id,
            "ZK demo file 2",
            "zk-demo-2.txt",
            "text/plain",
            second_plaintext,
        )
        .expect("second signed submission");
        let second_stored = state
            .verify_and_store_submission(second.submission)
            .expect("store second verified submission");
        let second_package = state
            .ciphertext_package(&second_stored.document_id)
            .expect("load second ciphertext package");
        let second_decrypted =
            decrypt_ciphertext_package(&second_package, &second.decryption_key_b64)
                .expect("decrypt second");

        assert_eq!(second_decrypted.as_slice(), second_plaintext);
        assert_eq!(stored.xmss_signature_idx, 0);
        assert_eq!(second_stored.xmss_signature_idx, 1);
        assert_eq!(state.documents().len(), 2);
        assert_eq!(state.public_users().len(), 1);
        assert_eq!(
            state.public_users()[0].last_verified_signature_index,
            Some(1)
        );

        let _ = std::fs::remove_dir_all(&base_dir);
    }
}
