use std::{fs, path::Path};

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use anyhow::{Context, anyhow};
use aws_lc_rs::{
    agreement::{self, PrivateKey as AgreementPrivateKey, UnparsedPublicKey},
    encoding::{AsBigEndian, Curve25519SeedBin},
    hkdf::{self, KeyType},
    kem::{DecapsulationKey, EncapsulationKey, ML_KEM_768},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::{RngCore, rngs::OsRng};

const LATIC_KEY_VERSION: &str = "LATIC-X25519-MLKEM768-V1";
const X25519_KEY_LEN: usize = 32;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct StoredKemPublicKey {
    version: String,
    x25519_public_b64: String,
    mlkem_public_b64: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct StoredKemPrivateKey {
    version: String,
    x25519_private_b64: String,
    mlkem_private_b64: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct HybridKemCiphertext {
    version: String,
    x25519_ephemeral_public_b64: String,
    mlkem_ciphertext_b64: String,
}

#[derive(Clone, Copy)]
struct HkdfLen(usize);

impl KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct HybirdEnvelope {
    pub algorithm: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

pub fn load_or_create_kem_pair(
    dir: &Path,
    master_key: &crate::crypto::MasterKey,
) -> anyhow::Result<(String, String)> {
    fs::create_dir_all(dir).context("failed to create hybird key directory")?;
    let public_path = dir.join("hybird_public.b64");
    let private_path = dir.join("hybird_private.b64");
    let legacy_public_path = dir.join("latic_public.b64");
    let legacy_private_path = dir.join("latic_private.b64");
    let removed_legacy_public_path = dir.join("mlkem_public.b64");
    let removed_legacy_private_path = dir.join("mlkem_private.b64");

    const PRIV_CTX: &str = "kem::hybird_private::v1";

    if public_path.exists() && private_path.exists() {
        let public_key =
            fs::read_to_string(&public_path).context("failed to read hybird public key")?;
        let raw_private = fs::read(&private_path).context("failed to read hybird private key")?;
        // Try decrypt as encrypted blob first; fall back to legacy plaintext base64 and migrate.
        let private_key = match crate::crypto::decrypt_blob_with_context(
            master_key, PRIV_CTX, &raw_private,
        ) {
            Ok(bytes) => String::from_utf8(bytes)
                .context("hybird private key is not valid utf-8 after decrypt")?,
            Err(_) => {
                let legacy = String::from_utf8(raw_private)
                    .context("legacy hybird private key is not valid utf-8")?;
                let trimmed = legacy.trim().to_owned();
                let encrypted = crate::crypto::encrypt_blob_with_context(
                    master_key,
                    PRIV_CTX,
                    trimmed.as_bytes(),
                )?;
                fs::write(&private_path, encrypted)
                    .context("failed to migrate hybird private key to encrypted form")?;
                trimmed
            }
        };
        return Ok((public_key.trim().to_owned(), private_key));
    }

    if legacy_public_path.exists() && legacy_private_path.exists() {
        let public_key = fs::read_to_string(&legacy_public_path)
            .context("failed to read legacy latic public key")?;
        let private_key = fs::read_to_string(&legacy_private_path)
            .context("failed to read legacy latic private key")?;
        let pub_trim = public_key.trim().to_owned();
        let priv_trim = private_key.trim().to_owned();
        fs::write(&public_path, &pub_trim).context("failed to migrate hybird public key")?;
        let encrypted = crate::crypto::encrypt_blob_with_context(
            master_key,
            PRIV_CTX,
            priv_trim.as_bytes(),
        )?;
        fs::write(&private_path, encrypted)
            .context("failed to migrate hybird private key (encrypted)")?;
        return Ok((pub_trim, priv_trim));
    }

    if removed_legacy_public_path.exists() || removed_legacy_private_path.exists() {
        return Err(anyhow!(
            "legacy Kyber key material detected; migrate documents with the previous build before upgrading"
        ));
    }

    let (public_key, private_key) = generate_hybrid_keypair()?;

    fs::write(&public_path, &public_key).context("failed to persist hybird public key")?;
    let encrypted =
        crate::crypto::encrypt_blob_with_context(master_key, PRIV_CTX, private_key.as_bytes())?;
    fs::write(&private_path, encrypted).context("failed to persist hybird private key")?;
    Ok((public_key, private_key))
}

pub fn encrypt_document(
    public_key_b64: &str,
    plaintext: &[u8],
) -> anyhow::Result<(String, String, Vec<u8>)> {
    let public_key = parse_public_key(public_key_b64)?;

    let ephemeral_private = AgreementPrivateKey::generate(&agreement::X25519)
        .map_err(|_| anyhow!("failed to generate X25519 ephemeral key"))?;
    let ephemeral_public = ephemeral_private
        .compute_public_key()
        .map_err(|_| anyhow!("failed to compute X25519 public key"))?;
    let x25519_shared =
        compute_x25519_shared_secret(&ephemeral_private, &public_key.x25519_public_b64)?;

    let mlkem_public_bytes = STANDARD
        .decode(public_key.mlkem_public_b64.trim())
        .context("failed to decode ML-KEM public key")?;
    let mlkem_public = EncapsulationKey::new(&ML_KEM_768, &mlkem_public_bytes)
        .map_err(|_| anyhow!("invalid ML-KEM public key"))?;
    let (mlkem_ciphertext, mlkem_shared) = mlkem_public
        .encapsulate()
        .map_err(|_| anyhow!("failed to encapsulate ML-KEM shared secret"))?;

    let document_key = derive_document_key(&x25519_shared, mlkem_shared.as_ref())?;
    let cipher = XChaCha20Poly1305::new((&document_key).into());
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let encrypted = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow!("failed to encrypt document"))?;

    let kem_payload = HybridKemCiphertext {
        version: LATIC_KEY_VERSION.to_owned(),
        x25519_ephemeral_public_b64: STANDARD.encode(ephemeral_public.as_ref()),
        mlkem_ciphertext_b64: STANDARD.encode(mlkem_ciphertext.as_ref()),
    };

    Ok((
        STANDARD.encode(
            serde_json::to_vec(&kem_payload).context("failed to serialize hybrid ciphertext")?,
        ),
        STANDARD.encode(nonce),
        encrypted,
    ))
}

pub fn decrypt_document(
    private_key_b64: &str,
    kem_ciphertext_b64: &str,
    nonce_b64: &str,
    encrypted: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let nonce_bytes = STANDARD
        .decode(nonce_b64.trim())
        .context("failed to decode nonce")?;
    let private_key = parse_private_key(private_key_b64)?;
    let bundle = decode_hybrid_ciphertext(kem_ciphertext_b64)?;
    decrypt_hybrid_document(&private_key, &bundle, &nonce_bytes, encrypted)
}

pub fn encrypt_transport_payload(
    sync_key_b64: &str,
    plaintext: &[u8],
) -> anyhow::Result<HybirdEnvelope> {
    let key_bytes = STANDARD
        .decode(sync_key_b64.trim())
        .context("invalid browser sync key")?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).context("invalid sync cipher key")?;
    let mut nonce_bytes = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| anyhow!("failed to encrypt sync payload"))?;
    Ok(HybirdEnvelope {
        algorithm: "LATIC-SYNC-AES256".to_owned(),
        nonce_b64: STANDARD.encode(nonce_bytes),
        ciphertext_b64: STANDARD.encode(ciphertext),
    })
}

pub fn decrypt_transport_payload(
    sync_key_b64: &str,
    nonce_b64: &str,
    ciphertext_b64: &str,
) -> anyhow::Result<Vec<u8>> {
    let key_bytes = STANDARD
        .decode(sync_key_b64.trim())
        .context("invalid browser sync key")?;
    let nonce_bytes = STANDARD
        .decode(nonce_b64.trim())
        .context("invalid sync nonce")?;
    let ciphertext = STANDARD
        .decode(ciphertext_b64.trim())
        .context("invalid sync ciphertext")?;
    let cipher = Aes256Gcm::new_from_slice(&key_bytes).context("invalid sync cipher key")?;
    cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        .map_err(|_| anyhow!("failed to decrypt sync payload"))
}

fn generate_hybrid_keypair() -> anyhow::Result<(String, String)> {
    let x25519_private = AgreementPrivateKey::generate(&agreement::X25519)
        .map_err(|_| anyhow!("failed to generate X25519 private key"))?;
    let x25519_public = x25519_private
        .compute_public_key()
        .map_err(|_| anyhow!("failed to compute X25519 public key"))?;
    let x25519_private_bytes: Curve25519SeedBin<'static> = x25519_private
        .as_be_bytes()
        .map_err(|_| anyhow!("failed to serialize X25519 private key"))?;

    let mlkem_private = DecapsulationKey::generate(&ML_KEM_768)
        .map_err(|_| anyhow!("failed to generate ML-KEM-768 private key"))?;
    let mlkem_public = mlkem_private
        .encapsulation_key()
        .map_err(|_| anyhow!("failed to derive ML-KEM-768 public key"))?;
    let mlkem_private_bytes = mlkem_private
        .key_bytes()
        .map_err(|_| anyhow!("failed to serialize ML-KEM private key"))?;
    let mlkem_public_bytes = mlkem_public
        .key_bytes()
        .map_err(|_| anyhow!("failed to serialize ML-KEM public key"))?;

    let public_key = StoredKemPublicKey {
        version: LATIC_KEY_VERSION.to_owned(),
        x25519_public_b64: STANDARD.encode(x25519_public.as_ref()),
        mlkem_public_b64: STANDARD.encode(mlkem_public_bytes.as_ref()),
    };
    let private_key = StoredKemPrivateKey {
        version: LATIC_KEY_VERSION.to_owned(),
        x25519_private_b64: STANDARD.encode(x25519_private_bytes.as_ref()),
        mlkem_private_b64: STANDARD.encode(mlkem_private_bytes.as_ref()),
    };

    Ok((
        STANDARD.encode(
            serde_json::to_vec(&public_key).context("failed to encode public key payload")?,
        ),
        STANDARD.encode(
            serde_json::to_vec(&private_key).context("failed to encode private key payload")?,
        ),
    ))
}

fn parse_public_key(public_key_b64: &str) -> anyhow::Result<StoredKemPublicKey> {
    let decoded = STANDARD
        .decode(public_key_b64.trim())
        .context("failed to decode LATIC public key")?;
    let parsed: StoredKemPublicKey =
        serde_json::from_slice(&decoded).context("failed to parse LATIC public key")?;
    if parsed.version != LATIC_KEY_VERSION {
        return Err(anyhow!("unsupported LATIC public key version"));
    }
    Ok(parsed)
}

fn parse_private_key(private_key_b64: &str) -> anyhow::Result<StoredKemPrivateKey> {
    let decoded = STANDARD
        .decode(private_key_b64.trim())
        .context("failed to decode LATIC private key")?;
    let parsed: StoredKemPrivateKey =
        serde_json::from_slice(&decoded).context("failed to parse LATIC private key")?;
    if parsed.version != LATIC_KEY_VERSION {
        return Err(anyhow!("unsupported LATIC private key version"));
    }
    Ok(parsed)
}

fn decode_hybrid_ciphertext(kem_ciphertext_b64: &str) -> anyhow::Result<HybridKemCiphertext> {
    let decoded = STANDARD
        .decode(kem_ciphertext_b64.trim())
        .context("failed to decode hybrid ciphertext payload")?;
    let payload: HybridKemCiphertext =
        serde_json::from_slice(&decoded).context("failed to parse hybrid ciphertext payload")?;
    if payload.version != LATIC_KEY_VERSION {
        return Err(anyhow!("unsupported LATIC ciphertext version"));
    }
    Ok(payload)
}

fn decrypt_hybrid_document(
    private_key: &StoredKemPrivateKey,
    kem_payload: &HybridKemCiphertext,
    nonce_bytes: &[u8],
    encrypted: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let x25519_private = decode_x25519_private_key(&private_key.x25519_private_b64)?;
    let x25519_shared =
        compute_x25519_shared_secret(&x25519_private, &kem_payload.x25519_ephemeral_public_b64)?;

    let mlkem_private_bytes = STANDARD
        .decode(private_key.mlkem_private_b64.trim())
        .context("failed to decode ML-KEM private key")?;
    let mlkem_private = DecapsulationKey::new(&ML_KEM_768, &mlkem_private_bytes)
        .map_err(|_| anyhow!("invalid ML-KEM private key"))?;
    let mlkem_ciphertext_bytes = STANDARD
        .decode(kem_payload.mlkem_ciphertext_b64.trim())
        .context("failed to decode ML-KEM ciphertext")?;
    let mlkem_shared = mlkem_private
        .decapsulate(mlkem_ciphertext_bytes.as_slice().into())
        .map_err(|_| anyhow!("failed to decapsulate ML-KEM ciphertext"))?;

    let document_key = derive_document_key(&x25519_shared, mlkem_shared.as_ref())?;
    let cipher = XChaCha20Poly1305::new((&document_key).into());
    cipher
        .decrypt(XNonce::from_slice(nonce_bytes), encrypted)
        .map_err(|_| anyhow!("failed to decrypt document"))
}

fn decode_x25519_private_key(private_key_b64: &str) -> anyhow::Result<AgreementPrivateKey> {
    let private_key_bytes = STANDARD
        .decode(private_key_b64.trim())
        .context("failed to decode X25519 private key")?;
    if private_key_bytes.len() != X25519_KEY_LEN {
        return Err(anyhow!("invalid X25519 private key length"));
    }
    AgreementPrivateKey::from_private_key(&agreement::X25519, &private_key_bytes)
        .map_err(|_| anyhow!("invalid X25519 private key"))
}

fn compute_x25519_shared_secret(
    private_key: &AgreementPrivateKey,
    peer_public_b64: &str,
) -> anyhow::Result<Vec<u8>> {
    let public_key_bytes = STANDARD
        .decode(peer_public_b64.trim())
        .context("failed to decode X25519 public key")?;
    let peer_key = UnparsedPublicKey::new(&agreement::X25519, public_key_bytes);
    agreement::agree(
        private_key,
        peer_key,
        anyhow!("failed to derive X25519 shared secret"),
        |secret| Ok(secret.to_vec()),
    )
}

fn derive_document_key(x25519_shared: &[u8], mlkem_shared: &[u8]) -> anyhow::Result<[u8; 32]> {
    let mut ikm = Vec::with_capacity(x25519_shared.len() + mlkem_shared.len());
    ikm.extend_from_slice(x25519_shared);
    ikm.extend_from_slice(mlkem_shared);
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, LATIC_KEY_VERSION.as_bytes());
    let prk = salt.extract(&ikm);
    let okm = prk
        .expand(&[b"document-encryption-key"], HkdfLen(32))
        .map_err(|_| anyhow!("failed to expand hybrid shared secret"))?;
    let mut output = [0_u8; 32];
    okm.fill(&mut output)
        .map_err(|_| anyhow!("failed to materialize hybrid document key"))?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngCore, SeedableRng, rngs::StdRng};

    #[test]
    fn hybrid_document_roundtrip() {
        let (public_key_b64, private_key_b64) = generate_hybrid_keypair().expect("keys");
        let plaintext = b"hybrid roundtrip";
        let (kem_ciphertext_b64, nonce_b64, encrypted) =
            encrypt_document(&public_key_b64, plaintext).expect("encrypt");
        let decrypted = decrypt_document(
            &private_key_b64,
            &kem_ciphertext_b64,
            &nonce_b64,
            &encrypted,
        )
        .expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn hybrid_document_roundtrip_varied_plaintexts() {
        let (public_key_b64, private_key_b64) = generate_hybrid_keypair().expect("keys");
        let mut rng = StdRng::seed_from_u64(7);

        for len in [0_usize, 1, 31, 32, 255, 1024, 4096] {
            let mut plaintext = vec![0_u8; len];
            rng.fill_bytes(&mut plaintext);
            let (kem_ciphertext_b64, nonce_b64, encrypted) =
                encrypt_document(&public_key_b64, &plaintext).expect("encrypt");
            let decrypted = decrypt_document(
                &private_key_b64,
                &kem_ciphertext_b64,
                &nonce_b64,
                &encrypted,
            )
            .expect("decrypt");
            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    fn tampered_hybrid_ciphertext_is_rejected() {
        let (public_key_b64, private_key_b64) = generate_hybrid_keypair().expect("keys");
        let (kem_ciphertext_b64, nonce_b64, mut encrypted) =
            encrypt_document(&public_key_b64, b"tamper check").expect("encrypt");
        encrypted[0] ^= 0x80;

        assert!(
            decrypt_document(
                &private_key_b64,
                &kem_ciphertext_b64,
                &nonce_b64,
                &encrypted
            )
            .is_err()
        );
    }

    #[test]
    fn transport_payload_roundtrip_varied_plaintexts() {
        let mut key = [0_u8; 32];
        let mut rng = StdRng::seed_from_u64(19);
        rng.fill_bytes(&mut key);
        let sync_key_b64 = STANDARD.encode(key);

        for len in [0_usize, 3, 64, 1024] {
            let mut plaintext = vec![0_u8; len];
            rng.fill_bytes(&mut plaintext);
            let envelope = encrypt_transport_payload(&sync_key_b64, &plaintext)
                .expect("encrypt transport payload");
            let decrypted = decrypt_transport_payload(
                &sync_key_b64,
                &envelope.nonce_b64,
                &envelope.ciphertext_b64,
            )
            .expect("decrypt transport payload");
            assert_eq!(decrypted, plaintext);
        }
    }
}
