//! XMSS (eXtended Merkle Signature Scheme) main API

use crate::address::{Address, AddressType};
use crate::hash::XmssHasher;
use crate::ltree::ltree;
use crate::params::{LEN, MAX_IDX, N, H};
use crate::wots::{WotsSignature, wots_pk_from_sig, wots_sign};
use crate::xmss_tree::{AuthPath, XmssTree, compute_root};

/// Error types for XMSS operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XmssError {
    SignaturesExhausted,
    InvalidSignature,
    InvalidParameter(String),
}

impl std::fmt::Display for XmssError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XmssError::SignaturesExhausted => write!(f, "All one-time signatures have been exhausted"),
            XmssError::InvalidSignature => write!(f, "Invalid signature"),
            XmssError::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
        }
    }
}

impl std::error::Error for XmssError {}

/// XMSS Public Key
#[derive(Clone, PartialEq, Eq)]
pub struct XmssPublicKey {
    pub root: [u8; N],
    pub public_seed: [u8; N],
}

impl XmssPublicKey {
    pub fn new(root: [u8; N], public_seed: [u8; N]) -> Self {
        Self { root, public_seed }
    }

    pub fn to_bytes(&self) -> [u8; 2 * N] {
        let mut bytes = [0u8; 2 * N];
        bytes[0..N].copy_from_slice(&self.root);
        bytes[N..2 * N].copy_from_slice(&self.public_seed);
        bytes
    }

    pub fn from_bytes(bytes: &[u8; 2 * N]) -> Self {
        let mut root = [0u8; N];
        let mut public_seed = [0u8; N];
        root.copy_from_slice(&bytes[0..N]);
        public_seed.copy_from_slice(&bytes[N..2 * N]);
        Self { root, public_seed }
    }
}

/// XMSS Secret Key
#[derive(Clone)]
pub struct XmssSecretKey {
    pub secret_seed: [u8; N],
    pub secret_prf: [u8; N],
    pub public_seed: [u8; N],
    /// Current index. WARNING: reusing an index allows signature forgery.
    pub idx: u32,
    tree: Option<XmssTree>,
}

impl XmssSecretKey {
    pub fn new(secret_seed: [u8; N], secret_prf: [u8; N], public_seed: [u8; N]) -> Self {
        Self {
            secret_seed,
            secret_prf,
            public_seed,
            idx: 0,
            tree: None,
        }
    }

    pub fn index(&self) -> u32 {
        self.idx
    }

    pub fn remaining_signatures(&self) -> u32 {
        if self.idx > MAX_IDX { 0 } else { MAX_IDX - self.idx + 1 }
    }

    fn ensure_tree<Hasher: XmssHasher>(&mut self, hasher: &Hasher) {
        if self.tree.is_none() {
            self.tree = Some(XmssTree::build(hasher, &self.secret_seed, &self.public_seed));
        }
    }

    pub fn root<Hasher: XmssHasher>(&mut self, hasher: &Hasher) -> [u8; N] {
        self.ensure_tree(hasher);
        *self.tree.as_ref().unwrap().root()
    }
}

/// XMSS Signature
#[derive(Clone, Debug)]
pub struct XmssSignature {
    pub idx: u32,
    pub randomness: [u8; N],
    pub wots_sig: WotsSignature,
    pub auth_path: AuthPath,
}

/// Signature size in bytes: 4 (idx) + N (randomness) + LEN*N (wots) + H*N (auth)
pub const SIGNATURE_SIZE: usize = 4 + N + LEN * N + H * N;

impl XmssSignature {
    pub fn size(&self) -> usize {
        SIGNATURE_SIZE
    }

    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        let mut bytes = [0u8; SIGNATURE_SIZE];
        let mut offset = 0;

        bytes[offset..offset + 4].copy_from_slice(&self.idx.to_be_bytes());
        offset += 4;

        bytes[offset..offset + N].copy_from_slice(&self.randomness);
        offset += N;

        for elem in &self.wots_sig.sig {
            bytes[offset..offset + N].copy_from_slice(elem);
            offset += N;
        }

        for elem in &self.auth_path.path {
            bytes[offset..offset + N].copy_from_slice(elem);
            offset += N;
        }

        bytes
    }

    pub fn from_bytes(bytes: &[u8; SIGNATURE_SIZE]) -> Self {
        let mut offset = 0;

        let idx = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        offset += 4;

        let mut randomness = [0u8; N];
        randomness.copy_from_slice(&bytes[offset..offset + N]);
        offset += N;

        let mut wots_sig_data = Vec::with_capacity(LEN);
        for _ in 0..LEN {
            let mut elem = [0u8; N];
            elem.copy_from_slice(&bytes[offset..offset + N]);
            wots_sig_data.push(elem);
            offset += N;
        }
        let wots_sig = WotsSignature::new(wots_sig_data);

        let mut auth_path_data = Vec::with_capacity(H);
        for _ in 0..H {
            let mut elem = [0u8; N];
            elem.copy_from_slice(&bytes[offset..offset + N]);
            auth_path_data.push(elem);
            offset += N;
        }
        let auth_path = AuthPath::new(auth_path_data);

        Self { idx, randomness, wots_sig, auth_path }
    }
}

/// XMSS signature scheme implementation
pub struct Xmss<Hasher: XmssHasher> {
    hasher: Hasher,
}

impl<Hasher: XmssHasher> Xmss<Hasher> {
    pub fn new(hasher: Hasher) -> Self {
        Self { hasher }
    }

    /// Generate an XMSS key pair from a 96-byte seed
    pub fn keygen(&self, seed: &[u8; 96]) -> (XmssPublicKey, XmssSecretKey) {
        let mut secret_seed = [0u8; N];
        let mut secret_prf = [0u8; N];
        let mut public_seed = [0u8; N];

        secret_seed.copy_from_slice(&seed[0..N]);
        secret_prf.copy_from_slice(&seed[N..2 * N]);
        public_seed.copy_from_slice(&seed[2 * N..3 * N]);

        let tree = XmssTree::build(&self.hasher, &secret_seed, &public_seed);
        let root = *tree.root();

        let pk = XmssPublicKey::new(root, public_seed);
        let mut sk = XmssSecretKey::new(secret_seed, secret_prf, public_seed);
        sk.tree = Some(tree);

        (pk, sk)
    }

    /// Sign a message. Mutates the secret key by incrementing the index.
    pub fn sign(
        &self,
        message: &[u8],
        sk: &mut XmssSecretKey,
    ) -> Result<XmssSignature, XmssError> {
        if sk.idx > MAX_IDX {
            return Err(XmssError::SignaturesExhausted);
        }

        let idx = sk.idx;

        sk.ensure_tree(&self.hasher);
        let tree = sk.tree.as_ref().unwrap();

        let mut idx_bytes = [0u8; 32];
        idx_bytes[28..32].copy_from_slice(&idx.to_be_bytes());
        let randomness = self.hasher.prf(&sk.secret_prf, &idx_bytes);

        let msg_hash = self
            .hasher
            .h_msg(&randomness, tree.root(), idx as u64, message);

        let mut address = Address::new();
        address.set_type(AddressType::Ots);
        address.set_ots_address(idx);

        let wots_sig = wots_sign(
            &self.hasher,
            &msg_hash,
            &sk.secret_seed,
            &sk.public_seed,
            &mut address,
        );

        let auth_path = tree.auth_path(idx);
        sk.idx += 1;

        Ok(XmssSignature { idx, randomness, wots_sig, auth_path })
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &XmssSignature, pk: &XmssPublicKey) -> bool {
        if signature.idx > MAX_IDX {
            return false;
        }

        let msg_hash = self.hasher.h_msg(
            &signature.randomness,
            &pk.root,
            signature.idx as u64,
            message,
        );

        let mut address = Address::new();
        address.set_type(AddressType::Ots);
        address.set_ots_address(signature.idx);

        let wots_pk = wots_pk_from_sig(
            &self.hasher,
            &signature.wots_sig,
            &msg_hash,
            &pk.public_seed,
            &mut address,
        );

        address.set_type(AddressType::LTree);
        address.set_ltree_address(signature.idx);
        let leaf = ltree(&self.hasher, &wots_pk, &pk.public_seed, &mut address);

        let computed_root = compute_root(
            &self.hasher,
            &leaf,
            signature.idx,
            &signature.auth_path,
            &pk.public_seed,
        );

        computed_root == pk.root
    }
}
