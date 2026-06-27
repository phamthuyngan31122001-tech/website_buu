//! Hash functions for XMSS
//!
//! This module defines the hash function trait required by XMSS and provides
//! a SHA-256 based implementation following RFC 8391.

use crate::address::Address;
use crate::params::N;
use sha2::{Digest, Sha256};

/// Hash function trait for XMSS
pub trait XmssHasher: Clone + Default {
    fn f(&self, input: &[u8; N], public_seed: &[u8; N], address: &Address) -> [u8; N];
    fn h(
        &self,
        left: &[u8; N],
        right: &[u8; N],
        public_seed: &[u8; N],
        address: &Address,
    ) -> [u8; N];
    fn h_msg(&self, randomness: &[u8; N], root: &[u8; N], index: u64, message: &[u8]) -> [u8; N];
    fn prf(&self, key: &[u8; N], input: &[u8; 32]) -> [u8; N];
    fn prf_keygen(&self, secret_seed: &[u8; N], address: &Address) -> [u8; N];
}

/// SHA-256 based hasher following RFC 8391
#[derive(Clone, Default)]
pub struct Sha256Hasher;

impl Sha256Hasher {
    pub fn new() -> Self {
        Self
    }

    fn prf_internal(&self, key: &[u8; N], input: &[u8]) -> [u8; N] {
        let mut hasher = Sha256::new();
        let mut padding = [0u8; 32];
        padding[31] = 3;
        hasher.update(padding);
        hasher.update(key);
        hasher.update(input);
        let result = hasher.finalize();
        let mut output = [0u8; N];
        output.copy_from_slice(&result);
        output
    }
}

impl XmssHasher for Sha256Hasher {
    fn f(&self, input: &[u8; N], public_seed: &[u8; N], address: &Address) -> [u8; N] {
        let key = self.prf_internal(public_seed, address.as_bytes());
        let mut hasher = Sha256::new();
        let mut padding = [0u8; 32];
        padding[31] = 0;
        hasher.update(padding);
        hasher.update(key);
        hasher.update(input);
        let result = hasher.finalize();
        let mut output = [0u8; N];
        output.copy_from_slice(&result);
        output
    }

    fn h(
        &self,
        left: &[u8; N],
        right: &[u8; N],
        public_seed: &[u8; N],
        address: &Address,
    ) -> [u8; N] {
        let key = self.prf_internal(public_seed, address.as_bytes());
        let mut hasher = Sha256::new();
        let mut padding = [0u8; 32];
        padding[31] = 1;
        hasher.update(padding);
        hasher.update(key);
        hasher.update(left);
        hasher.update(right);
        let result = hasher.finalize();
        let mut output = [0u8; N];
        output.copy_from_slice(&result);
        output
    }

    fn h_msg(&self, randomness: &[u8; N], root: &[u8; N], index: u64, message: &[u8]) -> [u8; N] {
        let mut hasher = Sha256::new();
        let mut padding = [0u8; 32];
        padding[31] = 2;
        hasher.update(padding);
        hasher.update(randomness);
        hasher.update(root);
        let mut idx_bytes = [0u8; 32];
        idx_bytes[24..32].copy_from_slice(&index.to_be_bytes());
        hasher.update(idx_bytes);
        hasher.update(message);
        let result = hasher.finalize();
        let mut output = [0u8; N];
        output.copy_from_slice(&result);
        output
    }

    fn prf(&self, key: &[u8; N], input: &[u8; 32]) -> [u8; N] {
        self.prf_internal(key, input)
    }

    fn prf_keygen(&self, secret_seed: &[u8; N], address: &Address) -> [u8; N] {
        self.prf_internal(secret_seed, address.as_bytes())
    }
}

/// Simple hash of arbitrary data
pub fn hash_message(data: &[u8]) -> [u8; N] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; N];
    output.copy_from_slice(&result);
    output
}
