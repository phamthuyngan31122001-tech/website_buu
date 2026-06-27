//! WOTS+ (Winternitz One-Time Signature Plus) implementation

use crate::address::{Address, AddressType};
use crate::hash::XmssHasher;
use crate::params::{LEN, N, W};
use crate::utils::msg_to_wots_input;

/// WOTS+ signature containing LEN n-byte chain values
#[derive(Clone, Debug)]
pub struct WotsSignature {
    pub sig: Vec<[u8; N]>,
}

impl WotsSignature {
    pub fn new(sig: Vec<[u8; N]>) -> Self {
        assert_eq!(sig.len(), LEN, "WOTS+ signature must have {} elements", LEN);
        Self { sig }
    }

    pub fn len(&self) -> usize {
        self.sig.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sig.is_empty()
    }
}

/// WOTS+ public key containing LEN n-byte values
#[derive(Clone, PartialEq, Eq)]
pub struct WotsPublicKey {
    pub pk: Vec<[u8; N]>,
}

impl WotsPublicKey {
    pub fn new(pk: Vec<[u8; N]>) -> Self {
        assert_eq!(pk.len(), LEN, "WOTS+ public key must have {} elements", LEN);
        Self { pk }
    }
}

/// Compute the chain function: apply F iteratively
pub fn chain<H: XmssHasher>(
    hasher: &H,
    input: &[u8; N],
    start: u32,
    steps: u32,
    public_seed: &[u8; N],
    address: &mut Address,
) -> [u8; N] {
    if steps == 0 {
        return *input;
    }
    let mut result = *input;
    for i in start..(start + steps) {
        address.set_hash_address(i);
        result = hasher.f(&result, public_seed, address);
    }
    result
}

fn wots_sk_element<H: XmssHasher>(
    hasher: &H,
    secret_seed: &[u8; N],
    address: &mut Address,
    chain_idx: u32,
) -> [u8; N] {
    address.set_chain_address(chain_idx);
    address.set_hash_address(0);
    address.set_key_and_mask(0);
    hasher.prf_keygen(secret_seed, address)
}

/// Generate WOTS+ public key from secret seed
pub fn wots_pkgen<H: XmssHasher>(
    hasher: &H,
    secret_seed: &[u8; N],
    public_seed: &[u8; N],
    address: &mut Address,
) -> WotsPublicKey {
    address.set_type(AddressType::Ots);
    let mut pk = Vec::with_capacity(LEN);
    for i in 0..LEN {
        let sk_i = wots_sk_element(hasher, secret_seed, address, i as u32);
        address.set_chain_address(i as u32);
        let pk_i = chain(hasher, &sk_i, 0, (W - 1) as u32, public_seed, address);
        pk.push(pk_i);
    }
    WotsPublicKey::new(pk)
}

/// Sign a message hash using WOTS+
pub fn wots_sign<H: XmssHasher>(
    hasher: &H,
    msg_hash: &[u8; N],
    secret_seed: &[u8; N],
    public_seed: &[u8; N],
    address: &mut Address,
) -> WotsSignature {
    address.set_type(AddressType::Ots);
    let msg_base_w = msg_to_wots_input(msg_hash);
    let mut sig = Vec::with_capacity(LEN);
    for (i, &msg_val) in msg_base_w.iter().enumerate().take(LEN) {
        let sk_i = wots_sk_element(hasher, secret_seed, address, i as u32);
        address.set_chain_address(i as u32);
        let sig_i = chain(hasher, &sk_i, 0, msg_val, public_seed, address);
        sig.push(sig_i);
    }
    WotsSignature::new(sig)
}

/// Compute WOTS+ public key from signature (used in verification)
pub fn wots_pk_from_sig<H: XmssHasher>(
    hasher: &H,
    signature: &WotsSignature,
    msg_hash: &[u8; N],
    public_seed: &[u8; N],
    address: &mut Address,
) -> WotsPublicKey {
    address.set_type(AddressType::Ots);
    let msg_base_w = msg_to_wots_input(msg_hash);
    let mut pk = Vec::with_capacity(LEN);
    for (i, &msg_val) in msg_base_w.iter().enumerate().take(LEN) {
        address.set_chain_address(i as u32);
        let steps = (W as u32) - 1 - msg_val;
        let pk_i = chain(
            hasher,
            &signature.sig[i],
            msg_val,
            steps,
            public_seed,
            address,
        );
        pk.push(pk_i);
    }
    WotsPublicKey::new(pk)
}
