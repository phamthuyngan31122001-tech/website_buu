//! L-Tree implementation for XMSS
//!
//! Compresses a WOTS+ public key (LEN elements) into a single n-byte leaf value.

use crate::address::{Address, AddressType};
use crate::hash::XmssHasher;
use crate::params::N;
use crate::wots::WotsPublicKey;

/// Compress a WOTS+ public key into a single leaf value using L-tree
pub fn ltree<H: XmssHasher>(
    hasher: &H,
    wots_pk: &WotsPublicKey,
    public_seed: &[u8; N],
    address: &mut Address,
) -> [u8; N] {
    address.set_type(AddressType::LTree);

    let mut nodes: Vec<[u8; N]> = wots_pk.pk.clone();
    let mut height: u32 = 0;

    while nodes.len() > 1 {
        address.set_tree_height(height);
        let mut parent_nodes = Vec::with_capacity(nodes.len().div_ceil(2));
        let mut i = 0;

        while i + 1 < nodes.len() {
            address.set_tree_index(i as u32 / 2);
            let parent = hasher.h(&nodes[i], &nodes[i + 1], public_seed, address);
            parent_nodes.push(parent);
            i += 2;
        }

        // Promote unpaired last node if odd count
        if i < nodes.len() {
            parent_nodes.push(nodes[i]);
        }

        nodes = parent_nodes;
        height += 1;
    }

    nodes[0]
}
