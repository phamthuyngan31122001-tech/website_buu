//! XMSS Merkle Tree implementation

use crate::address::{Address, AddressType};
use crate::hash::XmssHasher;
use crate::ltree::ltree;
use crate::params::N;
use crate::wots::wots_pkgen;

/// Authentication path for XMSS signature verification
#[derive(Clone, Debug)]
pub struct AuthPath {
    pub path: Vec<[u8; N]>,
}

impl AuthPath {
    pub fn new(path: Vec<[u8; N]>) -> Self {
        assert_eq!(
            path.len(),
            crate::params::H,
            "Auth path must have {} elements",
            crate::params::H
        );
        Self { path }
    }
}

/// Full XMSS tree containing all nodes
#[derive(Clone)]
pub struct XmssTree {
    nodes: Vec<Vec<[u8; N]>>,
}

impl XmssTree {
    /// Build a complete XMSS tree from seeds
    pub fn build<H: XmssHasher>(hasher: &H, secret_seed: &[u8; N], public_seed: &[u8; N]) -> Self {
        let num_leaves = 1usize << crate::params::H;

        let mut nodes: Vec<Vec<[u8; N]>> = Vec::with_capacity(crate::params::H + 1);

        let mut leaves = Vec::with_capacity(num_leaves);
        for i in 0..num_leaves {
            let leaf = compute_leaf(hasher, secret_seed, public_seed, i as u32);
            leaves.push(leaf);
        }
        nodes.push(leaves);

        let mut address = Address::new();
        address.set_type(AddressType::HashTree);

        for height in 0..crate::params::H {
            let current_level = &nodes[height];
            let num_parents = current_level.len() / 2;
            let mut parent_level = Vec::with_capacity(num_parents);

            address.set_tree_height(height as u32);

            for i in 0..num_parents {
                address.set_tree_index(i as u32);
                let left = &current_level[2 * i];
                let right = &current_level[2 * i + 1];
                let parent = hasher.h(left, right, public_seed, &address);
                parent_level.push(parent);
            }

            nodes.push(parent_level);
        }

        Self { nodes }
    }

    /// Get the root of the tree (XMSS public key)
    pub fn root(&self) -> &[u8; N] {
        &self.nodes[crate::params::H][0]
    }

    /// Get the authentication path for a given leaf index
    pub fn auth_path(&self, leaf_idx: u32) -> AuthPath {
        let mut path = Vec::with_capacity(crate::params::H);
        let mut idx = leaf_idx as usize;

        for height in 0..crate::params::H {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            path.push(self.nodes[height][sibling_idx]);
            idx /= 2;
        }

        AuthPath::new(path)
    }

    /// Get a leaf node by index
    pub fn leaf(&self, idx: u32) -> &[u8; N] {
        &self.nodes[0][idx as usize]
    }
}

/// Compute a single leaf node (L-tree compression of a WOTS+ public key)
pub fn compute_leaf<H: XmssHasher>(
    hasher: &H,
    secret_seed: &[u8; N],
    public_seed: &[u8; N],
    idx: u32,
) -> [u8; N] {
    let mut address = Address::new();

    address.set_type(AddressType::Ots);
    address.set_ots_address(idx);
    let wots_pk = wots_pkgen(hasher, secret_seed, public_seed, &mut address);

    address.set_type(AddressType::LTree);
    address.set_ltree_address(idx);
    ltree(hasher, &wots_pk, public_seed, &mut address)
}

/// Compute root from a leaf and its authentication path (used in verification)
pub fn compute_root<H: XmssHasher>(
    hasher: &H,
    leaf: &[u8; N],
    leaf_idx: u32,
    auth_path: &AuthPath,
    public_seed: &[u8; N],
) -> [u8; N] {
    let mut address = Address::new();
    address.set_type(AddressType::HashTree);

    let mut current = *leaf;
    let mut idx = leaf_idx;

    for height in 0..crate::params::H {
        address.set_tree_height(height as u32);
        address.set_tree_index(idx / 2);

        current = if idx % 2 == 0 {
            hasher.h(&current, &auth_path.path[height], public_seed, &address)
        } else {
            hasher.h(&auth_path.path[height], &current, public_seed, &address)
        };

        idx /= 2;
    }

    current
}
