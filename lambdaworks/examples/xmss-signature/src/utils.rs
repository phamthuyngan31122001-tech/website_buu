//! Utility functions for XMSS

use crate::params::{LEN, LEN_1, LEN_2, W};

/// Convert a byte array to base-w representation
pub fn base_w(input: &[u8], out_len: usize) -> Vec<u32> {
    let log_w = match W {
        4 => 2,
        16 => 4,
        256 => 8,
        _ => (W as f64).log2() as u32,
    };

    let mut result = vec![0u32; out_len];
    let mut in_idx = 0;
    let mut bits = 0u32;
    let mut total = 0u32;

    for item in result.iter_mut() {
        if bits == 0 {
            if in_idx < input.len() {
                total = input[in_idx] as u32;
                in_idx += 1;
            } else {
                total = 0;
            }
            bits = 8;
        }
        bits -= log_w;
        *item = (total >> bits) & ((W as u32) - 1);
    }

    result
}

/// Compute the checksum for WOTS+ message
pub fn compute_checksum(msg_base_w: &[u32]) -> Vec<u32> {
    let mut csum: u32 = 0;
    for &digit in msg_base_w.iter().take(LEN_1) {
        csum += (W as u32) - 1 - digit;
    }
    let log_w = 4u32;
    let shift = (8 - ((LEN_2 as u32 * log_w) % 8)) % 8;
    csum <<= shift;
    let csum_bytes = csum.to_be_bytes();
    let needed_bytes = (LEN_2 * 4).div_ceil(8);
    let start = 4 - needed_bytes;
    base_w(&csum_bytes[start..], LEN_2)
}

/// Convert message to full WOTS+ input (message + checksum)
pub fn msg_to_wots_input(msg_hash: &[u8; 32]) -> Vec<u32> {
    let mut result = Vec::with_capacity(LEN);
    let msg_base_w = base_w(msg_hash, LEN_1);
    result.extend_from_slice(&msg_base_w);
    let checksum = compute_checksum(&msg_base_w);
    result.extend_from_slice(&checksum);
    result
}
