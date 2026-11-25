use sha2::{Digest, Sha256};

const BLOCK_SIZE: usize = 64;

/// Pure safe Rust RFC 2104 HMAC-SHA256 hex digest helper.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> String {
    let mut normalized = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hashed = Sha256::digest(key);
        normalized[..hashed.len()].copy_from_slice(&hashed);
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    for idx in 0..BLOCK_SIZE {
        ipad[idx] = normalized[idx] ^ 0x36;
        opad[idx] = normalized[idx] ^ 0x5c;
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let mac = outer.finalize();

    let mut hex = String::with_capacity(mac.len() * 2);
    for byte in mac {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{byte:02x}");
    }
    hex
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4231_hmac_sha256_vectors_match() {
        // Test Case 1
        assert_eq!(
            hmac_sha256(&[0x0bu8; 20], b"Hi There"),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // Test Case 2
        assert_eq!(
            hmac_sha256(b"Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // Test Case 3
        assert_eq!(
            hmac_sha256(&[0xaau8; 20], &[0xddu8; 50]),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
        // Long key > 64 bytes triggers digest folding branch and verifies constant_time_eq
        let long_mac = hmac_sha256(&[0x42u8; 131], b"payload");
        assert_eq!(long_mac.len(), 64);
        assert!(constant_time_eq(long_mac.as_bytes(), long_mac.as_bytes()));
        assert!(!constant_time_eq(long_mac.as_bytes(), b"tampered"));
    }
}
