use alloc::string::String;
use core::fmt::Write as _;

use sha2::{Digest, Sha256};

/// Incremental SHA-256, compared against a manifest hash at the end. Hash the
/// bytes as they stream so a multi-gigabyte artifact never has to be read twice.
pub struct Sha256Verifier {
    hasher: Sha256,
}

impl Default for Sha256Verifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256Verifier {
    /// Start hashing.
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    /// Feed the next chunk.
    pub fn update(&mut self, chunk: &[u8]) {
        self.hasher.update(chunk);
    }

    /// Finish and return the lowercase hex digest.
    pub fn finish(self) -> String {
        let digest = self.hasher.finalize();
        let mut hex = String::with_capacity(64);
        for byte in digest {
            // Writing to a String cannot fail.
            let _ = write!(hex, "{byte:02x}");
        }
        hex
    }
}

/// Case-insensitive comparison of two hex digests.
pub(crate) fn same_digest(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .all(|(x, y)| x.eq_ignore_ascii_case(&y))
}
