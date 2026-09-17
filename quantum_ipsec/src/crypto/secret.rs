use zeroize::{Zeroize, ZeroizeOnDrop};

/// Owned secret, deliberately neither Clone nor serializable.
/// Rust moves, registers, allocator/OS snapshots and dependency internals are not
/// guaranteed erased by this wrapper. No memory-locking guarantee is made.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize>([u8; N]);
impl<const N: usize> SecretBytes<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }
    pub(crate) fn expose_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}
impl<const N: usize> core::fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}
