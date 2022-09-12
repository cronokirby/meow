use core::ops::{Deref, DerefMut};

use zeroize::Zeroize;

/// The number of words in our permutation state.
pub const STATE_SIZE_U64: usize = 25;
/// The number of bytes in our permutation state.
pub const STATE_SIZE_U8: usize = STATE_SIZE_U64 * 8;

/// The Kit-Ten permutation.
///
/// This is a reduced round version of the keccak permutation.
fn kitten(state: &mut [u64; STATE_SIZE_U64]) {
    keccak::keccak_p(state, 10);
}

/// A buffer of bytes which is aligned, so that we can apply our permutation to it.
///
/// Strobe wants to operate on individual bytes, whereas the kitten permutation
/// wants to operate on 64 bit words. To reconcile the two, we need a buffer
/// of bytes which is correctly aligned, so that it can be easily transmuted
/// into a buffer of words, and
#[derive(Clone, Zeroize)]
#[cfg_attr(test, derive(Debug, PartialEq))]
#[repr(align(8))]
pub struct AlignedKittenState(pub [u8; STATE_SIZE_U8]);

impl AlignedKittenState {
    /// Apply the kitten permutation to this state.
    pub fn permute(&mut self) {
        // SAFETY: because we've declared this struct to have an alignment of 8,
        // this transmutation will work
        let state_u64 = unsafe { &mut *(self as *mut Self as *mut [u64; STATE_SIZE_U64]) };
        // In placing bytes into the state, we've always assumed that the u64s
        // are in little endian order. To correct for this on big endian architectures,
        // we need to do the following:
        for state in state_u64.iter_mut() {
            *state = u64::from_le(*state);
        }
        // Now we can safely permute.
        kitten(state_u64);
        // We also need to place the words back in little endian order.
        for state in state_u64.iter_mut() {
            *state = u64::to_le(*state);
        }
    }
}

impl Deref for AlignedKittenState {
    type Target = [u8; STATE_SIZE_U8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AlignedKittenState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod test {
    use super::{AlignedKittenState, STATE_SIZE_U8};

    #[test]
    fn test_permute_changes_state() {
        let data0 = AlignedKittenState([0u8; STATE_SIZE_U8]);
        let mut data1 = data0.clone();
        data1.permute();
        assert_ne!(data0, data1);
    }
}
