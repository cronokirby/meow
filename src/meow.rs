// See: https://strobe.sourceforge.io/specs for the specification for STROBE.
use crate::kitten::{AlignedKittenState, STATE_SIZE_U8};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// We use a hard coded security parameter of 128 bits.
const SECURITY_PARAM: usize = 128;
/// This is the rate of our sponge, given our security parameter.
const MEOW_R: usize = STATE_SIZE_U8 - (2 * SECURITY_PARAM) / 8 - 2;
/// The context string we use when initializing our construction.
const MEOW_CONTEXT: &[u8] = b"Meow v0.1.0";

#[derive(Clone, Copy, Debug, PartialEq, Zeroize)]
#[repr(u8)]
enum Role {
    Undecided = 2,
    Initiator = 0,
    Responder = 1,
}

#[derive(Clone, ZeroizeOnDrop)]
pub struct Meow {
    state: AlignedKittenState,
    pos: u8,
    pos_begin: u8,
    i0: Role,
}

impl Meow {
    pub fn new() -> Self {
        let mut state = AlignedKittenState([0u8; STATE_SIZE_U8]);
        // "5.1:
        // The initial state of the object is as follows:
        // st = F([0x01, R+2, 0x01, 0x00, 0x01, 0x60] + ascii("STROBEvX.Y.Z"))
        // pos = posbegin = 0
        // I0 = None"
        //
        // Instead, we use a different context string.
        state[0..6].copy_from_slice(&[0x01, (MEOW_R as u8) + 2, 0x01, 0x00, 0x01, 0x60]);
        state[6..6 + MEOW_CONTEXT.len()].copy_from_slice(MEOW_CONTEXT);
        state.permute();

        Self {
            state,
            pos: 0,
            pos_begin: 0,
            i0: Role::Undecided,
        }
    }
}
