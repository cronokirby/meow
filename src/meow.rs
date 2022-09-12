// See: https://strobe.sourceforge.io/specs for the specification for STROBE.
use crate::kitten::{AlignedKittenState, STATE_SIZE_U8};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// We use a hard coded security parameter of 128 bits.
const SECURITY_PARAM: usize = 128;
/// This is the rate of our sponge, given our security parameter.
const MEOW_R: u8 = (STATE_SIZE_U8 - (2 * SECURITY_PARAM) / 8 - 2) as u8;
/// The context string we use when initializing our construction.
const MEOW_CONTEXT: &[u8] = b"Meow v0.1.0";

// 6.2: Operations and flags.
type Flags = u8;

// Inbound flag. This is set when receiving data.
const FLAG_I: Flags = 0b00000001;
// Application flag. If set, data is moving to or from the application.
const FLAG_A: Flags = 0b00000010;
// Cipher flag. If set, the output depends on the cipher state.
const FLAG_C: Flags = 0b00000100;
// Transport flag. If set, the operation sends or receives dat on the transport.
const FLAG_T: Flags = 0b00001000;
// Meta flag. If set, indicates that the operation is handling metadata.
const FLAG_M: Flags = 0b00010000;
// Keytree flag. It's a mystery.
const FLAG_K: Flags = 0b00100000;

#[derive(Clone, Copy, Debug, PartialEq, Zeroize)]
#[repr(u8)]
enum Role {
    Undecided = 2,
    Initiator = 0,
    Responder = 1,
}

impl Role {
    fn to_flag(self) -> Flags {
        match self {
            Role::Undecided => panic!("undecided rule was converted to flag."),
            Role::Initiator => 0,
            Role::Responder => 1,
        }
    }
}

impl From<u8> for Role {
    fn from(x: u8) -> Self {
        match x {
            0 => Role::Initiator,
            1 => Role::Responder,
            _ => Role::Undecided,
        }
    }
}

#[derive(Clone, ZeroizeOnDrop)]
pub struct Meow {
    state: AlignedKittenState,
    pos: u8,
    pos_begin: u8,
    role: Role,
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
            role: Role::Undecided,
        }
    }
}

impl Meow {
    /// See: 7.1, running F
    fn run_f(&mut self) {
        self.state[self.pos as usize] &= self.pos_begin;
        self.state[self.pos as usize + 1] &= 0x04;
        self.state[MEOW_R as usize + 1] ^= 0x80;
        self.state.permute();
        self.pos = 0;
        self.pos_begin = 0;
    }

    /// Absorb some data into this sponge.
    fn absorb(&mut self, data: &[u8]) {
        for x in data {
            self.state[self.pos as usize] ^= x;
            self.pos += 1;
            if self.pos == MEOW_R {
                self.run_f();
            }
        }
    }

    /// See: 7.3. Beginning an Operation.
    fn begin_op<const FLAGS: Flags>(&mut self) {
        let flags = if FLAGS & FLAG_T != 0 {
            if let Role::Undecided = self.role {
                self.role = Role::from(FLAGS & FLAG_I);
            }
            FLAGS | self.role.to_flag()
        } else {
            FLAGS
        };
        let old_begin = self.pos_begin;
        self.pos_begin = self.pos + 1;
        self.absorb(&[old_begin, flags]);
    }
}
