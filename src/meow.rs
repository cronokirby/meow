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
            Role::Undecided => panic!("Undecided role was converted to flag."),
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
    cur_flags: Flags,
}

impl Meow {
    pub fn new(protocol: &[u8]) -> Self {
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

        let mut out = Self {
            state,
            pos: 0,
            pos_begin: 0,
            role: Role::Undecided,
            cur_flags: 0,
        };

        out.meta_ad(protocol, false);

        out
    }

    pub fn ad(&mut self, data: &[u8], more: bool) {
        self.operate::<FLAG_A>(data, more);
    }

    pub fn meta_ad(&mut self, data: &[u8], more: bool) {
        const FLAGS: Flags = FLAG_M | FLAG_A;
        self.operate::<FLAGS>(data, more);
    }

    pub fn key(&mut self, data: &[u8], more: bool) {
        const FLAGS: Flags = FLAG_A | FLAG_C;
        self.operate::<FLAGS>(data, more);
    }

    pub fn send_clr(&mut self, data: &[u8], more: bool) {
        const FLAGS: Flags = FLAG_A | FLAG_T;
        self.operate::<FLAGS>(data, more);
    }

    pub fn recv_clr(&mut self, data: &[u8], more: bool) {
        const FLAGS: Flags = FLAG_I | FLAG_A | FLAG_T;
        self.operate::<FLAGS>(data, more);
    }

    pub fn send_enc(&mut self, data: &[u8], more: bool) {
        const FLAGS: Flags = FLAG_A | FLAG_C | FLAG_T;
        self.operate::<FLAGS>(data, more);
    }

    pub fn recv_enc(&mut self, data: &[u8], more: bool) {
        const FLAGS: Flags = FLAG_I | FLAG_A | FLAG_C | FLAG_T;
        self.operate::<FLAGS>(data, more);
    }

    pub fn send_mac(&mut self, data: &[u8], more: bool) {
        const FLAGS: Flags = FLAG_C | FLAG_T;
        self.operate::<FLAGS>(data, more);
    }

    pub fn recv_mac(&mut self, data: &[u8], more: bool) {
        const FLAGS: Flags = FLAG_I | FLAG_C | FLAG_T;
        self.operate::<FLAGS>(data, more);
    }

    pub fn ratchet(&mut self) {
        self.operate_ratchet::<FLAG_C>(SECURITY_PARAM / 8, false);
    }

    pub fn ratchet_many(&mut self, len: usize, more: bool) {
        self.operate_ratchet::<FLAG_C>(len, more);
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

    #[inline(always)]
    fn advance_pos(&mut self) {
        self.pos += 1;
        if self.pos == MEOW_R {
            self.run_f();
        }
    }

    /// Absorb some data into this sponge.
    fn absorb(&mut self, data: &[u8]) {
        for b in data {
            self.state[self.pos as usize] ^= b;
            self.advance_pos();
        }
    }

    fn overwrite(&mut self, data: &[u8]) {
        for &b in data {
            self.state[self.pos as usize] = b;
            self.advance_pos();
        }
    }

    fn zero_out(&mut self, len: usize) {
        for _ in 0..len {
            self.state[self.pos as usize] = 0;
            self.advance_pos();
        }
    }

    fn duplex<const CBEFORE: bool, const CAFTER: bool>(&mut self, data: &mut [u8]) {
        assert!(!(CBEFORE && CAFTER));
        for b in data {
            let pos = self.pos as usize;
            if CBEFORE {
                *b ^= self.state[pos];
            }
            self.state[pos] ^= *b;
            if CAFTER {
                *b = self.state[pos];
            }
            self.advance_pos();
        }
    }

    /// See: 7.3. Beginning an Operation.
    fn begin_op<const FLAGS: Flags>(&mut self, more: bool) {
        if more {
            assert_eq!(
                self.cur_flags, FLAGS,
                "Cannot continue {:#b} with {:#b}.",
                self.cur_flags, FLAGS
            );
            return;
        }

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

    fn operate<const FLAGS: Flags>(&mut self, data: &[u8], more: bool) {
        assert!(FLAGS & FLAG_K == 0, "Flag K is not implemented.");

        self.begin_op::<FLAGS>(more);

        assert!(
            FLAGS & (FLAG_C | FLAG_T | FLAG_I) != (FLAG_C | FLAG_T),
            "No immutable operations with flags {:#b}.",
            FLAGS
        );

        if FLAGS & FLAG_C != 0 {
            self.overwrite(data);
        } else {
            self.absorb(data);
        }
    }

    fn operate_output<const FLAGS: Flags>(&mut self, data: &mut [u8], more: bool) {
        assert!(FLAGS & FLAG_K == 0, "Flag K is not implemented.");

        self.begin_op::<FLAGS>(more);

        if FLAGS & (FLAG_C | FLAG_I | FLAG_T) == (FLAG_C | FLAG_T) {
            self.duplex::<true, false>(data);
        } else if FLAGS & FLAG_C != 0 {
            self.duplex::<false, true>(data);
        } else {
            self.duplex::<false, false>(data);
        }
    }

    fn operate_ratchet<const FLAGS: Flags>(&mut self, len: usize, more: bool) {
        self.begin_op::<FLAGS>(more);

        self.zero_out(len);
    }
}
