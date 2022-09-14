// See: https://strobe.sourceforge.io/specs for the specification for STROBE.
use crate::kitten::{AlignedKittenState, STATE_SIZE_U8};
use subtle::{Choice, ConstantTimeEq};
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

#[derive(Clone, Copy, Debug)]
pub struct MacError;

fn check_zero(data: &[u8]) -> Result<(), MacError> {
    let mut ok = Choice::from(1);
    for b in data {
        ok &= b.ct_eq(&0u8);
    }
    if !bool::from(ok) {
        Err(MacError)
    } else {
        Ok(())
    }
}

#[cfg_attr(test, derive(Debug))]
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
        self.begin_op(FLAG_A, more);
        self.absorb(data);
    }

    pub fn meta_ad(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_M | FLAG_A, more);
        self.absorb(data);
    }

    pub fn key(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_A | FLAG_C, more);
        self.overwrite(data);
    }

    pub fn send_clr(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_A | FLAG_T, more);
        self.absorb(data);
    }

    pub fn meta_send_clr(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_M | FLAG_A | FLAG_T, more);
        self.absorb(data);
    }

    pub fn recv_clr(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_I | FLAG_A | FLAG_T, more);
        self.absorb(data);
    }

    pub fn meta_recv_clr(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_M | FLAG_I | FLAG_A | FLAG_T, more);
        self.absorb(data);
    }

    pub fn send_enc(&mut self, data: &mut [u8], more: bool) {
        self.begin_op(FLAG_A | FLAG_C | FLAG_T, more);
        self.absorb_and_set(data);
    }

    pub fn meta_send_enc(&mut self, data: &mut [u8], more: bool) {
        self.begin_op(FLAG_M | FLAG_A | FLAG_C | FLAG_T, more);
        self.absorb_and_set(data);
    }

    pub fn recv_enc(&mut self, data: &mut [u8], more: bool) {
        self.begin_op(FLAG_I | FLAG_A | FLAG_C | FLAG_T, more);
        self.exchange(data);
    }

    pub fn meta_recv_enc(&mut self, data: &mut [u8], more: bool) {
        self.begin_op(FLAG_M | FLAG_I | FLAG_A | FLAG_C | FLAG_T, more);
        self.exchange(data);
    }

    pub fn send_mac(&mut self, data: &mut [u8]) {
        self.begin_op(FLAG_C | FLAG_T, false);
        self.copy(data);
    }

    pub fn meta_send_mac(&mut self, data: &mut [u8]) {
        self.begin_op(FLAG_M | FLAG_C | FLAG_T, false);
        self.copy(data);
    }

    pub fn recv_mac(&mut self, data: &mut [u8]) -> Result<(), MacError> {
        self.begin_op(FLAG_I | FLAG_C | FLAG_T, false);
        self.exchange(data);
        check_zero(data)
    }

    pub fn meta_recv_mac(&mut self, data: &mut [u8]) -> Result<(), MacError> {
        self.begin_op(FLAG_M | FLAG_I | FLAG_C | FLAG_T, false);
        self.exchange(data);
        check_zero(data)
    }

    pub fn prf(&mut self, data: &mut [u8], more: bool) {
        self.begin_op(FLAG_I | FLAG_A | FLAG_C, more);
        self.squeeze(data);
    }

    pub fn ratchet(&mut self) {
        self.ratchet_many(SECURITY_PARAM / 8, false)
    }

    pub fn ratchet_many(&mut self, len: usize, more: bool) {
        self.begin_op(FLAG_C, more);
        self.zero_out(len);
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

    fn absorb_and_set(&mut self, data: &mut [u8]) {
        for b in data {
            self.state[self.pos as usize] ^= *b;
            *b = self.state[self.pos as usize];
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

    fn exchange(&mut self, data: &mut [u8]) {
        for b in data {
            let pos = self.pos as usize;
            *b ^= self.state[pos];
            self.state[pos] ^= *b;
            self.advance_pos();
        }
    }

    fn copy(&mut self, data: &mut [u8]) {
        for b in data {
            let pos = self.pos as usize;
            *b = self.state[pos];
            self.advance_pos();
        }
    }

    fn squeeze(&mut self, data: &mut [u8]) {
        for b in data {
            let pos = self.pos as usize;
            *b = self.state[pos];
            self.state[pos] = 0;
            self.advance_pos();
        }
    }

    /// See: 7.3. Beginning an Operation.
    fn begin_op(&mut self, flags: Flags, more: bool) {
        if more {
            assert_eq!(
                self.cur_flags, flags,
                "Cannot continue {:#b} with {:#b}.",
                self.cur_flags, flags
            );
            return;
        }
        self.cur_flags = flags;

        let flags = if flags & FLAG_T != 0 {
            if let Role::Undecided = self.role {
                self.role = Role::from(flags & FLAG_I);
            }
            flags ^ self.role.to_flag()
        } else {
            flags
        };

        let old_begin = self.pos_begin;
        self.pos_begin = self.pos + 1;

        self.absorb(&[old_begin, flags]);

        let force_f = (flags & (FLAG_C | FLAG_K)) != 0;
        if force_f && self.pos != 0 {
            self.run_f();
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_basic_encryption() {
        let key = [0xAA; 32];
        let message0 = [0xFF; MEOW_R as usize];

        let mut encrypted = message0;
        {
            let mut meow = Meow::new(b"test protocol");
            meow.key(&key, false);
            meow.send_enc(&mut encrypted, false);
        }

        assert_ne!(message0, encrypted);

        let mut message1 = encrypted;
        {
            let mut meow = Meow::new(b"test protocol");
            meow.key(&key, false);
            meow.recv_enc(&mut message1, false);
        }

        assert_eq!(message0, message1);
    }

    #[test]
    fn test_encryption_with_nonce() {
        let key = [0xAA; 32];
        let nonce = [0xBB; 32];
        let message0 = [0xFF; MEOW_R as usize];

        let mut encrypted = message0.to_owned();
        {
            let mut meow = Meow::new(b"test protocol");
            meow.key(&key, false);
            meow.send_clr(&nonce, false);
            meow.send_enc(&mut encrypted, false);
        }

        assert_ne!(message0, encrypted);

        let mut message1 = encrypted.to_owned();
        {
            let mut meow = Meow::new(b"test protocol");
            meow.key(&key, false);
            meow.recv_clr(&nonce, false);
            meow.recv_enc(&mut message1, false);
        }

        assert_eq!(message0, message1);
    }

    #[test]
    fn test_authenticated_encryption() {
        let key = [0xAA; 32];
        let nonce = [0xBB; 32];
        let message0 = [0xFF; MEOW_R as usize];

        let mut mac = [0u8; 32];

        let mut encrypted = message0.to_owned();
        {
            let mut meow = Meow::new(b"test protocol");
            meow.key(&key, false);
            meow.send_clr(&nonce, false);
            meow.send_enc(&mut encrypted, false);
            meow.send_mac(&mut mac);
        }

        assert_ne!(message0, encrypted);

        let mut bad_mac = mac;
        bad_mac[0] ^= 0xFF;

        let mut message1 = encrypted.to_owned();
        {
            let mut meow = Meow::new(b"test protocol");
            meow.key(&key, false);
            meow.recv_clr(&nonce, false);
            meow.recv_enc(&mut message1, false);
            assert!(meow.clone().recv_mac(&mut mac).is_ok());
            assert!(meow.clone().recv_mac(&mut bad_mac).is_err());
        }

        assert_eq!(message0, message1);
    }

    #[test]
    fn test_prf() {
        let mut hash0 = [0u8; 32];
        {
            let mut meow = Meow::new(b"test protocol");
            meow.ad(b"hello A", false);
            meow.prf(&mut hash0, false);
        }

        let mut hash1 = [0u8; 32];
        {
            let mut meow = Meow::new(b"test protocol");
            meow.ad(b"hello B", false);
            meow.prf(&mut hash1, false);
        }

        assert_ne!(hash0, hash1);
    }
}
