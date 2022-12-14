use core::fmt;

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

/// Represents the role of a participant.
///
/// This allows one state sending data and another state receiving data to come
/// to the same result. Each of them modifies their role to be either the initiator
/// or the responder, and this allows their state to be synchronized, since
/// both parties agree on their respective roles.
#[derive(Clone, Copy, Debug, PartialEq, Zeroize)]
#[repr(u8)]
enum Role {
    /// We don't know which role we play yet.
    Undecided = 2,
    // We're the first person to send a message.
    Initiator = 0,
    // We're the first person to receive a message.
    Responder = 1,
}

// We also need to be able to convert roles to flags, to include in our state updates.
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

/// A generic error to signal that MAC verification failed.
#[derive(Clone, Copy, Debug)]
pub struct MacError;

impl fmt::Display for MacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MAC failed to verify.")
    }
}

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

/// Represents the state of a Meow instance.
///
/// This is the main object you interact with when using Meow, and all of
/// the functionalities of the framework are derived from methods on this
/// object.
///
/// The basic idea is that each party creates their own local instance
/// of Meow, and then performs various operations in sync, allowing them
/// to hash data, encrypt it, verify its integrity, etc.
///
/// This crate contains examples of composite operations like that in its
/// main documentation.
///
/// This object is cloneable, and that's very useful in certain situations,
/// but one should be careful that the states are identical, and so some operations
/// may not be secure because of common randomness between the states.
///
/// For example, the PRF output from both states will be the same right
/// after forking them.
///
/// Many operations are divided into `send` and `recv` pairs. The idea is that
/// one party performs `send`, sends some data, and then the other party uses
/// `recv` with this data.
///
/// Many operations have a `meta` variant. These variants basically do the
/// same thing as their normal variants, but have a bit of domain separation
/// so that their result is separate.
///
/// Many operations also have a `more` argument. This can be used to split up
/// an operation over multiple calls. For example, you might want to encrypt
/// 1 GB of data as a single logical operation, but without having to store
/// this entire piece of data in memory. Using `more` allows you to do this chunk
/// by chunk, as if it were a single large operation. Each call after the first
/// would set `more = true`, in order to indicate that it's a continuation
/// of the previous call.
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
    /// Create a new Meow instance.
    ///
    /// This function takes in a protocol string, which gets hashed into the state.
    /// The intention is to use this for domain separation of different protocols based on Meow.
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

    /// Absorb additional data into this state.
    ///
    /// This can be used as a way to hash in additional data, such as when
    /// implementing an AEAD, or just a simple hash function.
    ///
    /// The semantics of this are also that each party already knows the data,
    /// and doesn't have to send it to the other person.
    pub fn ad(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_A, more);
        self.absorb(data);
    }

    /// Absorb additional metadata into this state.
    ///
    /// This is intended to be used to describe additional data, or for
    /// framing: describing the operations being done.
    pub fn meta_ad(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_M | FLAG_A, more);
        self.absorb(data);
    }

    /// Include a secret key into the state.
    ///
    /// This makes further operations dependent on knowing this secret key.
    ///
    /// For forward secrecy, the state is also ratcheted.
    pub fn key(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_A | FLAG_C, more);
        self.overwrite(data);
    }

    /// Send some plaintext data to the other party.
    ///
    /// This is similar to `ad`, except the semantics are that the other person
    /// will not already know this information, and so we additionally have
    /// to send it to them.
    pub fn send_clr(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_A | FLAG_T, more);
        self.absorb(data);
    }

    /// Send some plaintext metadata to the other party.
    ///
    /// Similarly to `send_clr`, the semantics are that the other party doesn't
    /// know this information, and we need to send it to them.
    pub fn meta_send_clr(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_M | FLAG_A | FLAG_T, more);
        self.absorb(data);
    }

    /// Receive plaintext data.
    ///
    /// This is the counterpart to `send_clr`.
    pub fn recv_clr(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_I | FLAG_A | FLAG_T, more);
        self.absorb(data);
    }

    /// Receive plaintext metadata.
    ///
    /// This is the counterpart to `meta_recv_clr`.
    pub fn meta_recv_clr(&mut self, data: &[u8], more: bool) {
        self.begin_op(FLAG_M | FLAG_I | FLAG_A | FLAG_T, more);
        self.absorb(data);
    }

    /// Send encrypted data.
    ///
    /// This function takes in the plaintext data to encrypt, and modifies
    /// it in place to contain the encrypted data. This should then be sent
    /// to the other party.
    pub fn send_enc(&mut self, data: &mut [u8], more: bool) {
        self.begin_op(FLAG_A | FLAG_C | FLAG_T, more);
        self.absorb_and_set(data);
    }

    /// Send encrypted metadata.
    ///
    /// The intention of this operation is to send encrypted framing data,
    /// which might be useful for some situations.
    pub fn meta_send_enc(&mut self, data: &mut [u8], more: bool) {
        self.begin_op(FLAG_M | FLAG_A | FLAG_C | FLAG_T, more);
        self.absorb_and_set(data);
    }

    /// Receive encrypted data.
    ///
    /// This is the counterpart to `send_enc`.
    ///
    /// We start with a buffer of encrypted data, and then modify it to contain
    /// the plaintext.
    pub fn recv_enc(&mut self, data: &mut [u8], more: bool) {
        self.begin_op(FLAG_I | FLAG_A | FLAG_C | FLAG_T, more);
        self.exchange(data);
    }

    /// Received encrypted metadata.
    pub fn meta_recv_enc(&mut self, data: &mut [u8], more: bool) {
        self.begin_op(FLAG_M | FLAG_I | FLAG_A | FLAG_C | FLAG_T, more);
        self.exchange(data);
    }

    /// Send a MAC to the other party.
    ///
    /// The buffer will be filled with a MAC, which verifies the integrity
    /// of the operations done so far. This MAC is then intended to be sent
    /// to the other party.
    ///
    /// This operation intentionally does not allow `more` to be used. This
    /// is to match `recv_mac`.
    pub fn send_mac(&mut self, data: &mut [u8]) {
        self.begin_op(FLAG_C | FLAG_T, false);
        self.copy(data);
    }

    /// Send a MAC of metadata to the other party.
    ///
    /// This is very similar to `send_mac`.
    pub fn meta_send_mac(&mut self, data: &mut [u8]) {
        self.begin_op(FLAG_M | FLAG_C | FLAG_T, false);
        self.copy(data);
    }

    /// Receive and verify a MAC.
    ///
    /// The buffer contains the MAC to verify, and we need to mutate it
    /// to be able to more conveniently check its correctness.
    ///
    /// This operation intentionally does not allow `more` to be used. This
    /// is because a MAC should always be verified all at once, rather than in chunks.
    pub fn recv_mac(&mut self, data: &mut [u8]) -> Result<(), MacError> {
        self.begin_op(FLAG_I | FLAG_C | FLAG_T, false);
        self.exchange(data);
        check_zero(data)
    }

    /// Receive and verify a MAC of metadata.
    ///
    /// This is very similar to `recv_mac`.
    pub fn meta_recv_mac(&mut self, data: &mut [u8]) -> Result<(), MacError> {
        self.begin_op(FLAG_M | FLAG_I | FLAG_C | FLAG_T, false);
        self.exchange(data);
        check_zero(data)
    }

    /// Generate random bytes from the state.
    pub fn prf(&mut self, data: &mut [u8], more: bool) {
        self.begin_op(FLAG_I | FLAG_A | FLAG_C, more);
        self.squeeze(data);
    }

    /// Ratchet the state forward.
    ///
    /// Because the state is modified with a permutation, we can use new states
    /// to derive information about old states. Ratcheting prevents this flow
    /// of information backwards.
    pub fn ratchet(&mut self) {
        self.ratchet_many(SECURITY_PARAM / 8, false)
    }

    /// Ratchet the state forward many times.
    ///
    /// The difference with `ratchet` is that you can specify how far to ratchet
    /// the state. For `S` bits of security, you want to ratchet at least `S / 8`
    /// bytes. Ratcheting more can function as a kind of "difficulty", like
    /// you might want for password hashing.
    ///
    /// That said, you probably want a function dedicated for hashing passwords,
    /// which have other security features, like being memory hard, and things like
    /// that.
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

    /// Move our writing position forward, possibly running the permutation
    /// if we run out of space.
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

    /// Absorb data into the sponge, and the set the data to the resulting output.
    fn absorb_and_set(&mut self, data: &mut [u8]) {
        for b in data {
            self.state[self.pos as usize] ^= *b;
            *b = self.state[self.pos as usize];
            self.advance_pos();
        }
    }

    /// Overwrite bytes of the state with this data.
    fn overwrite(&mut self, data: &[u8]) {
        for &b in data {
            self.state[self.pos as usize] = b;
            self.advance_pos();
        }
    }

    /// Zero out bytes of the state.
    ///
    /// A special case of `overwrite`.
    fn zero_out(&mut self, len: usize) {
        for _ in 0..len {
            self.state[self.pos as usize] = 0;
            self.advance_pos();
        }
    }

    /// Exchange data with the state.
    ///
    /// Basically, the data gets xored with the state, and then the state
    /// gets set to the initial value of the data.
    ///
    /// This is mainly useful when decrypting. There, you want to xor the
    /// state to turn the ciphertext into the plaintext, but you then want
    /// to commit to the ciphertext inside of the state, like the sender did.
    ///
    /// You can accomplish this by setting the state to the initial value of the data,
    /// which was the ciphertext.
    fn exchange(&mut self, data: &mut [u8]) {
        for b in data {
            let pos = self.pos as usize;
            *b ^= self.state[pos];
            self.state[pos] ^= *b;
            self.advance_pos();
        }
    }

    /// Copy bytes from the state.
    fn copy(&mut self, data: &mut [u8]) {
        for b in data {
            let pos = self.pos as usize;
            *b = self.state[pos];
            self.advance_pos();
        }
    }

    /// Squeeze bytes from the state.
    ///
    /// The difference with `copy` is that the operation is "destructive",
    /// overwriting data with 0. This can provide some forward secrecy,
    /// which is why we prefer this operation for extracting randomness
    /// from the state.
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

    #[test]
    fn test_streaming() {
        let mut hash0 = [0u8; 32];
        {
            let mut meow = Meow::new(b"test protocol");
            meow.ad(b"hello world!", false);
            meow.prf(&mut hash0, false);
        }

        let mut hash1 = [0u8; 32];
        {
            let mut meow = Meow::new(b"test protocol");
            meow.ad(b"hello", false);
            meow.ad(b" world!", true);
            meow.prf(&mut hash1, false);
        }

        assert_eq!(hash0, hash1);
    }
}
