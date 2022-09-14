//! This crate is an implementation of [STROBE](https://strobe.sourceforge.io/specs/) using KitTen (reduced round [Keccak](https://keccak.team/keccak.html)).
//! STROBE is a framework for symmetric cryptography protocols, similar to
//! how Noise works for key exchange.
//!
//! Because this project combines a Noise-like framework with KitTen, I called
//! it **Meow**.
//!
//! # Rationale
//!
//! STROBE uses the 24 round variant of Keccak.
//! Having been [too much crypto-pilled](https://eprint.iacr.org/2019/1492),
//! I think 24 rounds is excessive, and instead think that the 10 rounds
//! of KitTen are sufficient.
//!
//! Following in the TMC rationale, I also hardcode 128 bits of security
//! into the protocol.
//!
//! There are also some slight changes to the protocol, such as not allowing
//! MACs to be created or verified in a streaming fashion, or setting
//! a default length for ratcheting.
//! These don't change the behavior of the other operations though, internally,
//! these work like STROBE, just with a different permutation.
//!
//! # Use Cases
//!
//! The use cases are that of STROBE essentially.
//! You can use the framework for encryption, hashing, etc.
//!
//! ## Encryption
//!
//! For basic encryption, the flow is that each party sets up their Meow state,
//! seeds it with a key, and then either sends or receives a message.
//!
//! ```rust
//! use ck_meow::Meow;
//!
//! let key = [0xFF; 32];
//!
//! let message = b"hello world!";
//!
//! let mut encrypted = message.to_owned();
//! let mut meow0 = Meow::new(b"my protocol");
//! meow0.key(&key, false);
//! meow0.send_enc(&mut encrypted, false);
//!
//! let mut plaintext = encrypted.clone();
//! let mut meow1 = Meow::new(b"my protocol");
//! meow1.key(&key, false);
//! meow1.recv_enc(&mut plaintext, false);
//!
//! assert_eq!(&plaintext, message);
//! ```
//!
//! ### Randomized Encryption
//!
//! It's also very easy to add a nonce to the encryption scheme:
//!
//! ```rust
//! use ck_meow::Meow;
//!
//! let key = [0xFF; 32];
//! let nonce = [0xAA; 32];
//!
//! let message = b"hello world!";
//!
//! let mut encrypted = message.to_owned();
//! let mut meow0 = Meow::new(b"my protocol");
//! meow0.key(&key, false);
//! meow0.send_clr(&nonce, false);
//! meow0.send_enc(&mut encrypted, false);
//!
//! let mut plaintext = encrypted.clone();
//! let mut meow1 = Meow::new(b"my protocol");
//! meow1.key(&key, false);
//! meow1.recv_clr(&nonce, false);
//! meow1.recv_enc(&mut plaintext, false);
//!
//! assert_eq!(&plaintext, message);
//! ```
//!
//! All that was need was to add in calls to `send_clr` and `recv_clr`.
//! In the real protocol, this nonce would be sent to the other participant.
//!
//! ### AEAD
//!
//! From there, it's straightforward to turn this into a full fledged AEAD scheme.
//! We can also incorporate additional data into the state, and we can also generate
//! and check MACs.

//! ```rust
//! use ck_meow::Meow;
//!
//! let key = [0xFF; 32];
//! let nonce = [0xAA; 32];
//!
//! let message = b"hello world!";
//!
//! let mut encrypted = message.to_owned();
//! let mut meow0 = Meow::new(b"my protocol");
//! meow0.key(&key, false);
//! meow0.send_clr(&nonce, false);
//! meow0.ad(b"hello again!", false);
//! meow0.send_enc(&mut encrypted, false);
//! let mut mac = [0u8; 32];
//! meow0.send_mac(&mut mac);
//!
//!
//! let mut plaintext = encrypted.clone();
//! let mut meow1 = Meow::new(b"my protocol");
//! meow1.key(&key, false);
//! meow1.recv_clr(&nonce, false);
//! meow1.ad(b"hello again!", false);
//! meow1.recv_enc(&mut plaintext, false);
//! assert!(meow1.recv_mac(&mut mac).is_ok());
//!
//! assert_eq!(&plaintext, message);
//! ```
//!
//! The essential new functionality here is `send_mac / recv_mac`, which allows
//! creating and verifying a MAC which attests to the integrity of the entire
//! transcript thus far.
//!
//! ## Hashing
//!
//! It's also possible to use Meow as a very simple hash function:
//!
//! ```rust
//! use ck_meow::Meow;
//! 
//! let mut meow = Meow::new(b"my hash function");
//! meow.ad(b"big data", false);
//! // Same as hashing to entire string at once.
//! meow.ad(b"big ", false);
//! meow.ad(b"data", true);
//! let mut hash = [0u8; 32];
//! meow.prf(&mut hash, false);
//! ```
//!
//! You absorb in data with `ad`, and then squeeze it out using the `prf` function.
//! This example also illustrates using `more`, which allows us to split up
//! operations into multiple calls. The second call to the hash function
//! is equivalent.
//!
//! ## Fiat-Shamirization
//!
//! Not only can Meow be used for hashing in one stroke, it's also possible
//! to alternate between absorbing and squeezing out data, which is useful
//! for making interactive public coin protocols non-interactive:
//!
//! ```rust
//! use ck_meow::Meow;
//! 
//! let mut meow = Meow::new(b"my protocol");
//! meow.ad(b"some data", false);
//! meow.ad(b"some more data", false);
//! let mut challenge = [0u8; 32];
//! meow.prf(&mut challenge, false);
//! meow.ad(b"even more data", false);
//! let mut another_challenge = [0u8; 32];
//! meow.prf(&mut another_challenge, false);
//! ```
//!
//! (Note that it would be a good ad to add some `meta_ad` calls for framing,
//! defining the length of the inputs).
#![cfg_attr(not(test), no_std)]
mod kitten;
mod meow;
// For much heavier tests.
#[cfg(test)]
mod test;

pub use crate::meow::{MacError, Meow};
