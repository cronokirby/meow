#![cfg_attr(not(test), no_std)]
mod kitten;
mod meow;
// For much heavier tests.
#[cfg(test)]
mod test;

pub use crate::meow::{MacError, Meow};
