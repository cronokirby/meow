#![cfg_attr(not(test), no_std)]
mod kitten;
mod meow;

pub use crate::meow::{Meow, MacError};
