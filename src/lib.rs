//! Implements the RC5 encryption algorithm based on <https://www.grc.com/r&d/rc5.pdf>.
//!
//! Aims to provide a generalized implementation that works with any word bit size that is a
//! multiple of 8 (i.e RC5-24/4/0, RC5-32/20/16, RC5-128/28/32 to name a few). The downside is that
//! it is not making use of hardware intrinsics when dealing with word sizes that match u32, u64,
//! etc.
//!
//! The library makes heavy use of const generics. However, since const generics do not support
//! arithmetics in const context on stable Rust, the API is unnecessarily verbose and error prone.
//! This can be improved in the future once const generics gain more power.

#![no_std]

mod bytes;
mod consts;
mod rc5;

pub use crate::rc5::*;
