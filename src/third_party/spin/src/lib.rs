#![crate_type = "lib"]
#![warn(missing_docs)]

//! Synchronization primitives based on spinning

#![no_std]

#[cfg(test)]
#[macro_use]
extern crate std;

pub use mutex::*;
pub use once::*;

mod mutex;
mod once;
