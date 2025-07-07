//! Motor FS.
//!
//! Motor Filesystem is work-in-progress. It is designed for use in
//! virtual machines and thus has certain assumptions that simplify its
//! design vs traditional filesystems that are designed to run on real
//! hardware.
//!
//! More specifically:
//! - Block writes are assumed to be atomic;
//! - No "on disk" data corruption is assumed or protected against;
//! - Only resistance to "power off" is built-in.
#![feature(random)]

mod bplus_tree;
mod city_hash;
mod fs;
mod layout;
mod txn;

pub(crate) use layout::*;
pub(crate) use txn::*;

pub use fs::*;

#[cfg(test)]
mod tests;
