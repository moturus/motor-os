//! IO subsystem (sys-io) API.

#![no_std]

pub mod rt_fs;

#[cfg(feature = "std")]
pub mod stats;
