//! IO subsystem (sys-io) API.

#![no_std]

pub mod api_fs;
pub mod api_net;

#[cfg(feature = "std")]
pub mod stats;
