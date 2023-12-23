#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unused_qualifications
)]

#[cfg(feature = "client")]
mod client;
mod io;
pub mod model;
#[cfg(feature = "server")]
mod server;
mod utils;

#[cfg(feature = "client")]
pub use client::Client;
#[cfg(feature = "server")]
pub use server::Server;
