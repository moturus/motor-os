// A distinct target entry point avoids declaring src/lib.rs twice in Cargo.
#[path = "../src/lib.rs"]
mod suite;

pub use suite::*;
