// This module contains external code that could not be used directly,
// and had changes too specific to warrant forking and publishing
// as separate crates on crates.io.

// Copied from https://github.com/bitflags/bitflags (MIT/Apache2).
pub mod bitflags;

// Copied from https://github.com/gz/rust-elfloader (MIT/Apache2).
pub mod elfloader;

// Copied from https://github.com/bluss/scopeguard/tree/master (MIT/Apache2).
pub mod scopeguard;

// Copied from https://github.com/mvdnes/spin-rs (MIT).
pub mod spin;

// Copied from https://github.com/nrc/xmas-elf (Apache2).
pub mod xmas_elf;

// Copied from https://github.com/nrc/zero (Apache2).
pub mod zero;
