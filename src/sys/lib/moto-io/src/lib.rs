//! Motor OS "native" I/O crate.
//!
//! Rust's std library is designed to provide the most ergonomic common
//! way to do I/O across a variety of platforms/operating systems; in particular,
//! Rust's std library targets Linux, Mac OS, and Windows as their "Tier 1" targets.
//!
//! In addition, while Rust's async I/O ecosystem is robust and probably
//! the best there is across several important dimensions (e.g. performance, security),
//! it is not std: Rust's std library's I/O is, more or less, POSIX, as in everything
//! is an FD; definitely on Unices, but also, quite surprisingly, on WASI, for example.
//! (Windows is a little bit different, but not by much).
//!
//! It is also worth noting that operating systems are not programming-language-agnostic:
//! Unix co-evolved with C, and Windows API, while expressed in C, has been designed
//! with (early) C++ in mind.
//!
//! As such, a new operating system that wants to explore more modern I/O approaches
//! (e.g. async-first), and languages (Rust) necessarily has to express its I/O API
//! in a way that is different from what Rust's std library provides.
//!
//! This is the purpose of the moto-io crate: to expose Motor OS I/O API that is not
//! burdened by legacy approaches.
//!
//! There is a tension here: filesystems are understood through POSIX API, and
//! networking protocols (e.g. TCP/IP) are often defined/understood via "sockets".
//! While it is quite possible, and extremely interesting, to explore new ways
//! of defining distributed computation, from higher-level RPC protocols to
//! imagining a multi-node super-computer running a single operating system,
//! this kind of larger-scale projects is probably only possible within a large
//! corporate setting.
//!
//! Motor OS, being a volunteer-driven open-source effort, will focus on
//! the typical/standard/legacy I/O paradigms, such as file systems and standard
//! networking protocols.
#![no_std]
pub mod fs;
