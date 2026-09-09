//! A global allocator with dynamic memory expansion and on-demand reclaim.
//!
//! Memory is requested from a fallback (system) allocator when needed and
//! returned by an explicit `reclaim()` call. Compared to `frusa`, owner
//! lookup and free-slot search are bounded (a sorted block index and a
//! partial stack instead of list walks), no lock is held across a backend
//! call, and callers may hold a per-thread cache of private blocks.

#![no_std]
// Temporary: the primitives below have no user until the patch that adds
// `Frusa` and its slabs, which removes this allowance.
#![allow(dead_code)]

mod block;
mod sync;

#[cfg(test)]
#[macro_use]
extern crate std;

#[cfg(test)]
mod tests;
