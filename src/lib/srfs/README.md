# Simple Rust File System

A simple filesystem impremented in Rust.

This crate is a work-in-progress. It contains synchronous
high-level API, similar to std::fs::* in Rust, and uses
crate srfs-core internally. For use with \[std\].

All basic filesystem features are implemented, with
provisions for extensions.

At the moment only synchronous interface is provided.

See srfs-core crate for more technical information.

TODO:

* crash recovery
* timestamps
* async API

Contributions are welcome.