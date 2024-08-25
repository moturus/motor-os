# Simple Rust File System (core library)

A simple filesystem impremented in Rust \[no_std\].

This crate is a work-in-progress. It contains low-level
code to work directly with block devices (see trait SyncBlockDevice).

Higher-level API, dependent on \[std\], lives in crate srfs.

All basic filesystem features are implemented, with
provisions for extensions.

At the moment only synchronous interface is provided.
See src/tests.rs for usage examples.

TODO:

* crash recovery
* timestamps
* async API

Contributions are welcome.
