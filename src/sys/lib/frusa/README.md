# frusa
Fast RUst System Allocator

## What is it?

Another implementation of core::alloc::GlobalAlloc (Rust)

## Why?

A system allocator should be reasonably fast, should be able to request more memory,
and allow memory reclaim. I needed one at the beginning of 2023, and at this time
none of the allocators I could find on crates.io matched the requirements.

## Goals

- fast and efficient alloc/dealloc of small memory chunks
- no-std
- can be used as ```#[GlobalAllocator]```
- relatively easy and efficient expansion/reclaim

## Non goals

- don't care about large memory chunks: this is punted to the back-end allocator
- being the fastest possible allocator is not the goal at the moment; relatively
  low overhead and efficient reclaim are more important

## So is it fast? Ready to use?

- not as fast as malloc or kernel slabs at the moment, but still decent
- reclaim works (on demand)
- tested on x64
- NOT tested on arm64 or other architectures

## A simple benchmark

```
$ cargo test --release -- concurrent_speed_test --nocapture

[...]

------- FRUSA Allocator ---------------
concurrent speed test: 1 threads:   59.48 ns per alloc/dealloc; throughput:  16.81 ops/usec
concurrent speed test: 2 threads:  198.80 ns per alloc/dealloc; throughput:  10.06 ops/usec
concurrent speed test: 4 threads:  465.11 ns per alloc/dealloc; throughput:   8.60 ops/usec
concurrent speed test: 8 threads: 1339.12 ns per alloc/dealloc; throughput:   5.97 ops/usec

------- Rust System Allocator ----------
concurrent speed test: 1 threads:   19.54 ns per alloc/dealloc; throughput:  51.17 ops/usec
concurrent speed test: 2 threads:   22.67 ns per alloc/dealloc; throughput:  88.22 ops/usec
concurrent speed test: 4 threads:   23.47 ns per alloc/dealloc; throughput: 170.44 ops/usec
concurrent speed test: 8 threads:   26.92 ns per alloc/dealloc; throughput: 297.21 ops/usec

------- Talc Allocator ----------
concurrent speed test: 1 threads:   41.85 ns per alloc/dealloc; throughput:  23.89 ops/usec
concurrent speed test: 2 threads:  311.50 ns per alloc/dealloc; throughput:   6.42 ops/usec
concurrent speed test: 4 threads:  697.42 ns per alloc/dealloc; throughput:   5.74 ops/usec
concurrent speed test: 8 threads: 2196.38 ns per alloc/dealloc; throughput:   3.64 ops/usec

```
