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
$ cargo test --release concurrent_speed_test -- --nocapture

[...]

------- FRUSA Allocator ---------------
concurrent speed test: 1 threads:   38.85 ns per alloc/dealloc; throughput:  25.74 ops/usec
concurrent speed test: 2 threads:  119.54 ns per alloc/dealloc; throughput:  16.73 ops/usec
concurrent speed test: 4 threads:  234.18 ns per alloc/dealloc; throughput:  17.08 ops/usec
concurrent speed test: 8 threads:  465.11 ns per alloc/dealloc; throughput:  17.20 ops/usec

------- Rust System Allocator ----------
concurrent speed test: 1 threads:   11.92 ns per alloc/dealloc; throughput:  83.90 ops/usec
concurrent speed test: 2 threads:   12.01 ns per alloc/dealloc; throughput: 166.49 ops/usec
concurrent speed test: 4 threads:   14.18 ns per alloc/dealloc; throughput: 282.07 ops/usec
concurrent speed test: 8 threads:   18.74 ns per alloc/dealloc; throughput: 427.00 ops/usec

```