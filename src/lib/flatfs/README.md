# flatfs
Flat Filesystem

## What is it?

A simple way to package a small number of files into a single flat memory area. Like CPIO. \[no-std\]

## Why?

Same reason why [CPIO](https://en.wikipedia.org/wiki/Cpio) exists. I needed a way to easily create
read-only partitions in Rust in 2023, and could not find a suitable and lightweight way to do it,
so I rolled my own.

## Goals

- \[no-std\]
- pack a small (~1k) number of "files" into a single contiguous memory region
  - here a "file" is a pair of (&str, &\[u8\])
- unpack that memory region back into "files"
- expose the "files" as a rudimentary directory tree (readonly)
- the "unpacked" filesystem should be reasonably efficient (both memory and CPU)
- no panicking (other than on OOM)

## Non goals

- neither packing nor unpacking are required to be especially fast
- ensuring that filenames are "canonical" in any sense is not a goal
  - for example, the user may add a "/foo" file and a "/foo/bar" file,
    resulting in the root directory containing both a "foo" file and a "foo" directory
