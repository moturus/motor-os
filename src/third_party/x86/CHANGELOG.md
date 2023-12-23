# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]

## [0.48.0] - 2022-05-23

- Added `const new` constructor for X2APIC struct
- Use fully qualified `asm!` import for `int!` macro so clients do no longer
  need to import `asm!` themselves.
