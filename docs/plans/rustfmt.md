# Standard Motor Rust unwinding and native rustfmt

Status: local implementation and candidate validation complete through patch
17, revised 2026-09-12 for D4. Publication, the managed `.dev.2` cutover, its
six main-image gates, and the release developer-image gate remain pending.
The external Rust changes are committed only in the local authoring
checkout; no remote refs have been created or moved.

Decisions recorded:

- **D1 (accepted 2026-09-10):** the Motor target defaults to `panic=unwind`.
  Shipped OS binaries keep abort through explicit profiles (section 4.5).
- **D2 (accepted 2026-09-11):** the unwinder's FDE finder is a Motor-specific
  function registered by std: from a high-priority constructor in mlibc-linked
  binaries and from std's per-platform `init` otherwise (section 4.3).
- **D3 (design):** in Rust-linked binaries the pure-Rust unwinder owns the
  `_Unwind_*` ABI for Rust and C++ frames alike (section 4.4).
- **D4 (accepted 2026-09-12):** rustfmt resolves its user configuration on
  Motor from the fixed paths `/user` (home) and `/user/cfg` (configuration)
  behind `cfg(target_os = "motor")`; the `dirs` and `dirs-sys` crates are not
  compiled for Motor and no dirs-sys fork exists (section 4.6).

## 1. Goal

Native `rustfmt` on the developer image, used by Helix through rust-analyzer
for `:format` and format-on-save, built on general unwinding support in the
standard Motor Rust toolchain. rustc, the compiler-private libraries, rustfmt,
rust-analyzer, and ordinary applications all use the standard Motor sysroots.
The analyzer's private patched-std build is retired. The "keep unwinding
private" decision in [rust-unwinding.md](rust-unwinding.md) is superseded; its
measurements and regressions remain valid evidence, and its deployed code
stays until the replacement passes its gates.

## 2. Verified findings

Checked on 2026-09-10 and 2026-09-11 against the selected source trees and
built artifacts.

- The host toolchain packages rustfmt 1.10.0 from `src/tools/rustfmt`, a
  member of the Rust root workspace. The native assembly stages rustc and
  rust-analyzer but not rustfmt. Helix's packaged `languages.toml` disables
  `auto-format` and excludes the analyzer's `format` feature for that reason.
- rustfmt depends on unwinding for correctness. It wraps crate parsing,
  module parsing, snippet formatting, and macro rewriting in `catch_unwind`;
  rustc's `FatalError::raise` is `resume_unwind`, raised at 16 sites in
  rustc_parse. On the abort-only Motor std a fatal parse error exits -1 and
  valid macro input can abort. Fatal errors emit their diagnostic first.
- rustfmt links rustc-private rlibs that only bootstrap produces for Motor.
  rustc refuses to link abort-compiled crates into an unwind binary, so the
  whole Motor compiler-library closure must be unwind-compiled.
- Locked `dirs 6.0.0` routes Motor to its Linux module, which calls
  `dirs_sys::home_dir` and `dirs_sys::user_dir`; `dirs-sys 0.5.0` defines them
  only under `cfg(unix)` and its XDG parser imports the Unix `OsStringExt`.
  Motor declares no target family. rustfmt's config lookup therefore does not
  compile for Motor unchanged. rustfmt calls `dirs` in exactly two places,
  both in `Config::from_resolved_toml_path`. Motor has no home directory in
  the Unix sense: per-program configuration lives under `/user/cfg`
  (`img_files/motor-os-dev/devtools/www/filesystem.html`), and the packaged
  rust-analyzer already compiles `dirs` only off Motor
  ([rust-analyzer.md](rust-analyzer.md), configuration row).
- Cargo (tested with the selected host cargo on a Motor-target scratch crate)
  passes `-C panic=abort` for an abort profile and nothing for an unwind
  profile; rustc then uses the target default. That is why D1 flips the
  default instead of adding rustflags.
- rust-analyzer resolves rustfmt through its own process's `RUSTFMT` variable
  before `PATH`, runs it in the file's directory with `--edition`, and treats
  exit 1, or exit 101 with an `error` prefix, as "no edits". An abort also
  yields "no edits", so tests must observe the formatter's own exit status.
- Helix's `--health rust` reports only the external-formatter setting; it will
  keep saying `None`. Format-on-write goes through the LSP `format` feature.
- Both LLVM libunwind and the Rust `unwinding` crate implement the level-1
  `_Unwind_*` ABI. Native rustc-main today contains libunwind's
  `_Unwind_RaiseException` and `_Unwind_Resume` plus the internal
  `__unw_getcontext`, pulled in by libc++abi's `__cxa_throw` (libc++ and
  libc++abi are built with exceptions). The native analyzer contains the Rust
  crate's versions and no libunwind object. The Rust crate exports every
  `_Unwind_*` symbol that `libc++abi.a` and `libc++.a` reference.
- Real Motor binaries place the ELF header and program headers in the first
  read-only `PT_LOAD` at offset 0, and LLD already defines `__ehdr_start` in
  them. The `unwinding` crate's `fde-custom` feature exposes `EhFrameFinder`,
  `FrameInfo`, `FrameInfoKind::EhFrameHdr`, and `set_custom_eh_frame_finder`,
  which Xous's std already uses from its own entry point.
- `std::rt::init` calls `sys::init` before `main` on every platform
  (`library/std/src/rt.rs:118`). Motor's implementation in
  `library/std/src/sys/pal/motor/mod.rs:52` is an empty function, reached from
  both entry paths: the weak Rust `motor_start` and mlibc's `crt1.o`, which
  calls the rustc-generated `main`.
- Profile audit for D1: every `src/sys` workspace profile, the kernel and boot
  JSON targets, and the moto-rt C ABI shim select abort. Eleven `src/bin`
  crates pin abort only in `[profile.release]`; russhd has no profile. The
  Makefile builds `src/bin` crates with the dev profile for debug images.
  Packaged ripgrep pins abort only in its `release-lto` profile and is built
  with plain `--release`. Lorry mirrors Cargo's flag behavior.
- The Rust checkout ships an `AGENTS.md` (upstream's LLM policy). The user
  ruled that it does not govern this Motor OS work; section 3 records the
  rules that do.

## 3. Which contribution rules govern the fork edits

The Rust checkout carries upstream's `AGENTS.md` (the rust-lang LLM usage
policy with reviewer, prohibited-text, and soundness gates). The user ruled on
2026-09-11 that it does not govern this work: the edits go to the moturus fork
as Motor OS work, so the motor-os `AGENTS.md` applies instead. Consequences:

- No named upstream reviewer is required; the user reviews the patches.
- Source comments in the fork follow the motor-os ratio guideline (about
  1:5) and may be written by the agent.
- Formatting in the fork uses `./x fmt`, the fork's selected formatter.
- The only `src/tools` edit is rustfmt's user-configuration lookup (4.6),
  the same shape as the analyzer's existing Motor configuration change;
  nothing else under `src/tools` is modified.
- The tests for the fork changes are the motor-os native fixtures in
  section 6, since Motor std cannot run under `./x test` on the host.
- Nothing here is upstreamed to rust-lang/rust by this plan. If a change is
  ever proposed upstream, upstream's policy applies at that point.

## 4. Implementation specification

### 4.1 Rust fork: unwind runtime selection

Authoring checkout: `/home/posk/motor-dev/rust-unwind-authoring`, a clone of
`https://github.com/moturus/rust.git` at `MOTOR_RUST_REV`
(`75940756edd423d88ba353ce720770f3061b285a`), on a branch off
`motor-os-1.99.0-beta-f47d5bb`. Never edit
`/home/posk/motor-dev/toolchain-src/rust`.

`library/unwind/Cargo.toml`, after the Xous target block:

```toml
[target.'cfg(target_os = "motor")'.dependencies]
unwinding = { version = "0.2.10", features = ['rustc-dep-of-std', 'unwinder', 'fde-custom'], default-features = false }
```

`library/unwind/src/lib.rs`: add `#[cfg(target_os = "motor")] extern crate
unwinding as _;` next to the Xous line, add `target_os = "motor"` to the
`cfg_select!` arm that selects `mod libunwind`, and delete the
`// - os=motor` line from the "no unwinder" list.

`library/unwind/src/libunwind.rs`: change the Xous-only re-export to
`#[cfg(any(target_os = "xous", target_os = "motor"))]`.

`library/panic_unwind/src/lib.rs` and
`library/std/src/sys/personality/mod.rs`: add `target_os = "motor"` to the
arm that selects the real `gcc`-style implementation and remove Motor from the
dummy list, exactly as `src/patches/rust-analyzer-unwind.patch` does.

The library lock already pins `unwinding 0.2.10` with `gimli`; the feature
change must produce no lock diff. Verify with `cargo metadata --locked
--offline` on `library/Cargo.toml`.

### 4.2 Rust fork: target default (D1)

`compiler/rustc_target/src/spec/base/motor.rs`: delete the line
`panic_strategy: PanicStrategy::Abort,` and the now-unused import. The
`x86_64_unknown_motor` target file needs no change. `src/sys/kernel/kernel.json`
and the boot JSON targets keep their own `"panic-strategy": "abort"`.

Effect: bootstrap builds Motor std, panic_unwind, the compiler-private
closure, rustc, rustfmt, and (after 4.9) the analyzer with unwinding by
default, for both the host-cross sysroot and the native sysroot, with no
per-target rustflags. Both `libpanic_abort` and `libpanic_unwind` rlibs are
present in every Motor sysroot.

### 4.3 Rust fork: the Motor FDE finder and its registration (D2)

New file `library/std/src/sys/pal/motor/eh_frame.rs`:

```rust
use crate::sys::pal::unwind_ffi as unwind;

unsafe extern "C" {
    static __ehdr_start: u8;
}

pub(crate) struct Finder;

pub(crate) static FINDER: Finder = Finder;

const ELFCLASS64: u8 = 2;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PT_GNU_EH_FRAME: u32 = 0x6474e550;
const PF_X: u32 = 1;

#[repr(C)]
struct Ehdr {
    ident: [u8; 16],
    r#type: u16,
    machine: u16,
    version: u32,
    entry: u64,
    phoff: u64,
    shoff: u64,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
}

#[repr(C)]
struct Phdr {
    r#type: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

unsafe impl unwind::EhFrameFinder for Finder {
    fn find(&self, pc: usize) -> Option<unwind::FrameInfo> {
        let base = unsafe { &__ehdr_start as *const u8 as usize };
        if base == 0 {
            return None;
        }
        let ehdr = unsafe { &*(base as *const Ehdr) };
        if ehdr.ident[..4] != *b"\x7fELF"
            || ehdr.ident[4] != ELFCLASS64
            || ehdr.machine != EM_X86_64
            || usize::from(ehdr.phentsize) != size_of::<Phdr>()
        {
            return None;
        }
        let phdrs = base.checked_add(usize::try_from(ehdr.phoff).ok()?)? as *const Phdr;
        let mut in_text = false;
        let mut eh_frame_hdr = None;
        for index in 0..usize::from(ehdr.phnum) {
            let phdr = unsafe { &*phdrs.add(index) };
            let start = base.checked_add(usize::try_from(phdr.vaddr).ok()?)?;
            let end = start.checked_add(usize::try_from(phdr.memsz).ok()?)?;
            match phdr.r#type {
                PT_LOAD if phdr.flags & PF_X != 0 && (start..end).contains(&pc) => in_text = true,
                PT_GNU_EH_FRAME => eh_frame_hdr = Some(start),
                _ => {}
            }
        }
        if !in_text {
            return None;
        }
        Some(unwind::FrameInfo { text_base: Some(base), kind: unwind::FrameInfoKind::EhFrameHdr(eh_frame_hdr?) })
    }
}
```

The first line's path is illustrative: use whatever path the std crate
already uses to reach the `unwind` crate's re-exports (Xous writes
`unwind::EhFrameFinder` directly because std depends on the `unwind` crate).
Static PIEs are linked at nominal address 0, so `__ehdr_start` is the load
bias and `vaddr` values are offsets from it; the ELF validation in 4.8 checks
that assumption on every produced binary. `phoff` is 64 in every LLD output,
but read it rather than assume it. No allocation, no locks, no I/O, reads only
the mapped read-only header page, safe under concurrent panics.

Registration happens in two places, both in `eh_frame.rs` and
`library/std/src/sys/pal/motor/mod.rs`:

```rust
pub(crate) fn register() {
    let _ = unwind::set_custom_eh_frame_finder(&FINDER);
}

extern "C" fn register_ctor() {
    register();
}

#[used]
#[unsafe(link_section = ".init_array.00001")]
static REGISTER_CTOR: extern "C" fn() = register_ctor;
```

```rust
#[cfg(all(not(test), feature = "panic-unwind"))]
mod eh_frame;

pub unsafe fn init(_argc: isize, _argv: *const *const u8, _sigpipe: u8) {
    #[cfg(all(not(test), feature = "panic-unwind"))]
    eh_frame::register();
}
```

Why two. mlibc-linked binaries (everything containing C++, including native
rustc and rustfmt) run `.init_array` constructors before the rustc-generated
`main`, and a C++ static constructor may throw and catch. The
`.init_array.00001` entry sorts before every default-priority constructor, so
the finder is registered before any C++ static initializer runs. Pure-Rust
binaries enter through `moto_rt::start()`, which runs no constructors
(verified: no `.init_array` handling in moto-rt or rt.vdso), so `sys::init`
registers there; it runs before `main`, thread creation, and any user code.
`set_custom_eh_frame_finder` returns `Err` when already registered, which is
the expected second call in mlibc-linked binaries, so the result is
discarded. `#[used]` keeps the entry through `--gc-sections`; the existing
ELF validation already requires a populated `.init_array`.

Cost per process: one or two compare-exchanges and a few stores, tens of
nanoseconds. Rust code that runs before both registrations (nothing does) or
inside a staticlib without a Rust `main` and without constructors (the
moto-rt C ABI shim, abort-compiled) cannot unwind; record this in
`docs/build-rustc.md`.

Layout guarantee for ordinary applications. The finder assumes the running
image is a static PIE linked at nominal address 0 whose ELF header, program
headers, and `PT_GNU_EH_FRAME` segment are mapped readable. Two linkers
produce Motor binaries, and both must satisfy this (verified 2026-09-11 with
the selected toolchain):

- Host-cross builds with rustc's default linker invoke the host `cc`, which
  on the build machine is GCC driving GNU ld. rustc passes `-static-pie`,
  `-nostartfiles`, and `-Wl,--eh-frame-hdr` explicitly, and GNU ld's default
  layout puts the headers in the first read-only `PT_LOAD` at offset 0 and
  emits `PT_GNU_EH_FRAME`. This is how every `src/sys` and `src/bin` binary
  and every `cargo build --target x86_64-unknown-motor` on the host is linked.
- Native builds on the image and every clang-driven link (`cc` on the image,
  `motor-clang`, the bootstrap `motor-rust-cc`) use LLD, with the same layout.

Both linkers define `__ehdr_start` only when the ELF header lies inside a
loadable segment, so a binary that links at all has mapped headers. Custom
linker scripts that move the headers are unsupported. The producer's ELF
validation (4.8) checks the invariants on every shipped native binary (LLD
path), and `test-unwind.sh` checks them on its own cross-compiled (GNU ld
path) and natively compiled (LLD path) test binaries.

### 4.4 One unwinder per process (D3)

Rust-linked Motor binaries containing C++ (native rustc, rustfmt, any Rust
program opting into the C runtime) see two providers of `_Unwind_*`: the Rust
`unwinding` crate inside std's rlibs, and LLVM libunwind from the `-lunwind`
in both link recipes (`motor-rust-cc` in `src/toolchain-bootstrap.sh` and the
clang Motor toolchain's default group). Rule: the Rust implementation wins.
It exports a superset of what libc++abi and libc++ reference, rustc places
rlibs before the driver's library group, so LLD binds every reference to the
Rust definition and never extracts libunwind's level-1 object. Pure C and C++
programs keep LLVM libunwind. Neither link recipe changes.

Because the Rust unwinder serves C++ frames, it must be usable whenever C++
code can throw, including during static initialization; the constructor
registration in 4.3 is what makes that hold. Enforcement, in 4.8's ELF
validation on the unstripped build outputs: no `__unw_` symbol present
(`llvm-nm` on rustc-main, rustfmt, and the analyzer), and
`_Unwind_RaiseException` defined exactly once. Runtime proof: the `cxx`,
`cxx-static`, `cxx-through-rust`, and `rust-through-cxx` fixtures in 6.1.

### 4.5 motor-os: application profiles (D1)

Add to each of `src/bin/{curl,gears,gears-mock-provider,httpd,httpd-axum,kibim,lorry,red,rmux,rnetbench,rush}/Cargo.toml`,
next to the existing `[profile.release]` block:

```toml
[profile.dev]
panic = "abort"
```

Add both `[profile.dev]` and `[profile.release]` with `panic = "abort"` to
`src/bin/russhd/Cargo.toml`. `src/sys` crates, the kernel, and boot need no
profile change. Two freestanding artifacts link the sysroot's `core` and
`alloc`, which D1 makes unwind-compiled, and provide no unwinder: the moto-rt
C ABI shim and `rt.vdso`. Both build those two crates under their own abort
profile with `-Zbuild-std=core,alloc` (`src/build-motor-os.sh` and
`src/sys/lib/rt.vdso/build.sh`); without it the link fails on the
`_Unwind_Resume` and `rust_eh_personality` references in the prebuilt
`liballoc`. On the current abort tuple the flag still rebuilds `core` and
`alloc` with the vdso's fat-LTO profile, so the vdso binary changes (about
4 KB larger). In debug builds the dev profile would compile those crates at
opt-level 0 with assertions, unlike the prebuilt sysroot crates, so
`src/sys/lib/rt.vdso/.cargo/config.toml` overrides `core`, `alloc`, and
`compiler_builtins` back to opt-level 3 without assertions; without that,
the first debug gate on the managed `.dev.2` tuple ran every systest child
case three to five times slower and failed a 500 ms stdio lifetime bound.
ripgrep (confirmed 2026-09-11) stays on its `release` profile and becomes unwind, which is
its upstream default; record its size delta. Lorry needs no change:
`CargoPanicStrategy::Abort` already emits `panic=abort` and unwind relies on
the target default. Confirm with `cargo build -v` that every OS binary's
command line except ripgrep's carries `-C panic=abort` in both image modes.
The `src/bin/lorry/Cargo.toml` edit is a profile line only, not Lorry source;
per AGENTS.md it does not make this Lorry work.

### 4.6 Rust fork: rustfmt configuration directories (D4)

rustfmt looks for `rustfmt.toml` or `.rustfmt.toml` in the input's directory
and its parents, then in the user's home directory, then in
`<config dir>/rustfmt`. Upstream obtains the last two from `dirs`, which does
not compile for Motor (section 2). Motor uses fixed per-user locations
instead of `HOME` and XDG variables, so the fork answers those two lookups
behind `cfg(target_os = "motor")` and compiles no `dirs` at all for Motor.
This mirrors the analyzer fork, which compiles `dirs` only off Motor.

`src/tools/rustfmt/Cargo.toml`: move `dirs = "6.0"` from `[dependencies]` to
`[target.'cfg(not(target_os = "motor"))'.dependencies]`.

`src/tools/rustfmt/src/config/mod.rs`: the `dirs::home_dir()` and
`dirs::config_dir()` calls in `resolve_project_file` become calls to two
module-level helpers, `user_home_dir` and `user_config_dir`. Off Motor they
forward to `dirs`; on Motor they return `Some("/user")` and
`Some("/user/cfg")`. The search order is unchanged, so on Motor the user
files are `/user/rustfmt.toml` (or `/user/.rustfmt.toml`) and then
`/user/cfg/rustfmt/rustfmt.toml`. `HOME` and `XDG_CONFIG_HOME` are never
consulted on Motor. The lookup after the project tree stays one
`fs::metadata` per candidate, so its cost is unchanged.

The root `Cargo.toml` and `Cargo.lock` are untouched: the lock lists every
platform's dependencies, and a target-specific table does not change it.
`cargo metadata --locked --offline` on the root manifest passes and the lock
hash stays `MOTOR_RUST_ROOT_LOCK_SHA256`. `cargo tree -p rustfmt-nightly
--target x86_64-unknown-motor` on the root workspace must list neither `dirs`
nor `dirs-sys`, while the Linux graph keeps `dirs 6.0.0`; the host test in
6.2 asserts both. No dirs-sys fork, remote, or publication step exists.

### 4.7 motor-os producer: native rustfmt build

`src/toolchain-native.sh`, `toolchain_build_native_rustc`: change the
bootstrap invocation to

```sh
./x.py --config "$NATIVE_BOOTSTRAP_CONFIG" build \
	--stage 2 compiler src/tools/rustfmt \
	--host x86_64-unknown-motor --target x86_64-unknown-motor
```

and after `RUSTC_MAIN`, set and validate

```sh
RUSTFMT_MAIN="$rust/build/x86_64-unknown-linux-gnu/stage2-tools/x86_64-unknown-motor/release/rustfmt"
```

The tool step builds with the stage-1 Linux compiler against the stage-2
Motor compiler libraries, which the same compiler built; bootstrap also copies
the binary to `build/x86_64-unknown-motor/stage2/bin/rustfmt`. Confirm both
paths from the first real build's verbose output and keep the Cargo output
path as the source of truth. Bootstrap's rustc step normally keeps only
`.rmeta` files for most compiler crates because their objects live in
`librustc_driver.so`; Motor has no shared driver, so the fork keeps every
Motor `.rlib` in `src/bootstrap/src/core/build_steps/compile.rs` and rustfmt
links the rlibs. Add `toolchain_validate_native_rustfmt`: the
binary exists and is executable, contains the build-script string
`dev (<first ten characters of EFFECTIVE_MOTOR_RUST_REV> <YYYY-MM-DD>)` as one
contiguous byte sequence (that is how rustfmt's `build.rs` embeds it; the
version prefix `rustfmt 1.10.0-dev` is assembled at runtime from separate
strings and must not be grepped for), and passes the shared ELF validation of
4.8. The exact `--version` output is asserted natively in 6.3. The contract
test's fixture must use the same contiguous string so a wrong grep cannot
pass on fixtures and fail on the real binary.

### 4.8 motor-os producer: shared ELF validation

Move `toolchain_validate_rust_analyzer_elf` from
`src/toolchain-native-rust-analyzer.sh` to `src/toolchain-native.sh` as
`toolchain_validate_native_elf BINARY READELF [UNSTRIPPED]`, keeping its
checks (ELF64, little-endian, DYN, x86-64, no INTERP or TLS, non-executable
GNU_STACK, no W+X LOAD, `.init_array`, `.eh_frame_hdr`, `.eh_frame`,
`.gcc_except_table`, no NEEDED or TEXTREL, no undefined dynamic symbols) and
adding:

- the first `PT_LOAD` has `p_offset` 0 and `p_vaddr` 0 (nominal address 0,
  so `__ehdr_start` is the load bias), and its `p_filesz` is at least
  `e_phoff + e_phnum * e_phentsize`, computed with checked arithmetic;
- a `GNU_EH_FRAME` program header is present and its `[p_vaddr, p_vaddr +
  p_memsz)` range lies inside a readable `PT_LOAD`;
- when an unstripped path is given, `llvm-nm` shows no `__unw_` symbol and
  exactly one `T _Unwind_RaiseException`.

Apply it to rustc-main, rustfmt, and the analyzer (stripped output plus
unstripped build output), and expose it to `test-unwind.sh` for the test
crate's own binaries. Identity greps (revision, release, description) stay
per tool. Keep `src/tests/test-toolchain-native-rust-analyzer.sh`'s fixture
approach and add negative fixtures for each new invariant: nonzero first
`p_offset`, nonzero first `p_vaddr`, a first segment too short for the
program-header table, a missing `GNU_EH_FRAME`, and an unwind header outside
every readable `PT_LOAD`.

### 4.9 motor-os producer: analyzer on the installed std

`src/toolchain-native-rust-analyzer.sh`, `toolchain_build_native_rust_analyzer`:
remove the library preparation, `__CARGO_TESTS_ONLY_SRC_ROOT`,
`CARGO_TARGET_X86_64_UNKNOWN_MOTOR_RUSTFLAGS`, `-Z build-std=std,panic_unwind`,
and the library-lock `cmp`. Keep `CARGO_PROFILE_RELEASE_OPT_LEVEL=s`, the
`motor-clang` linker, `--locked --offline`, `--config
"$RUST_ANALYZER_CARGO_CONFIG"`, and the version environment. Add the analyzer's
own `-C link-self-contained=no -C default-linker-libraries=yes` back through
`CARGO_TARGET_X86_64_UNKNOWN_MOTOR_RUSTFLAGS` since those two flags came from
`toolchain_rust_analyzer_unwind_flags`; inline the two flags so the producer
no longer needs the unwind helper.

This is done in two patches. The **recipe switch** (patch 7) changes only
what the producer runs: the build command above, the removal of the
`toolchain_fetch_rust_analyzer_library` call in `src/build-motor-os.sh` (line
907 today), and the recipe bump below. The helper file, the patch file, the
old `test-rust-analyzer-unwind.sh`, and its crate stay in the tree and stay
listed in `MOTOR_OS_RUNTIME_INPUTS`, so the private-build regression keeps
running against the user's current toolchain until the replacement has
passed. The **cleanup** (patch 11, after the candidate runtime gates) deletes
`src/toolchain-rust-analyzer-unwind.sh`, `src/patches/rust-analyzer-unwind.patch`,
the old test and crate, removes both files from `MOTOR_OS_RUNTIME_INPUTS`
(assembly identity rejects missing inputs), and updates
`src/patches/README.md`. Keep `toolchain_fetch_rust_analyzer`: the analyzer
workspace still needs its provisioning. The library's `unwinding` and `gimli`
crates are now ordinary std dependencies that bootstrap fetches during the
online host provisioning like every other std dependency; no separate fetch
step remains.

Recipe identity: in `src/toolchain-assembly.sh`, bump
`toolchain_native_configuration_digest` to schema `motor-native-config-v4`
with `rust_analyzer_recipe motor-native-rust-analyzer-v3-std` and a new
`rustfmt_recipe motor-native-rustfmt-v1`; update the three
`native_rust_analyzer_recipe` literals accordingly.

### 4.10 motor-os producer: packaging

`src/build-motor-os.sh`, `rustc_stage_image`: after staging rustc, add

```sh
"$B/llvm-strip" -o "$rust_img/bin/rustfmt" "$RUSTFMT_MAIN"
cat > "$RUSTC_IMG/devtools/bin/rustfmt" << 'EOF'
#!/system/bin/rush
export TMPDIR=/devtools/tmp
exec /devtools/rust/bin/rustfmt "$@"
EOF
chmod +x "$RUSTC_IMG/devtools/bin/rustfmt"
```

and `"$RUSTC_IMG/devtools/rust/bin/rustfmt"` to `required_outputs`.

`src/toolchain-assembly.sh`: add the binary to
`toolchain_validate_assembly_outputs`, add manifest fields
`native_rustfmt_sha256` and `native_rustfmt_expected_version_base64`, add the
hash to `hash_fields`/`hash_paths`, and extend the reuse validation.

`src/imager/motor-os-dev.yaml`: add `rustc/devtools/rust/bin/rustfmt` and
`rustc/devtools/bin/rustfmt` under `assembly_required_executables` (the list
lives in the configuration, not in code). `src/imager/src/main.rs`: the unit
test that reads that configuration expects 10 entries and both paths.

### 4.11 motor-os: Helix configuration

`img_files/motor-os-dev/user/.config/helix/languages.toml`:

```toml
[language-server.rust-analyzer.environment]
CARGO = "/devtools/bin/lorry"
RUSTFMT = "/devtools/rust/bin/rustfmt"
PATH = "/devtools/bin:/system/bin:/user/bin"
TMPDIR = "/devtools/tmp"
MOTURUS_STDIO_NO_TERMINAL = "true"

[[language]]
name = "rust"
auto-format = true
language-servers = ["rust-analyzer"]
```

Replace the "does not package rustfmt" comment. `RUSTFMT` bypasses the
launcher on purpose: the server already exports `TMPDIR`. No Helix external
formatter.

### 4.12 motor-os: toolchain selection and identity

`src/toolchain-versions.sh`: after the fork commits exist, set
`MOTOR_RUST_REF` and `MOTOR_RUST_REV` to the new branch and revision.
`MOTOR_RUST_ROOT_LOCK_SHA256` and `MOTOR_RUST_LIBRARY_LOCK_SHA256` stay: no
fork patch changes either lock (4.1, 4.6). Bump `MOTOR_TOOLCHAIN_ID` to
`1.99.0-beta-f47d5bb-motor.dev.2` and `MOTOR_RUSTUP_TOOLCHAIN_BASE` to
`motor-1.99.0-beta-f47d5bb-dev.2` (confirmed 2026-09-11). The toolchain key changes through
these existing inputs; no schema change. `rust-toolchain.toml` and the
assembly pin change together at cutover (section 8).

Optional but recommended for the candidate builds: add
`build.bootstrap-cache-path` pointing at
`/home/posk/motor-dev/toolchain-src/rust/build/cache` to the rendered
bootstrap config so the authoring checkout reuses the hash-verified stage-0
archives instead of downloading them. If added, include it in the normalized
identity digest as `/MOTOR_BOOTSTRAP_CACHE` like the other paths.

## 5. Measurements and limits

Baseline recorded on 2026-09-11 before the first implementation edit, using
toolchain key `50df587e90f781a28d420f9b5e47135ea78508dd83bdac9f487a410fcd330500`
and assembly `f64cef43ac5451f87829bf0c45595b2d44ae1ae83eb25671161ce1707019abcc`:

| Artifact | Baseline |
|---|---:|
| Host toolchain prefix | 952,047,569 bytes |
| Native Rust sysroot overlay | 218,720,517 bytes |
| Stripped native rustc | 99,841,112 bytes |
| Stripped native rust-analyzer | 29,767,376 bytes |
| Main qcow2 file / allocated | 226,754,560 / 226,709,504 bytes |
| Developer qcow2 file / allocated | 4,252,041,216 / 4,252,209,152 bytes |

The current native analyzer acceptance took 25.658 seconds total, including
20.322 seconds to healthy quiescence; sampled maxima were 913,338,368 virtual
bytes and 26 analyzer threads, and 1,307,824,128 bytes of guest physical
memory. The existing QEMU boot observation is 203 ms to `kernel up` and
1.19-1.21 seconds to SSH readiness. The selected toolchain's recorded cold
host build took 20 minutes 25 seconds and the complete toolchain, assembly,
and image build took 3,785.08 seconds. Candidate measurements use the same
definitions.

Patch 1 validation passed: the memory contract covers the candidate wrapper's
8192 MiB default and caller override, the wrapper booted the release developer
image and passed both analyzer scripts, and the release `full-test.sh` passed
with the shared launcher. Immediately before this patch the same tuple passed
three consecutive debug and three consecutive release main-image suites plus
the release developer-image suite. An initial post-edit invocation stopped
before image construction because its sandbox made the shared patched-crates
cache read-only; the unchanged command passed with access to the established
build paths.

Patch 2 baseline also matches the current abort-default sysroot. The explicit
abort build passed `cancel` and `abort`, and its fresh verbose build contained
`-C panic=abort`. The normal and fat-LTO suites both failed `cancel`, `hook`,
`join`, and the double-panic cleanup marker; their explicit abort and
`extern "C"` termination cases passed. The candidate wrapper's analyzer tests
passed before it reported these expected unwind-suite failures.

Before any change: host prefix size, native sysroot size, rustc (99 MB) and
analyzer sizes, main and developer qcow2 sizes, boot time from the existing
boot observation, and representative build and runtime timings. After each
candidate: the same, plus cold bootstrap time, peak memory, disk use, rustfmt
unstripped and stripped size, native formatting time on the fixtures.

Limits: the analyzer keeps 32 MiB stripped, 80 MiB rust-src, 128 MiB overlay
growth, and its latency, memory, and thread bounds. rustfmt gets the same kind
of test-enforced ceilings (confirmed 2026-09-11), set in patch 16 from the
first real build: measured stripped size and measured fresh-qcow2 growth
attributable to rustfmt and its launcher, each rounded up with about ten
percent margin, measured between otherwise identical fresh images. The earlier
guesses of 128 MiB and 160 MiB are upper expectations, not the limits. Report
total image and sysroot growth too. Once set, a violated bound is
investigated, never raised.

The first packaged candidate, built with the superseded dirs-sys fork,
measured a 19,662,152-byte stripped rustfmt, an
84-byte launcher, and 19,726,336 bytes of fresh-qcow2 growth. Both enforced
ceilings are 21 MiB (22,020,096 bytes), about twelve percent above the measured
values. The complete candidate Rust overlay is 259,220,355 bytes, 40,499,838
bytes above the recorded baseline. Its most recently rebuilt fresh main and
developer images are 26,214,400 and 616,366,080 bytes. The recorded baseline
developer image had already been expanded by guest activity, so its 4.25 GB
host file is not a valid fresh-image growth comparator; the paired rustfmt-only
images above provide the enforced disk-growth result.

That producer completed in 23 minutes 32 seconds with 2,277,972 KiB peak
resident memory at Rust revision `60258b08da0e5b5285ceddfe3b4337f625171bf1`;
its formatter reported `rustfmt 1.10.0-dev (60258b08da 2026-09-11)` and its
native formatting suite passed in 892 ms.

The D4 candidate, Rust revision `9f2e10270e097f607d00bffd8dae2980ff7c26ef`
with no dirs-sys, measured a 19,660,056-byte stripped rustfmt, the same
84-byte launcher, and 19,791,872 bytes of fresh-qcow2 growth, both within
the ceilings. Its Rust overlay is 259,208,943 bytes; its fresh main and
developer images are 26,214,400 and 614,203,392 bytes. Its producer completed
in 40 minutes 50 seconds with 2,924,020 KiB peak resident memory. The packaged
formatter reports `rustfmt 1.10.0-dev (9f2e10270e 2026-09-12)` and has
SHA-256 `dcc0a09981b2a7f91640d77cd932533fe15c106d90bd2d03c3abdfe6ba4f4ed7`.
The complete 6.6 sequence then passed in 3 minutes 19 seconds: both sources
tests, the producer contract tests, both size gates, the analyzer acceptance
(21.29 seconds to quiescence), `test-unwind.sh` in every link mode, the native
formatting suite in 1,152 ms including the `/user/cfg/rustfmt/rustfmt.toml`,
`/user/rustfmt.toml`, and ignored-environment cases, and the Helix release
gate with formatting on save, manual formatting, width configuration,
parser-error recovery, all prior semantic checks, and clean server shutdown.

Two pre-existing test-only defects surfaced during that validation and were
fixed per AGENTS.md. `test-dev-memory-contract.sh` did not stub
`test-rustfmt-native.sh` after patch 16 added it to the candidate wrapper;
the stub and expected sequences now include it, in the native-fixture commit.
Both size gates counted YAML lines with a host `rg`, which is not a documented
host prerequisite and was only present in the earlier sessions' harness; they
use `grep -cxF` now.

Motor-os implementation commits through patch 17 are `24517f53` (candidate
harness), `70045e78` (unwind fixture), `32007447` (abort profiles), `4b11fda9`
(installed-std analyzer), `c3e33a49` (ELF validation), `e279fe90` (bootstrap
cache), `ed4bb6b7` (abort-only C ABI shim and rt.vdso), `ebdf5e3e`
(cross-language cases), `55b0058b` (candidate unwind modes), `0606f5bc`
(private-build cleanup), `ed9457df` (D4 plan revision and rustfmt sources
test), `bcbbf312` (rustfmt build), `cfa9f049` (rustfmt packaging), `35b9789d`
(native fixtures), `891940e5` (size contract), `1cec7c98` (analyzer size gate
without host ripgrep), and `6d9cabe3` (Helix formatting). The local Rust fork
ends at
`9f2e10270e097f607d00bffd8dae2980ff7c26ef` and its worktree is clean.

## 6. Tests

All new tests run from `src/tests/full-test.sh` directly or transitively and
are offline.

### 6.1 Generic unwind fixtures

Add `src/tests/unwind/` (crate `motor-unwind-test`, own workspace, seeded
from the existing `rust-analyzer-unwind` crate's cases) and
`src/tests/test-unwind.sh` as new files; the existing
`src/tests/rust-analyzer-unwind/` and `test-rust-analyzer-unwind.sh` are left
untouched until the cleanup patch deletes them. The script builds with plain
`cargo build --release --locked --offline --target x86_64-unknown-motor`
against the installed sysroot (no build-std, no source root) and runs each
case as a subcommand. The crate is built in two link modes, because they
enter the process differently: the default pure-Rust link (no rustflags,
rustc's default `cc`, entry through the weak `motor_start`, registration from
`sys::init`) and the C-runtime link (`motor-clang` with
`-C link-self-contained=no -C default-linker-libraries=yes`, entry through
mlibc's `crt1.o`, registration from the constructor). The `cxx*` cases exist
only in the C-runtime build. Cases:

| Case | Assertion |
|---|---|
| `cancel` (existing) | 4 threads, 128 `resume_unwind` cancellations, nested catch/rethrow, 256 destructors, no hook call, clear panic state |
| `hook` (existing) | one ordinary caught panic invokes the hook once |
| `abort` (existing) | `catch_unwind(process::abort)` terminates with status -1 |
| `join` | a spawned thread panics; `join()` returns `Err` carrying the payload; the process continues |
| `double` | a panic during unwind cleanup terminates; parent observes the abort status |
| `extern-c` | a panic escaping an `extern "C"` function terminates; parent observes the abort status |
| `cxx` | a C++ object built by the image's `c++` throws and catches its own exception, then the Rust side panics and catches, in one process |
| `cxx-static` | a C++ static constructor throws and catches during `.init_array`, before `main`; the process reaches `main` and reports it |
| `cxx-through-rust` | C++ throws through a Rust `extern "C-unwind"` callback frame holding a `Drop` guard; the C++ `catch` receives it and the Rust destructor ran |
| `rust-through-cxx` | Rust panics inside an `extern "C-unwind"` callback invoked from C++ through a frame holding an RAII object; `catch_unwind` on the Rust side receives the payload and the C++ destructor ran |

Build variants: the default profile with no flags (target default, must
unwind), an explicit `panic = "abort"` build (the `cancel` case must abort
inside `catch_unwind`; verbose cargo output must show `-C panic=abort`), and
release with `lto = "fat"`. Guest execution: the main-image branch of
`full-test.sh` uploads the test binaries with its existing sftp block next to
`systest` (guest `$TEST_BIN`, which exists on both images) and runs them with
`vm_ssh`; `test-rust-analyzer-crates.sh --run-motor` is not used because it
hard-codes a `/devtools/tmp` destination and the main-image suite asserts
`/devtools` is absent. The `cxx*` cases and a native compilation of the whole
crate with `/devtools/bin/rustc` run only in the developer-image branch. Before
upload, `test-unwind.sh` runs the 4.8 ELF validation on every test binary it
built. Child exit statuses are observed by a Motor parent process, not through
SSH.

### 6.2 Producer contract tests

- `src/tests/test-toolchain-native.sh`: the mock `x.py` asserts
  `src/tools/rustfmt` in its arguments and produces both `rustc-main` and
  `rustfmt`; rejection when rustfmt is missing or lacks the identity strings.
- `src/tests/test-toolchain-native-rust-analyzer.sh`: extend the ELF fixtures
  for the first-`PT_LOAD`, `GNU_EH_FRAME`, `__unw_` sentinel, and single
  `_Unwind_RaiseException` checks; remove the library-preparer cases.
- `src/tests/test-toolchain-assembly.sh`, `test-toolchain-assembly-selection.sh`:
  new manifest fields, required output, hash, and recipe literals; an
  assembly lacking rustfmt or with a tampered rustfmt hash is not selectable.
- `src/tests/test-toolchain-versions.sh`, `test-toolchain-cutover.sh`: the new
  revision, lock hashes, and toolchain id.
- imager unit test: required executables count 10 with both rustfmt paths.
- `src/tests/test-rustfmt-sources.sh`: on the selected compiler's source
  tree, `cargo tree -p rustfmt-nightly --locked --offline` for the Motor
  target lists neither `dirs` nor `dirs-sys`, and the Linux graph still
  lists `dirs 6.0.0`. It runs in `full-test.sh` next to
  `test-rust-analyzer-sources.sh` and honors `MOTOR_RUST_SOURCE`.
- Delete `src/tests/test-rust-analyzer-unwind.sh` and its crate in the
  cleanup patch (11), after 6.1 has passed on a candidate.

### 6.3 Native rustfmt fixtures (developer image)

New `src/tests/test-rustfmt-native.sh` with fixtures under
`src/tests/rustfmt-fixtures/`, expected outputs produced by the host
toolchain's rustfmt at the same revision and checked in:

- `--version` equals `rustfmt 1.10.0-dev (<10 hex> <date>)` with the hex
  matching the effective Rust revision prefix;
- stdin to stdout, exit 0, exact bytes;
- in-place file formatting in a directory whose name contains a space, then a
  second run produces no change;
- a project `rustfmt.toml` (`max_width = 60`) is honored from the file's
  directory; `/user/cfg/rustfmt/rustfmt.toml` and then `/user/rustfmt.toml`
  are each honored while installed and are removed again, also on failure;
  `HOME` and `XDG_CONFIG_HOME` pointing at directories that hold the same
  file change nothing;
- `--edition 2024` accepts syntax that `--edition 2015` rejects;
- a macro invocation that needs speculative parsing formats correctly;
- a fatal lexer input (unterminated raw string) exits 101 because lexing starts
  before rustfmt's parser unwind boundary, while a fatal parser input exits 1;
  both emit an `error` diagnostic on stderr, leave the file byte-identical,
  and allow a following valid run to succeed.

Wire it into the developer branch of `full-test.sh` next to
`test-rust-analyzer-native.sh`.

### 6.4 Helix acceptance (developer image)

Extend `src/tests/test-helix-lsp.sh` in the existing SSH/PTY session, in the
project path containing spaces:

1. Open a file with deliberately unformatted valid Rust. Wait for readiness
   through the existing helper.
2. `:format`. Assert a `textDocument/formatting` request and a non-null
   response in the LSP log, the buffer changed (screen capture), and the file
   on disk unchanged.
3. `:w`. Assert the saved bytes equal the checked-in expected formatting.
4. Insert an unformatted edit, `:w`. Assert the file is formatted again
   (format-on-save) and a second formatting response was logged.
5. With a project `rustfmt.toml` setting `max_width = 60`, repeat step 3 and
   assert the width was honored.
6. Introduce a fatal syntax error, `:w`. Assert the formatter logged exit 1
   (warning line in the Helix log), the file was saved unformatted, and after
   repairing the source `:w` formats again.
7. The existing hover, definition, completion, diagnostics, std navigation,
   and shutdown steps remain, with positional fixtures adjusted only where
   formatting moved them.

Add one console run of the shipped launcher in `test-tui.sh` covering steps 2
and 3. Preserve LSP logs and terminal evidence as today.

### 6.5 Documentation updates

`docs/build-rustc.md`: replace the "Native rustfmt is not packaged" sentence
with the formatting workflow; add a section on panic strategies (default
unwind, opt-out via profile, native and shell examples, the `rt::init`
boundary). `docs/toolchain.md` sections 3.2 and 5.2: the unwind default, and
that rustfmt adds no patched dependency. `docs/plans/rust-unwinding.md`
and `docs/plans/helix-rust-analyzer.md`: status paragraphs pointing here.
The packaged editor guide under `img_files/motor-os-dev`: formatting keys.

### 6.6 Candidate validation versus the managed gate

`src/tests/full-test.sh` runs `test-toolchain-cutover.sh` unconditionally
(line 50 today), and that test requires the tracked selector to name the
declared clean tuple. An authoring candidate can never satisfy it. Run the
baseline full suite before changing the current tuple's assembly inputs
(patch 1); subsequent full-suite runs are reserved for the managed cutover
(section 8). Candidates are validated by direct component commands, all run
from the candidate worktree after building its release developer image,
with its `rust-toolchain.toml` pointing at the candidate:

```sh
MOTOR_RUST_SOURCE=/home/posk/motor-dev/rust-unwind-authoring src/tests/test-rust-analyzer-sources.sh --release
MOTOR_RUST_SOURCE=/home/posk/motor-dev/rust-unwind-authoring src/tests/test-rustfmt-sources.sh
src/tests/test-toolchain-native.sh
src/tests/test-toolchain-native-rust-analyzer.sh
src/tests/test-toolchain-assembly.sh
src/tests/test-toolchain-assembly-selection.sh
src/tests/test-rust-analyzer-size.sh
src/tests/test-rustfmt-size.sh
src/tests/test-candidate-vm.sh --release          # new, see below
MOTO_MEMORY_MIB=8192 \
FULL_TEST_IMAGE=motor-os-dev.qcow2 \
FULL_TEST_IMAGE_PREBUILT=1 \
FULL_TEST_VERIFY_DEV_SOURCES=1 \
src/tests/test-tui.sh --release
```

The analyzer and rustfmt size scripts are host-side gates run after the release
image build and before VM acceptance. They enforce the artifact and fresh-image
growth ceilings on the candidate assembly; mock contract tests do not replace
these measurements.

`test-rust-analyzer-native.sh`, `test-rust-analyzer-crates.sh`, and the new
`test-unwind.sh` and `test-rustfmt-native.sh` assume a VM already running at
the suite's address; today only `full-test.sh` boots one for them. Add
`src/tests/test-candidate-vm.sh`: it boots the candidate developer image the
way `full-test.sh` does (same launcher, key, and known-hosts handling,
factored into a sourced helper rather than copied), runs the applicable
scripts in that order, and shuts the VM down. The wrapper initially runs the
two existing analyzer scripts; patch 2 adds `test-unwind.sh`, and patch 16
adds `test-rustfmt-native.sh`. `full-test.sh` sources the same helper so the
boot code exists once. The wrapper exports
`MOTO_MEMORY_MIB="${MOTO_MEMORY_MIB:-8192}"` before launching QEMU, matching
the developer suite's analyzer default and preserving an explicit caller
override. This belongs in the candidate wrapper: the shared launcher keeps
its existing 1024 MiB default for other callers. Extend
`test-dev-memory-contract.sh`, already run by `full-test.sh`, to check the
candidate wrapper's default and override without booting a VM.

`test-tui.sh` already boots its own VM and needs no wrapper. Its direct
developer-image invocation must set `FULL_TEST_VERIFY_DEV_SOURCES=1` to
enable the Helix tests and developer-image assertions. Host source tests
take `MOTOR_RUST_SOURCE` so they examine the authoring checkout instead of
the managed sources.

## 7. Patch sequence

100 to 300 changed lines including tests per patch. Each patch is gated by
its component tests, `cargo fmt` from the repository-selected toolchain
(`./x fmt` in the fork), Clippy and compiler warnings, shell syntax, and
`git diff --check`.

Candidate isolation. `src/build-motor-os.sh` has no host-only stop: one run
builds the host prefix, the native compiler, the analyzer, and the images,
and it writes the images into the checkout it runs from. Every candidate
producer run therefore happens in a disposable worktree,
`git worktree add /home/posk/motor-dev/motor-os-candidate`, sharing `MOTORH`
(keyed prefixes, state, and assemblies are content-addressed and cannot
collide) but keeping `build/` and `vm_images/` separate from the user's tree.
In that worktree `rust-toolchain.toml` is set to the candidate's rustup name
so host-cross test builds use the candidate. Candidates are validated with
the direct commands in 6.6, never with `full-test.sh`. The full suite runs on
the unchanged baseline in patch 1 and on the managed cutover in section 8.

Ordering. First factor and validate the VM boot helper on the unchanged
current tuple. The recipe switch changes hashed runtime inputs and the
native configuration digest, making the current assembly pin stale;
`full-test.sh` rebuilds the image and cannot reuse that pin afterward. Keep
the shared ELF validation after the recipe switch and before the first
candidate. The analyzer's private library patch cannot apply to the changed
fork sources, and the producer runs the analyzer stage in the same
invocation, so the analyzer migration (4.9) lands before the first candidate
build rather than after it.

| # | Where | Content | Gate |
|---|---|---|---|
| 1 | motor-os | Record baseline measurements (section 5) before edits; factor the shared VM boot helper into `full-test.sh`; add `test-candidate-vm.sh` for the existing analyzer scripts (6.6), with the 8192 MiB default and caller override covered by `test-dev-memory-contract.sh` | memory contract; `full-test.sh` passes on the unchanged current tuple before any assembly-input or recipe change |
| 2 | motor-os | New `src/tests/unwind/` and `test-unwind.sh` (6.1), wired into `test-candidate-vm.sh`, without the `cxx*` cases and without ELF validation, run against the current toolchain: unwind cases fail, abort cases pass; record it. The current toolchain has no constructor registration or unwind metadata, so only the runtime cases are baseline assertions | script runs; failures are the expected ones |
| 3 | fork | 4.1 runtime selection | `./x check library/std --target x86_64-unknown-motor` |
| 4 | fork | 4.3 finder, constructor, and `init` registration | same check |
| 5 | fork | 4.2 target default | `./x check compiler/rustc_target` |
| 6 | motor-os | 4.5 profile additions | `cargo build -v` shows `-C panic=abort` for each crate in both modes |
| 7 | motor-os | 4.9 recipe switch only: analyzer built against the installed std, fetch-call removal, recipe bump, contract tests updated; old helper, patch, and test untouched | `test-toolchain-native-rust-analyzer.sh`, `test-toolchain-versions.sh`, `test-toolchain-assembly.sh` |
| 8 | motor-os | 4.8 shared ELF validation with the new invariants and negative fixtures, exposed to `test-unwind.sh` | contract fixtures |
| 9 | motor-os | first candidate: `src/build-motor-os.sh --source-mode authoring --rust-source /home/posk/motor-dev/rust-unwind-authoring --authoring-base <commit>` in the candidate worktree, with the 4.12 cache option; record cold-build time, memory, disk, sizes | producer completes: prefix, native compiler, analyzer, images; manifests valid |
| 10 | motor-os | 6.6 candidate validation on the first candidate: 6.1 cases in both link modes with ELF validation, `cxx*` cases, native compilation, analyzer cancellation, semantic and resource gates, `test-rust-analyzer-size.sh` after the release image build, `__unw_` sentinel on rustc-main and the analyzer | all pass |
| 11 | motor-os | 4.9 cleanup: delete the unwind helper, patch, old test and crate; update `MOTOR_OS_RUNTIME_INPUTS` and `src/patches/README.md` | `test-toolchain-versions.sh`, `test-toolchain-assembly.sh`; producer identity derivation succeeds |
| 12 | fork | 4.6 rustfmt lookup behind `cfg(target_os = "motor")`; `dirs` compiled only off Motor | `cargo metadata --locked --offline` on the root workspace; root lock hash unchanged; Motor graph free of `dirs` and `dirs-sys`; `./x check src/tools/rustfmt` |
| 13 | motor-os | plan revision for D4; `test-rustfmt-sources.sh` (6.2) wired into `full-test.sh` | sources test passes against the authoring checkout |
| 14 | motor-os | 4.7 rustfmt bootstrap request and `toolchain_validate_native_rustfmt`; 6.2 native contract test | contract test; second candidate run produces the binary and it passes 4.8 |
| 15 | motor-os | 4.10 packaging, manifests, imager YAML and test | assembly, selection, imager tests |
| 16 | motor-os | 6.3 native rustfmt fixtures in `test-candidate-vm.sh`; size ceilings set from the measured build (section 5) | pass on the second candidate's developer image |
| 17 | motor-os | 4.11 Helix config and 6.4 acceptance | `MOTO_MEMORY_MIB=8192 FULL_TEST_IMAGE=motor-os-dev.qcow2 FULL_TEST_IMAGE_PREBUILT=1 FULL_TEST_VERIFY_DEV_SOURCES=1 src/tests/test-tui.sh --release` in the candidate worktree against the rebuilt candidate developer image |
| 18 | fork + motor-os | 4.12 versions after the fork branch is published; cutover per section 8 | section 8 gates, including the full suites |
| 19 | motor-os | 6.5 documentation; final fresh developer image; evidence recorded here | full gates already passed |

Patch 4 needs the D2 registration exactly as specified. Patches 3 to 5 and 12
are fork edits governed by the motor-os rules per section 3. Nothing
formatter-specific starts before patch 10 passes.

## 8. Cutover, gates, rollback

Cutover order once patch 18's inputs exist: provision a clean managed
toolchain from the new `MOTOR_RUST_REV` with `--source-mode managed`, produce
its assembly, then on that exact tuple run three consecutive passing debug and
three consecutive passing release runs of `src/tests/full-test.sh` (the core
gate applies because the std and compiler used by the whole OS change, even
without `src/sys` edits), then `src/tests/full-test-dev.sh --release` (release
only; this is not Lorry work). These are the first runs of the full suites on
the new toolchain; by then `test-unwind.sh`, `test-rustfmt-native.sh`, and
the Helix extensions are wired into `full-test.sh`'s existing branches. Only
then change `rust-toolchain.toml` and the assembly pin together. Validate the candidate with explicit toolchain and
assembly selection in a disposable checkout first, since
`test-toolchain-cutover.sh` requires the tracked selector and the clean tuple
to agree. No retries, timeout extensions, or ignored failures; the approved
DNS/ping single retry is the only exception.

Rollback restores the previous `MOTOR_RUST_REV`, lock hashes, toolchain id,
`rust-toolchain.toml`, and assembly pin together. Old prefixes, assemblies,
and fresh baseline images are retained; nothing overwrites a completed prefix
or a user's guest disk. Failed candidates and their logs stay distinguishable
from accepted artifacts.

Commits and publication only on request. A managed release needs the fork
revision reachable from `https://github.com/moturus/rust`, matching lock
hashes, and the motor-os selector update. Builds never create remotes, push,
or move refs.

## 9. Scope and external writes

External source changes, only in separate checkouts:

- `/home/posk/motor-dev/rust-unwind-authoring`: `library/unwind/Cargo.toml`,
  `library/unwind/src/lib.rs`, `library/unwind/src/libunwind.rs`,
  `library/panic_unwind/src/lib.rs`, `library/std/src/sys/personality/mod.rs`,
  `library/std/src/sys/pal/motor/mod.rs`, new
  `library/std/src/sys/pal/motor/eh_frame.rs`,
  `compiler/rustc_target/src/spec/base/motor.rs`,
  `src/tools/rustfmt/Cargo.toml`, `src/tools/rustfmt/src/config/mod.rs`, and
  `src/bootstrap/src/core/build_steps/compile.rs` (4.7). The root
  `Cargo.toml` and `Cargo.lock` are not modified. The branch also carries a
  formatting-only `./x fmt` commit for `library/core/src/num/f32.rs` and
  `f64.rs` with no Motor change.

Other external writes: `/home/posk/motor-dev/toolchain-state`,
`/home/posk/motor-dev/toolchains` (new keyed prefix), the authoring
checkout's `build/`, `/home/posk/motor-dev/assemblies`, Cargo caches during
provisioning, and the candidate worktree `/home/posk/motor-dev/motor-os-candidate`.
`/home/posk/motor-dev/toolchain-src/rust` is not edited. No changes in
moto-rt, `src/sys` Rust sources, Lorry source, Helix, LLVM, or mlibc; the
`src/sys` edit is the build-std flag in `src/sys/lib/rt.vdso/build.sh` (4.5),
and the only Lorry-path edit is the profile line in `src/bin/lorry/Cargo.toml`
(4.5). A
change that proves necessary elsewhere is a stop-and-review event with exact
paths. The
only new startup work is the D2 registration. Follow AGENTS.md for
preexisting bugs found along the way.

## 10. Review record

Patch references below follow the current sequence in section 7.

All four items from the 2026-09-11 review are answered:

1. **Reviewer for the fork edits: not needed.** Motor OS work; the motor-os
   `AGENTS.md` governs (section 3).
2. **Toolchain id `.dev.2`: agreed** (section 4.12). **dirs-sys remote:**
   fork the Codeberg upstream into `https://github.com/moturus/dirs-sys-rs`,
   branch `motor-os`; superseded by D4 on 2026-09-12 (no fork exists).
3. **Size ceilings: agreed** as test-enforced limits set from the first
   measured build with about ten percent margin (section 5).
4. **ripgrep switches to unwind: confirmed** (section 4.5).

Second review (2026-09-11, another model), nine findings, all incorporated:

1. C++ exceptions during static initialization: constructor registration
   added (4.3, 4.4), `cxx-static` fixture added (6.1).
2. `branch` plus `rev` is rejected by Cargo: declaration fixed (4.6).
3. rustfmt version prefix is not contiguous in the binary: identity check now
   greps the build-script commit string (4.7).
4. The producer has no host-only stop and the analyzer patch would fail on
   changed sources: analyzer migration moved before the first candidate,
   candidates run in a disposable worktree, old regression kept until then
   (section 7).
5. Dangling references to the deleted helper: added to 4.9.
6. A `path` override escapes identity: local candidates use a `file://` Git
   source with `rev` (4.6).
7. ELF invariants: `p_vaddr` 0, `e_phoff`-based coverage, unwind header
   inside a readable segment, negative fixtures, applied to test binaries
   too (4.8, 6.1).
8. Main-image runner: sftp upload next to `systest`; both entry paths built
   and tested (6.1).
9. Required executables live in `src/imager/motor-os-dev.yaml` (4.10).

Smaller items: patch 17 names the developer-image environment; the Lorry
manifest profile edit is acknowledged in section 9; ripgrep is excluded from
the "every OS binary" check; cross-language `C-unwind` fixtures with
destructor assertions added (6.1).

Third review (2026-09-11), four findings plus one detail, all incorporated:

1. `full-test.sh` runs the cutover check unconditionally, so it cannot
   validate an authoring candidate: new 6.6 defines candidate validation by
   direct component commands plus a small VM wrapper, and runs the full suites
   on the new toolchain only at the managed cutover; `MOTOR_RUST_SOURCE`
   points source tests at the authoring checkout.
2. Old regression deleted too early: the recipe switch (patch 7) and the
   cleanup (patch 11) are separate; 6.1 adds the new fixture instead of
   renaming the old one.
3. Shared ELF validation scheduled after its consumers: moved to patch 8,
   before the first candidate; patch 2's baseline is runtime-only.
4. Ordinary host-cross links use the host `cc` with GNU ld, not LLD:
   verified with the selected toolchain (`-static-pie`, `-nostartfiles`,
   `-Wl,--eh-frame-hdr`, headers in the first `PT_LOAD`); 4.3 now names both
   linkers and the validation covers both paths.
5. The `file://` source needs a committed dirs-sys revision: recorded as a
   user-authorized local commit in the fork before patch 13 (4.6, patch 12).

Fourth review (2026-09-11), four findings, all incorporated:

1. The recipe switch invalidates the baseline assembly pin: the VM boot
   helper refactor and its baseline full-suite gate now run first, in patch
   1, before assembly-input changes. Shared ELF validation stays in patch 8,
   before the first candidate.
2. Direct TUI commands omitted the flag that enables developer-image and
   Helix checks: both 6.6 and patch 17 now set
   `FULL_TEST_VERIFY_DEV_SOURCES=1`.
3. Candidate acceptance omitted the analyzer size gate: 6.6 and patch 10 now
   invoke `test-rust-analyzer-size.sh` after building the release image.
4. The candidate wrapper did not inherit the developer suite's memory
   setting: 6.6 specifies an 8192 MiB default, preserves caller overrides,
   and adds coverage to the existing memory contract test in patch 1.

Fifth revision (2026-09-12, user decision), recorded as D4: the dirs-sys fork
is replaced by a `cfg(target_os = "motor")` lookup in rustfmt that returns
`/user` and `/user/cfg`, and `dirs` is compiled only off Motor. The Codeberg
fork, its `moturus/dirs-sys-rs` remote, the `file://` candidate source, the
root lock change, and the publication prerequisite no longer apply (second
review items 2 and 6, third review item 5). The retired local dirs-sys
checkout is referenced by nothing. `HOME` and `XDG_CONFIG_HOME` are ignored
on Motor, and the native fixtures assert that (6.3).

No open questions remain. Implementation starts only when the user says so.
