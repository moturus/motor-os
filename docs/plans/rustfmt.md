# Standard Motor Rust unwinding and native rustfmt

Status: implementation plan, revised 2026-09-11 after a fourth review
(section 10). No implementation,
toolchain builds, external source changes, commits, or publication have been
made. Default policy: leave changes local; commit only when asked.

Decisions recorded:

- **D1 (accepted 2026-09-10):** the Motor target defaults to `panic=unwind`.
  Shipped OS binaries keep abort through explicit profiles (section 4.5).
- **D2 (accepted 2026-09-11):** the unwinder's FDE finder is a Motor-specific
  function registered by std: from a high-priority constructor in mlibc-linked
  binaries and from std's per-platform `init` otherwise (section 4.3).
- **D3 (design):** in Rust-linked binaries the pure-Rust unwinder owns the
  `_Unwind_*` ABI for Rust and C++ frames alike (section 4.4).

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
  compile for Motor today.
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
- No edit touches `src/tools/*`; rustfmt is built, not modified.
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
`src/bin/russhd/Cargo.toml`. `src/sys`, the kernel, boot, and the shim need
nothing. ripgrep (confirmed 2026-09-11) stays on its `release` profile and becomes unwind, which is
its upstream default; record its size delta. Lorry needs no change:
`CargoPanicStrategy::Abort` already emits `panic=abort` and unwind relies on
the target default. Confirm with `cargo build -v` that every OS binary's
command line except ripgrep's carries `-C panic=abort` in both image modes.
The `src/bin/lorry/Cargo.toml` edit is a profile line only, not Lorry source;
per AGENTS.md it does not make this Lorry work.

### 4.6 dirs-sys fork

Upstream moved from GitHub to Codeberg: `https://github.com/dirs-dev/dirs-sys-rs`
is archived and points at `https://codeberg.org/dirs/dirs-sys-rs`. Neither has a
0.5.0 tag. Verified on 2026-09-11: the crates.io 0.5.0 archive was cut from
commit `8bcd4aa2c35990d57a2cff2953793525fc42709c` ("Release 0.5.0"), and the
Codeberg head `cdfffb62ef3bc94192c62d7b3dc95b234aab4e58` differs from it only
in `README.md` and the `repository` field of `Cargo.toml`; every source file
matches the registry archive
(`e01a3366d27ee9890022452ee61b2b63a67e6f13f58900b651ff5665f0bb1fab`).

Fork the Codeberg repository at `cdfffb62` into
`/home/posk/motor-dev/dirs-sys-motor`. Remote, confirmed 2026-09-11:
`https://github.com/moturus/dirs-sys-rs` (GitHub, like the other moturus
patched dependencies), branch `motor-os`. The crate being patched is
`dirs-sys`; `dirs 6.0.0` itself is unchanged. Changes in `src/lib.rs`:

- Add `#[cfg(target_os = "motor")] mod target_motor { pub fn home_dir() ->
  Option<PathBuf> }` returning nonempty `HOME`, else `std::env::home_dir()`,
  and re-export it like the Unix and Redox arms.
- Widen the `xdg_user_dirs` module and the `target_unix_not_mac` block
  (`user_dir`, `user_dirs`) from `cfg(all(unix, not(any(macos, ios))))` to also
  cover `target_os = "motor"`.
- In `src/xdg_user_dirs.rs`, replace the Unix-only `OsStringExt::from_vec`
  conversion with a helper: on Unix keep the byte conversion; on Motor use
  `String::from_utf8(bytes).ok().map(OsString::from)` and skip entries that
  fail.

Tests, in the fork's `src/lib.rs` test module, runnable on Linux and natively
on Motor through `src/tests/test-rust-analyzer-crates.sh --run-motor` style
execution: HOME set, HOME empty with std fallback, absolute and relative
`XDG_CONFIG_HOME`, a `user-dirs.dirs` fixture with valid entries, an invalid
UTF-8 entry, and unchanged Linux results.

Rust fork root `Cargo.toml`, in the existing `[patch.crates-io]` table:

```toml
dirs-sys = { git = "https://github.com/moturus/dirs-sys-rs.git", rev = "<full 40-char revision on the motor-os branch>" }
```

Cargo accepts only one of `branch`, `tag`, or `rev`, so the branch name is
documentation, not part of the declaration. Until the user publishes the
fork, candidate builds use a local Git source, never a `path` override:

```toml
dirs-sys = { git = "file:///home/posk/motor-dev/dirs-sys-motor", rev = "<committed revision>" }
```

This requires a committed revision in `/home/posk/motor-dev/dirs-sys-motor`
before the Rust fork consumes it in patch 13. Under the "commit only when
asked" policy that local commit is an explicit prerequisite the user
authorizes; it is a commit in the dirs-sys fork only, not in motor-os or the
Rust fork, and it is never pushed by a build. A `path` override would let
edits to the sibling checkout change the build without changing the Rust
manifest, lock, or toolchain key. A Git source with
a full `rev` is content-addressed: the lock records the commit, the root lock
hash is already a toolchain identity input, and Cargo verifies the checkout
against that commit. Switching the URL to GitHub at publication changes the
lock and therefore the key, which is intended. Regenerate the root lock with
`cargo update -p dirs-sys` (network for the first fetch of the fork, then
`--offline`) and confirm the diff touches only the `dirs-sys` source entry.

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
path as the source of truth. Add `toolchain_validate_native_rustfmt`: the
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
`MOTOR_RUST_REF` and `MOTOR_RUST_REV` to the new branch and revision, update
`MOTOR_RUST_ROOT_LOCK_SHA256` (dirs-sys entry) and, only if it changed,
`MOTOR_RUST_LIBRARY_LOCK_SHA256`. Bump `MOTOR_TOOLCHAIN_ID` to
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
  directory; `XDG_CONFIG_HOME/rustfmt/rustfmt.toml` is honored when set;
- `--edition 2024` accepts syntax that `--edition 2015` rejects;
- a macro invocation that needs speculative parsing formats correctly;
- a fatal lexer input (unterminated raw string) and a fatal parser input:
  exit 1, an `error` diagnostic on stderr, the file byte-identical
  afterwards, and a following valid run succeeds.

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
boundary). `docs/toolchain.md` sections 3.2 and 5.2: the unwind default and
the dirs-sys fork among the patched dependencies. `docs/plans/rust-unwinding.md`
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
src/tests/test-toolchain-native.sh
src/tests/test-toolchain-native-rust-analyzer.sh
src/tests/test-toolchain-assembly.sh
src/tests/test-toolchain-assembly-selection.sh
src/tests/test-rust-analyzer-size.sh
src/tests/test-candidate-vm.sh --release          # new, see below
MOTO_MEMORY_MIB=8192 \
FULL_TEST_IMAGE=motor-os-dev.qcow2 \
FULL_TEST_IMAGE_PREBUILT=1 \
FULL_TEST_VERIFY_DEV_SOURCES=1 \
src/tests/test-tui.sh --release
```

`test-rust-analyzer-size.sh` is a host-side gate run after the release image
build and before VM acceptance. It enforces the existing 32 MiB analyzer,
80 MiB rust-src, and 128 MiB fresh-image growth ceilings on the candidate
assembly; mock contract tests do not replace these measurements.

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
| 12 | dirs-sys fork | 4.6 port and tests; the user commits the fork locally (prerequisite for 13) | Linux tests pass; native tests pass on the candidate developer image |
| 13 | fork | root manifest entry with the local `file://` Git source and `rev`; lock update | `cargo metadata --locked --offline` on the root workspace; lock diff is the single entry |
| 14 | motor-os | 4.7 rustfmt bootstrap request and `toolchain_validate_native_rustfmt`; 6.2 native contract test | contract test; second candidate run produces the binary and it passes 4.8 |
| 15 | motor-os | 4.10 packaging, manifests, imager YAML and test | assembly, selection, imager tests |
| 16 | motor-os | 6.3 native rustfmt fixtures in `test-candidate-vm.sh`; size ceilings set from the measured build (section 5) | pass on the second candidate's developer image |
| 17 | motor-os | 4.11 Helix config and 6.4 acceptance | `MOTO_MEMORY_MIB=8192 FULL_TEST_IMAGE=motor-os-dev.qcow2 FULL_TEST_IMAGE_PREBUILT=1 FULL_TEST_VERIFY_DEV_SOURCES=1 src/tests/test-tui.sh --release` in the candidate worktree against the rebuilt candidate developer image |
| 18 | fork + motor-os | dirs-sys GitHub `rev` pin after publication; 4.12 versions; cutover per section 8 | section 8 gates, including the full suites |
| 19 | motor-os | 6.5 documentation; final fresh developer image; evidence recorded here | full gates already passed |

Patch 4 needs the D2 registration exactly as specified. Patches 3 to 5 and 13
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

Commits and publication only on request. A managed release needs the dirs-sys
revision reachable from `https://github.com/moturus/dirs-sys-rs`, a
moturus/rust revision pinning it, matching lock hashes, and the motor-os
selector update. Builds never create remotes, push, or move refs.

## 9. Scope and external writes

External source changes, only in separate checkouts:

- `/home/posk/motor-dev/rust-unwind-authoring`: `library/unwind/Cargo.toml`,
  `library/unwind/src/lib.rs`, `library/unwind/src/libunwind.rs`,
  `library/panic_unwind/src/lib.rs`, `library/std/src/sys/personality/mod.rs`,
  `library/std/src/sys/pal/motor/mod.rs`, new
  `library/std/src/sys/pal/motor/eh_frame.rs`,
  `compiler/rustc_target/src/spec/base/motor.rs`, root `Cargo.toml` and
  `Cargo.lock`.
- `/home/posk/motor-dev/dirs-sys-motor`: `src/lib.rs`, `src/xdg_user_dirs.rs`,
  tests.

Other external writes: `/home/posk/motor-dev/toolchain-state`,
`/home/posk/motor-dev/toolchains` (new keyed prefix), the authoring
checkout's `build/`, `/home/posk/motor-dev/assemblies`, Cargo caches during
provisioning, and the candidate worktree `/home/posk/motor-dev/motor-os-candidate`.
`/home/posk/motor-dev/toolchain-src/rust` is not edited. No changes in
moto-rt, `src/sys` sources, Lorry source, Helix, LLVM, or mlibc; the only
Lorry-path edit is the profile line in `src/bin/lorry/Cargo.toml` (4.5). A
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
   branch `motor-os` (section 4.6).
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

No open questions remain. Implementation starts only when the user says so.
