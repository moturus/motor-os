# Building rustc for Motor OS

This guide assumes you have completed [build-llvm.md](build-llvm.md): `$MOTORH`
contains the Motor OS repo, the `rust` checkout with the registered
`dev-x86_64-unknown-motor` toolchain ([build.md](build.md)), the
`llvm-project` checkout with the host cross toolchain in
`$MOTORH/llvm-project/build/bin`, the `mlibc` checkout, and a populated
C/C++ sysroot at `$MOTORH/motor-sysroot`.

The end result is a Motor OS VM image that carries a **native `rustc`** — the
real Rust compiler, statically linked with its own LLVM, running on Motor OS —
plus a Rust sysroot (std and friends as rlibs), so that, booted into the VM, you
can compile and run Rust programs natively — a single `rustc`, no linker flag:

```sh
/sys/tools/rust/bin/rustc --version
/sys/tools/rust/bin/rustc /sys/tools/rust/src/hello.rs \
    -o /sys/tmp/hello && /sys/tmp/hello
```

rustc does not link by itself — on every platform it drives an external C
compiler, which it looks up by the bare name `cc`. On Linux that is
`/usr/bin/cc`; on Motor it is `/bin/cc`, a `#!/bin/rush` pass-through to the
`/sys/tools/llvm/bin/llvm` multicall's clang, **produced by
[build-llvm.md](build-llvm.md)** (it belongs with the C toolchain it fronts).
Because rustc finds `cc` on `PATH` (=`/bin`) on its own, no `-C linker=` flag is
needed.

**Pure Rust links no libc.** rustc passes `-nostartfiles -nodefaultlibs`
(structural: the target spec sets `link_self_contained` and rustc defaults to
`-C default-linker-libraries=no`), and the clang Motor ToolChain honors both,
so a pure-Rust `hello.rs` is ~113 KB — std's weak `motor_start` owns the entry
point, zero mlibc. A Rust program that **links C / wants mlibc** opts back into
the ToolChain's C runtime recipe (mlibc's `crt1.o` + the full runtime group,
fully initialized, mlibc's strong `motor_start` takes the entry point) with two
stock flags:

```sh
/sys/tools/rust/bin/rustc -C link-self-contained=no \
    -C default-linker-libraries=yes foo.rs -o foo
```

(For cargo cross-builds: put the pair in `rustflags` under
`[target.x86_64-unknown-motor]`, and point `-C linker=` at
`$SYSROOT/bin/motor-clang`.) Rust code calling real C++ additionally needs
`-C link-arg=-lc++` — rustc drives `cc` in C mode, which links libc++abi but
not libc++. Forgetting the pair in a Rust+C link fails loudly with undefined C
symbols; see [libc_start_redesign.md](libc_start_redesign.md) for the design.

On the image the Rust toolchain lives at `/sys/tools/rust` (`bin/rustc`,
`lib/rustlib/x86_64-unknown-motor/lib/*.rlib`, sample sources at `src/`). The
system C compiler / linker driver `/bin/cc` and the LLVM multicall it fronts come
from build-llvm.md; this guide only builds and stages the Rust half. Everything
is cross-built on the host by Rust's own bootstrap (`x.py`) and staged into the
image, exactly like the C toolchain in [build-llvm.md](build-llvm.md).

This build runs **on top of build-llvm.md** and reuses everything it produced:
the host cross-clang, the C/C++ sysroot (the `libc.a`/`crt1.o`/headers built
from mlibc — the mlibc *source* tree is no longer needed and can be deleted),
and — crucially — the **one** `llvm-project` checkout. All Motor OS support
lives on **`motor-os-rustc` branches of `github.com/moturus` forks**. The
checkouts on disk are just `rust` (from [build.md](build.md)) and `llvm-project`
(from build-llvm.md). The four dependency forks (`libc`, `rust_libloading`,
`stacker`, `rust-ctrlc`) are **fetched by cargo** from their git URLs — no
local clones — and `moto-rt` comes straight from crates.io. `src/build-rustc.sh`
performs every step below in one go (copy it into `$MOTORH` next to
`build-base.sh`/`build-llvm.sh` and run it after those two); it carries no
patches of its own.

**One LLVM, version 23.** rustc builds its own copy of LLVM from
`src/llvm-project`; this build seeds that checkout from build-llvm.md's
`moturus/llvm-project` @ `motor-os-rustc` checkout, shares its git objects, and
checks out its exact commit. So there is one LLVM repo, commit, and version, no
version split. (rustc's default pin is LLVM 22.1.7; 1.98-dev already carries the
LLVM-23 support code, plus one four-line adaptation on the `moturus/rust` branch
for a struct LLVM 23 made non-copyable — see the appendix.)

The explicit seeding avoids a known fork-history trap. The rust fork's gitlink
(`4c0679b5a854`) was orphaned when the LLVM branch tip was amended
(`88ea5aa2a7b4`). A plain `git submodule update` therefore depends on GitHub
retaining and serving an unreachable object; its direct-fetch fallback can
also fail with `transport 'file' not allowed` when a local reference checkout
is supplied. Stage R1 deliberately bypasses that stale gitlink and uses the
already validated build-llvm checkout. The upstream cleanup is still to update
the rust fork's gitlink to the LLVM branch tip.

## How the pieces fit together

A native rustc is one static-PIE binary with two C runtimes and two language
runtimes inside, all of which must agree:

```
rustc  (≈98 MB stripped)
  ├─ rustc crates + Rust std        compiled by x.py for x86_64-unknown-motor
  │    └─ moto-rt (crates.io)       std's runtime, talks to the RT.VDSO
  ├─ LLVM 23 static libs            cross-built by x.py from src/llvm-project
  │    └─ libc++ / libc++abi / libunwind   (the C++ stack from build-llvm.md)
  └─ mlibc crt1.o + libc.a          owns the entry point and the C runtime
```

The load-bearing decisions, each of which the stages below implement:

- **mlibc owns the entry point.** rustc's LLVM half needs a full C runtime
  (`.init_array` static constructors, C stdio, a C-level TCB). std's
  `motor_start` is declared `weak`, so mlibc's `crt1.o` wins the link: it
  initializes the VDSO vtable, the TCB and stdio, runs `.init_array`, then
  calls the C `main` that rustc's codegen emits — which enters Rust's
  `lang_start`. Pure-Rust programs (no mlibc in the link) keep std's entry.
- **One emulated-TLS and one allocator.** The C side (LLVM, libc++) uses the
  shim (`libmoto_rt_cabi.a`) from build-llvm.md stage 2; the Rust side talks
  to the same VDSO. mlibc's strong `mem*` must beat moto-rt's weak ones — the
  crates.io `moto-rt` ≥ 0.16.1 declares those `mem*` symbols weak, so no
  `[patch]` is needed (earlier releases needed a local fork).
- **Foreign threads get a lazy mlibc TCB.** rustc's worker threads are spawned
  by Rust std, not `pthread_create`, so their `UTCB.libc_tcb` is zero. mlibc's
  `get_current_tcb()` materializes a minimal TCB on first use
  (`__mlibc_motor_lazy_tcb`); without it, the first *contended* `std::mutex`
  on a Rust-spawned thread aborts (mutex owner bookkeeping reads the TCB tid).
- **libc++abi provides `operator new/delete`.** mlibc's internal
  `operator delete` panic stubs are **strong** symbols while libc++abi's real
  operators are **weak** — whenever both objects are extracted, the panic stub
  silently wins, and no link order can fix that. On Motor the stubs are
  compiled out of mlibc (`#ifndef __motor__`).
- **The host and motor LLVM builds must be component-identical.** rustc builds
  LLVM 23 twice from the one submodule — once for the host stage compilers,
  once cross-compiled for motor. `rustc_llvm`'s build script queries the *host*
  `llvm-config` and rewrites host paths to target paths, so both use the same
  `targets = "X86"`, `experimental-targets = ""` configuration.
- **No dynamic linking anywhere.** `rustc_driver` gains an `rlib` crate type
  (rustc drops the `dylib` with a warning on targets without dynamic linking);
  proc-macro loading and dylib codegen backends are stubbed by the
  `libloading` fork (a single 0.9 version — `rustc_metadata` was bumped off
  0.8); there are no proc-macro or `-C prefer-dynamic` builds on the image.
- **rustc drives the link through a `cc`.** rustc passes `-nostartfiles
  -nodefaultlibs` to its linker (it owns the runtime itself), which suppresses
  the clang driver's automatic `crt1.o` + mlibc/libc++ link group. On the
  host, the `motor-rust-cc` wrapper re-adds that group after rustc's inputs —
  rustc *is* a C++/LLVM program and genuinely needs mlibc, entry point
  included. On the image, `/bin/cc` (from build-llvm.md) is a pure
  pass-through to `/sys/tools/llvm/bin/llvm clang`: the Motor ToolChain owns
  the recipe and honors rustc's flags, so a native pure-Rust `rustc hello.rs`
  links **no** mlibc (~113 KB, std's entry point), a native `cc hello.c` gets
  the full C runtime from the ToolChain, and a native Rust+C link opts back in
  with `-C link-self-contained=no -C default-linker-libraries=yes` (see the
  intro; the design is argued in
  [libc_start_redesign.md](libc_start_redesign.md)). Note the two link
  contexts do **not** share a target-spec change: `base/motor.rs` is left
  untouched (the same built-in spec is compiled into the `dev` host toolchain
  that `make all` uses to link the OS's own pure-Rust programs via the host
  `cc`, and must keep passing `-nostartfiles -nodefaultlibs`); the mlibc group
  lives in the host's `motor-rust-cc` wrapper, not the spec.

Rough budget: a first build is ~1.5–2.5 h (two full LLVM builds plus the
compiler crates dominate) and adds ~160 MB to the image. Re-runs are
incremental.

## Prerequisites and environment

Everything from [build-llvm.md](build-llvm.md), plus the environment below:

```sh
export MOTORH=$HOME/motorh          # same root as build.md / build-llvm.md
export MOTOR=$MOTORH/motor-os
export LLVM=$MOTORH/llvm-project
export MLIBC=$MOTORH/mlibc
export B=$LLVM/build/bin            # host cross clang/lld/llvm-* (build-llvm stage 1)
export SYSROOT=$MOTORH/motor-sysroot
export RUST=$MOTORH/rust            # the rust checkout from build.md
```

Everything the port needs is on `moturus/*` forks, all on the **same
`motor-os-rustc` branch**. build-llvm.md already checked out `mlibc` and
`llvm-project` on that branch, so the only checkout this build *switches* is
the rust tree:

1. **The rust checkout** is set up by [build.md](build.md) against upstream
   `rust-lang/rust`. This build adds the `moturus` remote and switches it to
   `moturus/rust` branch `motor-os-rustc` (the Motor host-target patches; see
   the appendix). Its `[patch.crates-io]` already carries the four dependency
   forks as **git URLs** — cargo fetches them, so nothing is cloned by hand.
2. **The `src/llvm-project` submodule** is seeded from build-llvm.md's
   `$MOTORH/llvm-project` (moturus @ `motor-os-rustc`, **LLVM 23**) — the same
   commit, with its objects shared via a local clone. `submodules = false` in
   `bootstrap.toml` keeps bootstrap from resetting it to the stale gitlink.
3. **mlibc source is not needed** — rustc links the sysroot `libc.a`
   build-llvm.md already produced from mlibc `motor-os-rustc`. This build only
   checks that `libc.a` carries the `operator delete` guard; it touches the
   mlibc tree only in the unlikely case that stale `libc.a` must be rebuilt
   (Stage R2).

### This build repurposes the dev toolchain

Step 1 is not a private detail: `$MOTORH/rust` is the checkout that
[build.md](build.md)'s `dev-x86_64-unknown-motor` toolchain is registered
against, and `make all` compiles every Motor OS component with that toolchain
(`cargo +dev-x86_64-unknown-motor …`). Switching the tree to the fork therefore
**re-points the whole Motor OS build at the fork's compiler and std** — the
rustup link still resolves to `build/x86_64-unknown-linux-gnu/stage2`, but what
lives there is now built from `moturus/rust`. Two consequences:

- Everything previously built with the dev toolchain is stale — the Motor OS
  cargo caches (Stage R7 clears them) and anything else in `stage2` that an
  earlier build left behind, clippy above all (Stage R4, and the Pitfalls).
- If a fresh `make all` breaks right after this build while it worked before it,
  suspect this handover — not the Motor OS sources. Re-registering the toolchain
  cannot help: the link was never wrong.

[build.md](build.md) clones `rust-lang/rust` unpinned, so on a new machine the
tree starts at master-of-today and this build rewinds it to the fork's base
(`8b6558a02b27`). The two are only guaranteed to agree on the machines where the
fork is the tree.

The Motor OS checkout must carry the rustc-era runtime fixes: the RT.VDSO
`ChildStdio` EOF-on-closed-pipe mapping and `O_APPEND` support in `rt_fs.rs`,
and a data partition of at least 512 MB in `src/imager/motor-os.yaml` (rustc
plus the Rust and C sysroots need the room).

Two dependencies need **no fork at all** anymore:

- **getrandom** — upstream supports Motor OS since 0.4.3, and the compiler's
  only getrandom route for the motor target is `rand` 0.10+ (the branch bumps
  the three compiler crates off rand 0.9, whose rand_core still pulls
  getrandom 0.3).
- **memmap2** — the motor target does not depend on it at all:
  `rustc_data_structures` gates the dependency out for motor and
  `memmap.rs` falls back to `Vec<u8>` there.

## Stage R1 — sources

No dependency clones — the four forks are `[patch.crates-io]` git URLs cargo
resolves on its own. Only the rust tree switches to the fork, and its LLVM
submodule is pointed at build-llvm.md's LLVM-23 checkout:

```sh
# The rust tree: add the fork remote and switch to it (build.md left it on
# upstream rust-lang/rust).
cd $RUST
git remote add moturus https://github.com/moturus/rust.git
git fetch moturus motor-os-rustc
git switch -c motor-os-rustc moturus/motor-os-rustc

# Seed the LLVM submodule from build-llvm.md's checkout (moturus @
# motor-os-rustc, LLVM 23), sharing its objects and using its exact commit.
# protocol.file.allow is scoped to this trusted local clone; do not change the
# global Git policy. `submodules = false` in bootstrap.toml (below) stops
# bootstrap from resetting it to the stale LLVM gitlink.
git submodule init src/llvm-project
LLVM_COMMIT="$(git -C "$LLVM" rev-parse HEAD)"
LLVM_TOP=
if [ -e src/llvm-project/.git ]; then
    LLVM_TOP="$(git -C src/llvm-project rev-parse --show-toplevel \
        2>/dev/null || true)"
fi
if [ "$(readlink -f "$LLVM_TOP" 2>/dev/null || true)" != \
     "$(readlink -f src/llvm-project)" ]; then
    git -c protocol.file.allow=always clone --no-checkout --shared \
        "$LLVM" src/llvm-project
    git submodule absorbgitdirs src/llvm-project
fi
if ! git -C src/llvm-project cat-file -e "$LLVM_COMMIT^{commit}"; then
    git -c protocol.file.allow=always -C src/llvm-project \
        fetch "$LLVM" "$LLVM_COMMIT"
fi
git -C src/llvm-project checkout -q --detach "$LLVM_COMMIT"
git -C src/llvm-project remote set-url origin \
    https://github.com/moturus/llvm-project.git
```

mlibc and the deps need nothing here — build-llvm.md already checked out mlibc
and built `libc.a`, and cargo fetches the dependency forks. moto-rt comes from
crates.io (`cargo update -p moto-rt` picks up ≥ 0.16.1). The rust fork's
`[patch.crates-io]` already holds the four git URLs, so there are no local
paths to rewrite.

Two Cargo behaviors worth knowing when maintaining the branch:

- A `[patch.crates-io]` entry only takes effect when its version semver-matches
  what dependents require *and* the lockfile agrees. After a version bump (the
  branch moves rand 0.9 → 0.10 and libloading 0.8 → 0.9 in the compiler
  manifests), run `cargo update -p <crate>` so the lock re-resolves onto the
  patch; otherwise cargo silently reports `[patch.unused]`.
- The compiler stays on a **single version of each patched crate** — that is
  what makes one patch key per crate sufficient. `rustc_metadata` was bumped
  from libloading 0.8 to 0.9 for this (patching two majors of one crate is
  possible via `name-x-y = { package = ... }` keys, but keeping two forks
  alive is strictly worse).

## Stage R2 — the sysroot `libc.a` (mlibc source is optional)

rustc links against the **sysroot** `libc.a` / `crt1.o` that build-llvm.md
already built from mlibc `motor-os-rustc`. It does *not* read the mlibc source
tree — you can delete `$MOTORH/mlibc` after build-llvm.md and this build still
works, reusing the installed `libc.a`. (mlibc `motor-os-rustc` carries the two
changes the native rustc needs — the foreign-thread lazy TCB in
`sysdeps/motor/generic/thread.cpp` + `.../mlibc/thread.hpp`, and the
`#ifndef __motor__` guard around the strong `operator delete` panic stubs in
`options/internal/gcc-extra/cxxabi.cpp` — and build-llvm bakes them into that
`libc.a`.)

So the only thing to check here is that the installed `libc.a` carries the
guard, i.e. has no strong `_ZdlPvm`:

```sh
$B/llvm-nm $SYSROOT/sys/tools/llvm/lib/libc.a | grep 'T _ZdlPvm' && echo STALE || echo ok
```

If it is stale (built from the older `motor` branch), rebuild it — which is the
one step that *does* need the mlibc source checkout present — and refresh the
on-image copy:

```sh
ninja -C $MLIBC/build
( cd $MLIBC/build && DESTDIR=$SYSROOT meson install --no-rebuild )
cp $SYSROOT/sys/tools/llvm/lib/libc.a \
  $MOTOR/img_files/generated/llvm/sys/tools/llvm/lib/libc.a

# The strong stubs must be gone (only U references may remain):
$B/llvm-nm $SYSROOT/sys/tools/llvm/lib/libc.a | grep 'T _ZdlPvm' && echo BAD || echo ok
```

## Stage R3 — compiler wrappers and bootstrap.toml

Rust's bootstrap needs a cc/cxx pair and a linker for the motor target. Three
wrappers in `$SYSROOT/bin` (the script writes them):

- `motor-clang` / `motor-clang++` — the host cross clang with
  `--target=x86_64-unknown-motor --sysroot=$SYSROOT
  -D_GNU_SOURCE -D_DEFAULT_SOURCE`, plus `--no-default-config` to bypass
  `$B/x86_64-unknown-motor.cfg` (its `-nostdlib` is for build-llvm.md's
  explicit link recipes; here the Motor clang driver must complete links
  itself). cmake and cc-rs use these for compiling and for `try_compile`
  probes.
- `motor-rust-cc` — the linker rustc invokes. rustc passes `-nostartfiles
  -nodefaultlibs` (suppressing the driver's automatic runtime group), so the
  wrapper re-appends, *after* rustc's inputs:

  ```
  -Wl,--start-group $SYSROOT/sys/tools/llvm/lib/crt1.o
    -lmoto_rt_cabi -lc++ -lc++abi -lunwind -lc -lclang_rt.builtins-x86_64
  -Wl,--end-group
  ```

  Order inside the group still matters for archive-member selection: the C++
  runtime archives come before `-lc` so their members are chosen first when a
  symbol has several lazy definitions.

`bootstrap.toml` replaces the one from [build.md](build.md) — a superset of it,
so the `dev-x86_64-unknown-motor` toolchain keeps being produced at the path it
is registered at (but built from the fork now — see *This build repurposes the
dev toolchain* above):

```toml
change-id = "ignore"
profile = "library"

[build]
host = ["x86_64-unknown-linux-gnu"]
target = ["x86_64-unknown-linux-gnu", "x86_64-unknown-motor"]
# src/llvm-project is seeded from moturus/llvm-project @ motor-os-rustc
# (LLVM 23); keep bootstrap from resetting it to the stale gitlink.
submodules = false

[rust]
deny-warnings = false
incremental = true

# LLVM (23) is built from src/llvm-project for both triples. X86-only keeps the
# two builds' component lists identical — rustc_llvm's build.rs queries the
# *host* llvm-config and rewrites host->target paths, so any component that
# exists in one build but not the other breaks the link.
[llvm]
download-ci-llvm = false
targets = "X86"
experimental-targets = ""
static-libstdcpp = false

[target.x86_64-unknown-motor]
cc = "<$SYSROOT>/bin/motor-clang"
cxx = "<$SYSROOT>/bin/motor-clang++"
ar = "<$B>/llvm-ar"
ranlib = "<$B>/llvm-ranlib"
linker = "<$SYSROOT>/bin/motor-rust-cc"
```

(The script writes real absolute paths for the `<$...>` placeholders.)

## Stage R4 — build rustc

```sh
cd $RUST
./x.py build --stage 2 compiler --host x86_64-unknown-motor --target x86_64-unknown-motor
```

`--host x86_64-unknown-motor` is what requests a compiler that *runs on*
Motor; `--target` alone builds nothing new. This one command drives, in order:
the host LLVM build, the motor LLVM build (the bootstrap `llvm.rs` motor
branch sets `CMAKE_SYSTEM_NAME=Linux`, `LLVM_HOST_TRIPLE=x86_64-unknown-motor`,
the `CMAKE_*_COMPILER_TARGET`s that key mlibc header probing in the patched
`config-ix.cmake`, and turns off the two shared-library tools LTO/Remarks),
stage1 rustc + std for both triples, and finally the stage2
`x86_64-unknown-motor` compiler crates, linked by `motor-rust-cc`.

The product is
`build/x86_64-unknown-linux-gnu/stage2-rustc/x86_64-unknown-motor/release/rustc-main`
(~154 MB unstripped, ~98 MB stripped) plus an assembled motor sysroot under
`build/x86_64-unknown-motor/stage2`.

Then build std for **both** targets and clippy — in **one** invocation. That
this is a single command is load-bearing, not stylistic (see Pitfalls):

```sh
./x.py build --stage 2 clippy library --target x86_64-unknown-motor,x86_64-unknown-linux-gnu
```

Every `x.py` invocation **wipes the entire stage2 sysroot** and re-links only
what that invocation builds: bootstrap's `Sysroot` step opens with
`remove_dir_all(build/x86_64-unknown-linux-gnu/stage2)` ("Removing sysroot …
to avoid caching bugs"), and that directory *is* the `dev-x86_64-unknown-motor`
toolchain `make all` runs on. The wipe happens once per invocation, so
everything named in one command survives together, while a **later** invocation
silently discards what an earlier one produced:

- `x.py build library --target A,B` followed by `x.py build clippy` — the clippy
  run wipes the sysroot and puts **no** std back, leaving *both* targets without
  core+std. `make all` then dies with `error[E0463]: can't find crate for
  core`/`std` … "target may not be installed" on whatever dependency it compiles
  first. This looks like a Motor OS or toolchain-registration failure; it is
  neither, and re-registering the toolchain cannot help.
- `x.py build library --target A` followed by the same for `B` — `B` evicts
  `A`'s std.

Naming `clippy` and `library` together (exactly what [build.md](build.md)'s
`x.py build --stage 2 clippy library …` does) makes the whole set survive the one
wipe, so no ordering can be wrong and nothing needs copying back afterwards.

clippy must be **rebuilt** here rather than reused: [build.md](build.md) built it
from this tree *before* Stage R1 switched the checkout to the fork, so
`stage2-tools-bin` holds binaries from a different compiler (see Pitfalls).
Naming it above rebuilds it from the fork — incremental, and a no-op once
current.

Then confirm the sysroot the dev toolchain points at is actually complete —
one second here versus an hour into `make all`:

```sh
S=build/x86_64-unknown-linux-gnu/stage2
echo 'pub fn f() -> u32 { 1 }' > /tmp/probe.rs
for t in x86_64-unknown-motor x86_64-unknown-linux-gnu; do
  $S/bin/rustc --crate-type rlib --target $t -o /tmp/probe-$t.rlib /tmp/probe.rs \
      || echo "BROKEN: $t"
done
$S/bin/clippy-driver --version      # must match the rustc just built
```

## Stage R5 — `cc`, the on-image linker driver (from build-llvm.md)

rustc on the image needs a `cc` to drive the link, and it looks for exactly that
bare name on `PATH`. That `cc` is **not built here** — it is the `#!/bin/rush`
script [build-llvm.md](build-llvm.md) stages at `/bin/cc`, because it belongs
with the C toolchain it fronts (`/sys/tools/llvm/bin/llvm`'s clang plus the
sysroot libs). It cannot be a symlink to `llvm`: motor-fs has no symlinks, and a
spawned child always sees the resolved exe path as its argv[0], so the
multicall's only entry is the subcommand form `llvm clang …`. The script is a
pure pass-through: the clang Motor ToolChain owns the `crt1.o` + mlibc/libc++
recipe (including `libc++abi`, which mlibc — being C++ internally — needs even
from pure-C code) and honors the `-nostartfiles -nodefaultlibs` rustc passes,
so pure-Rust links stay mlibc-free while `cc hello.c` gets the full C runtime.
So the one script is both rustc's linker and a working C compiler. Nothing to
do in this stage beyond confirming build-llvm.md ran:
`test -f $MOTOR/img_files/generated/llvm/bin/cc`.

Before staging, `build-rustc.sh` rebuilds `libmoto_rt_cabi.a` in a fresh Cargo
target directory with the final stage-2 toolchain. It verifies that
`motor_start`, `memcpy`, `memmove`, `memset`, and `memcmp` are not strong
definitions in either the target libraries or the rebuilt shim, then refreshes
the cross sysroot and `img_files/generated/llvm`. This is what permits the
final DNS resolver link to reject duplicate symbols instead of masking them.

## Stage R6 — stage everything into the image

```sh
IMG=$MOTOR/img_files/generated/rustc
RUSTLIB=$RUST/build/x86_64-unknown-linux-gnu/stage2/lib/rustlib/x86_64-unknown-motor/lib
rm -rf $IMG
mkdir -p $IMG/sys/tools/rust/bin $IMG/sys/tools/rust/src \
         $IMG/sys/tools/rust/lib/rustlib/x86_64-unknown-motor/lib

# The compiler, stripped (~154 MB -> ~98 MB).
$B/llvm-strip -o $IMG/sys/tools/rust/bin/rustc \
    $RUST/build/x86_64-unknown-linux-gnu/stage2-rustc/x86_64-unknown-motor/release/rustc-main

# The Rust sysroot: rlibs AND their .rmeta siblings AND self-contained/.
# Bootstrap builds std with -Zembed-metadata=no: each rlib carries only a
# metadata *stub*, the full metadata lives in the .rmeta file next to it.
# Staging only *.rlib yields "only metadata stub found for rlib dependency
# `std`" at compile time.
rm -rf $IMG/sys/tools/rust/lib/rustlib/x86_64-unknown-motor/lib
mkdir -p $IMG/sys/tools/rust/lib/rustlib/x86_64-unknown-motor/lib
cp -r $RUSTLIB/* $IMG/sys/tools/rust/lib/rustlib/x86_64-unknown-motor/lib/

# (/bin/cc — the linker driver rustc uses — is staged in the separate
# img_files/generated/llvm tree by build-llvm.md, not here.)

# A sample source (the script writes one exercising HashMap + threads).
cp .../hello.rs $IMG/sys/tools/rust/src/hello.rs
```

rustc finds its sysroot relative to `current_exe()` (`bin/..` →
`/sys/tools/rust`), so no `--sysroot` flag is needed on the image.

## Stage R7 — rebuild the OS and the image

**After any rustc relink, the Motor OS tree's cargo caches are poison** (see
Pitfalls); clear them, then rebuild everything. `src/sys/target` is the workspace
target dir [build-llvm.md](build-llvm.md)'s shim stage builds into with the same
dev toolchain, so it is poisoned too:

```sh
rm -rf $MOTOR/build/obj/release $MOTOR/src/sys/target
cd $MOTOR && make all BUILD=release MOTOR_DNS_STRICT_LINK=1 -j$(nproc)
```

Confirm the output ends with `built Motor OS image in .../vm_images/release` —
a failure in any component (e.g. the vdso step missing clippy) leaves the old
image in place while looking superficially fine.

## Verify in the VM

Boot the image ([build.md](build.md), `run-qemu.sh`) and, at the Motor OS
prompt:

```sh
mkdir /sys/tmp                      # scratch for outputs, if not present
/sys/tools/rust/bin/rustc --version
/sys/tools/rust/bin/rustc /sys/tools/rust/src/hello.rs -o /sys/tmp/hello
/sys/tmp/hello
```

No `-C linker=` flag: rustc's default linker is the bare name `cc`, which it
finds at `/bin/cc` via `PATH`.

Expected: `rustc 1.98.0-dev`, a silent successful compile (~1 min in a 1 GB
VM), then the program prints its HashMap-ordered sentence and `10! = 3628800`
from a spawned thread — Rust compiled, linked (via the native clang/lld), and
executed entirely on Motor OS.

## Pitfalls (each cost real debugging time)

- **An empty submodule directory is not an initialized submodule.** In
  particular, `git -C src/llvm-project rev-parse --git-dir` is an unsafe test:
  Git walks up from an empty `src/llvm-project`, finds the Rust superproject's
  `.git`, and succeeds. A script that trusts that result skips initialization
  and then runs its LLVM fetch against a directory with no checkout (or against
  the Rust repository). Stage R1 instead requires `src/llvm-project/.git` and
  verifies that `src/llvm-project` itself is the reported worktree root. The
  `warning: unable to rmdir 'library/backtrace': Directory not empty` sometimes
  printed while switching Rust branches is separate and harmless: it is Git
  retaining that separately initialized submodule directory while it updates
  the superproject.
- **A rustc relink silently poisons every cargo cache that used the old
  binary.** Two builds of the same tree produce byte-different compilers with
  *identical* `rustc -vV` output, which is all cargo fingerprints. Cargo then
  reuses stale rlibs and rustc rejects them — `error[E0463]: can't find crate
  for <random dep>` in workspaces that were building fine minutes earlier.
  Fix: `rm -rf $MOTOR/build/obj/release` (and any other target dir built with
  the dev toolchain) after every relink.
- **Every `x.py` invocation wipes the whole stage2 sysroot — so the *last* one
  decides what the dev toolchain has.** Bootstrap's `Sysroot` step begins with an
  unconditional `remove_dir_all(build/x86_64-unknown-linux-gnu/stage2)` ("Removing
  sysroot … to avoid caching bugs"), then re-links only what *that* invocation
  builds. This is the single sharpest edge in this build, because
  `build/x86_64-unknown-linux-gnu/stage2` **is** the `dev-x86_64-unknown-motor`
  toolchain that `make all` runs on. Consequences:
  - `x.py build --stage 2 clippy` run *after* the library build leaves
    `stage2/lib/rustlib` with no std for *either* target, and `make all` then dies
    with `error[E0463]: can't find crate for core` (motor) and `for std`/`core`
    (linux-gnu) on whatever dependency it happens to compile first — `futures-io`,
    `futures-sink`, … It reads as a Motor OS or a toolchain-registration breakage;
    it is neither, and re-registering the toolchain cannot help. Only a `library`
    build puts std back.
  - `x.py build library --target X` alone evicts the *other* target's std.
  - A `library` build on its own drops `cargo-clippy`/`clippy-driver` from
    `stage2/bin` (the Motor OS `make` runs clippy in its vdso step and fails
    *before the imager runs*).

  The fix for all three is the same and is the only robust one: name everything
  in **one** invocation — `x.py build --stage 2 clippy library --target <both>` —
  so it all survives the single wipe. Then verify the sysroot before trusting it
  (compile a probe rlib for each target). Since qemu writes to a mounted image's
  file, the image mtime keeps changing, looking freshly built while being stale —
  trust only the `built Motor OS image` line, never the image mtime.
- **Restoring clippy means rebuilding it, not copying whatever is in
  `stage2-tools-bin`.** On a machine that has run [build.md](build.md), that
  directory already holds a `cargo-clippy`/`clippy-driver` pair built from the
  *upstream* tree, before Stage R1 switched the checkout to the fork. Copying
  that stale pair into the freshly built `stage2/bin` puts a `clippy-driver` there
  that cannot load this compiler's hash-suffixed `librustc_driver-*.so` (or cannot
  resolve against it), so `make all` dies in the vdso step — which reads as a
  *Motor OS* build failure even though the toolchain is registered correctly, and
  re-registering it changes nothing. `./x.py build --stage 2 clippy` before the
  copy is incremental and rules this out.
- **Stage the `.rmeta` files, not just `*.rlib`** (see stage R6).
- **The `operator delete` trap cannot be fixed by link order.** mlibc's stubs
  are strong `T` symbols; libc++abi's real operators are weak `W`. If the
  staged rustc ever aborts with `operator delete called! delete expressions
  cannot be used in mlibc`, the sysroot `libc.a` predates the stub guard —
  rebuild mlibc (stage R2). `grep -a 'operator delete called' rustc` must find
  nothing in a good binary.
- **mlibc aborts print to the serial console, not the ssh session** — a
  crashing program can look like a silent exit over ssh. Check the serial log.
- **Re-running `x.py` after deleting `rustc-main` does nothing** — bootstrap
  trusts its stamp file. Delete
  `stage2-rustc/x86_64-unknown-motor/release/.rustc-stamp` alongside the
  binary to force a relink.

## Where the port lives (for maintainers)

- **`moturus/rust` @ `motor-os-rustc`** (on top of upstream `8b6558a02b27`):
  - `library/std/src/sys/pal/motor/mod.rs` — `motor_start` made weak (mlibc
    entry wins when present).
  - `library/std/src/sys/paths/{mod,motor}.rs` — real `:`-separated
    `split_paths`/`join_paths` (rustc unwraps `join_paths` when building the
    linker's `PATH`).
  - `library/std/src/sys/process/motor.rs` — `getpid()` reads the pid from the
    kernel's `ProcessStaticPage` (was a panic stub; rustc calls
    `process::id()` while linking); `read_output` drains both child pipes
    concurrently via a scoped thread (was `NotImplemented`; rustc uses
    `wait_with_output` on the linker); a `self.stdout`/`self.stderr` spawn
    typo fixed.
  - `library/Cargo.toml` — unchanged; `moto-rt` comes from crates.io (≥ 0.16.1
    has the weak `mem*`, so no patch is needed).
  - `Cargo.toml` — `[patch.crates-io]` git URLs for the four dependency forks.
  - `compiler/rustc_driver/Cargo.toml` — `crate-type = ["dylib", "rlib"]`.
  - `compiler/rustc_metadata/Cargo.toml` — libloading 0.8 → 0.9 (single
    version across the compiler; one call site adjusted for 0.9's
    `AsFilename`).
  - `compiler/rustc_{interface,incremental,abi}/Cargo.toml` — rand 0.9 → 0.10
    (+ rand_xoshiro 0.7 → 0.8), which moves the compiler's randomness onto
    getrandom 0.4.3 — the first upstream release with Motor OS support. The
    only remaining getrandom-0.3 user on the motor target is the host-only
    `test-float-parse` tool, which x.py never builds for motor.
  - `compiler/rustc_data_structures/Cargo.toml` — memmap2 excluded for the
    motor target (with `memmap.rs`'s `Vec<u8>` fallback selected there).
  - `compiler/rustc_sanitizers/Cargo.toml` — `twox-hash` with
    `default-features = false`. Its default `std` feature pulls `rand` 0.8 →
    `rand_core` 0.6 → **getrandom 0.2** (which has no Motor support and no
    fork), and feature unification would drag that onto the motor build even
    though `rustc_sanitizers` only uses the fixed-seed `XxHash64`. This was
    the one non-obvious getrandom-0.2 path; with it cut, the sole remaining
    getrandom-0.2/0.3 users on the motor target are host-only test tools
    (`test-float-parse`) that x.py never cross-compiles.
  - `compiler/rustc_llvm/{build.rs,src/lib.rs}` — no C++ stdlib `-l` emitted
    for motor (the linker driver owns the group); local `size_t` alias.
  - `compiler/rustc_llvm/llvm-wrapper/PassWrapper.cpp` — a four-line LLVM-23
    adaptation: this LLVM-23 snapshot privatized `SubtargetFeatureKV`/
    `SubtargetSubTypeKV`'s `Key`/`Desc` and made them non-copyable, so the
    CPU/feature listing uses the `key()`/`desc()` accessors and a reference
    (guarded by `LLVM_VERSION_GE(23, 0)`). Everything else in rust's LLVM FFI
    already compiled against LLVM 23 unchanged.
  - `compiler/rustc_session/src/filesearch.rs` — `current_dll_path()` via
    `current_exe()` (static-only; sysroot discovery).
  - `compiler/rustc_fs_util/src/lib.rs` — `path_to_c_string` for motor.
  - `compiler/rustc_data_structures/src/memmap.rs` — `Vec<u8>` fallback (no
    file mmap on Motor).
  - `src/bootstrap/src/core/build_steps/llvm.rs` — the motor LLVM cmake block
    and `CMAKE_SYSTEM_NAME=Linux` mapping.
- **`moturus/llvm-project` @ `motor-os-rustc`** (**LLVM 23** — the single LLVM
  used by both build-llvm.md's cross toolchain and rustc's own LLVM; `motor-os-next`
  is a legacy alias for the same commit): the `Motor` `Triple::OSType` (+ default
  emulated TLS), the Clang `Motor` ToolChain, `config-ix.cmake` header probing
  keyed on `CMAKE_*_COMPILER_TARGET matches motor`, `ADT/bit.h` endian include,
  `Unix/Path.inc` (argv0 main-executable lookup, `is_local` = true),
  `ExitCodes.h` (`EX_IOERR` without `sysexits.h`).
- **Dependency forks** (each `motor-os-rustc`, branched from the exact version
  rustc locks; **referenced as `[patch.crates-io]` git URLs — cargo fetches
  them, nothing is cloned**; host targets compile byte-identical upstream code,
  only `target_os = "motor"` paths differ):
  - `moturus/rust_libloading` (0.9.0) — motor gated to graceful runtime
    failure (no `dlopen`; proc macros unsupported).
  - `moturus/stacker` (0.1.21) — motor uses the alloc-based stack-restore
    guard (no file/anon mmap).
  - `moturus/libc` (0.2.186) — the Motor module (`src/motor/`) transplanted
    from the libc main-branch port; `extern_ty!` occurrences replaced with
    empty enums.
  - `moturus/rust-ctrlc` (3.5.1) — motor platform stub (no signals; the
    waiter parks).
- **`moturus/mlibc` @ `motor-os-rustc`** (on top of `motor`) — the lazy
  foreign-thread TCB (`sysdeps/motor/generic/thread.cpp`, hook in
  `options/internal/x86_64-include/mlibc/thread.hpp`) and the
  `#ifndef __motor__` guard around the `operator delete` stubs
  (`options/internal/gcc-extra/cxxabi.cpp`).
- **motor-os** — RT.VDSO: `ChildStdio::read` maps the bad-remote-handle IPC
  error to EOF (child exit is *signalled* by that error; without the mapping,
  reading a finished linker's output fails with `BadHandle`); `rt_fs.rs`
  implements `O_APPEND` (open positioned at size — rustc's ICE reporter uses
  append). Imager: `data_partition_size_mb: 512`.
- The Rust *libc crate* port on the libc main (1.0) branch is the
  upstream-facing artifact of this work; rustc consumes the 0.2-series port
  (`moturus/libc` @ `motor-os-rustc`, via the `[patch.crates-io]` git URL) and
  does not build the 1.0 tree.
