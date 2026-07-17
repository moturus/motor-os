# The mlibc link seam: why `hello.rs` is 7.63 MB, and how to fix it

Status: **implemented and VM-verified (2026-07-17).** Recommendations 1-3
below are in: mlibc rebuilt with `-Ddebug=false` (`.text` byte-identical,
`libc.a` 18,287,414 → 3,838,854), `/bin/cc` is a pass-through, `/bin/c++`
added, the flag pair documented in build-rustc.md; B′ deferred as planned.
Measured on the rebuilt image, all four programs run:

| on-image test | before | after |
|---|---|---|
| `rustc hello.rs` (pure Rust) | 8,006,160 | **112,720** |
| `rustc -C link-self-contained=no -C default-linker-libraries=yes` | 8,006,160 | 1,345,888 (mlibc entry) |
| `cc hello.c` | ~8 MB | 1,394,272 |
| `c++ hello.cpp` (new) | — | 2,170,144 |

The review history below is kept as the design record. Numbers from the
original investigation that were re-measured during review reproduced
**exactly** (8,006,160 / 124,400 / 1,085,568 / 18,287,414 → 3,856,718).

The trigger: on the image,

```
rush:/sys/tools/rust$ bin/rustc -O src/hello.rs -o hello
rush:/sys/tools/rust$ ls -lh
f 7.63M   hello
```

`src/hello.rs` is the sample from [build-rustc.md](build-rustc.md) — HashMap,
sort, `println!`, one spawned thread. Pure Rust, no C.

## Review verdict

A second pass over the original investigation, with everything re-derived from
the artifacts (sysroot `crt1.o`/`libc.a`, `/bin/cc`, clang's `Motor.cpp`, the
rust target specs, `--print link-args`).

**Confirmed as-is:**

- Finding 1 (DWARF is mlibc's, `-Ddebug=false` is the right fix) — every number
  reproduces; `llvm-strip --strip-debug libc.a` gives byte-identical results.
- Finding 2 (`crt1.o`, not the archives, drags mlibc in) — `nm crt1.o` shows
  exactly the described shape: strong `T motor_start`, `U __mlibc_entry`.
- Finding 3 (the `libc` crate is inert on Motor) — the 4,852-byte rlib is real.
- The rejection of Options C/D/E, including the archive-extraction trap and the
  "correction to the record" (crt1.c is genuine Motor→SysV translation, not a
  duplicated std startup). The micro-experiments stand.

**Disagreements / amendments** (each argued in its section below):

1. **Option A is under-ambitious and keeps the wrong half.** Clang's Motor
   ToolChain (`Motor.cpp`) *already* implements the entire link recipe with
   correct flag gating — `crt1.o` behind `-nostartfiles`, the group behind
   `-nodefaultlibs`, both behind `-nostdlib`/`-r`. `/bin/cc` should become a
   **pure pass-through** (Option A′), not grow a conditional. And the original
   recommendation to keep the `-l` group when dropping `crt1.o` converts the
   Rust+C failure mode from a *loud link error* into a *silently uninitialized
   libc* — the worst of the options. Drop both; let the flags mean what they say.
2. **The doc missed that the opt-in already exists in stock rustc.**
   `-C link-self-contained=no -C default-linker-libraries=yes` deletes exactly
   the two flags that suppress the ToolChain's recipe. Measured: with a
   pass-through driver, those two flags flip `hello.rs` between 112,680 bytes
   (std entry) and 8,006,144 bytes (`T motor_start`, mlibc entry — byte-parity
   with today's forced link). This is the escape hatch for Rust+C, it needs zero
   new code, and it changes the sequencing: A′ can ship alone.
3. **Option B in `moturus/libc` is a landmine; the validated shape was a
   standalone crate — keep it that way (Option B′).** In-tree counterexample:
   `rush` depends on `libc = "0.2"` **unconditionally** (`src/bin/rush/
   Cargo.toml:20`) for its Linux dev backend (`sys/unix.rs` termios); on motor
   the crate is compiled but inert. Put the `#[link]` block in the `libc` crate
   and rush — and any future program with an incidental `libc` dep — links all
   of mlibc, hands its entry point to `crt1.o`, and `make all` breaks on the
   host (no `-lmotorcrt1` on plain `cc`'s search path). The original's own
   validation used `extern crate motorlibc` — a *separate* crate. That is the
   right design; embedding it in `moturus/libc` is the unvalidated extrapolation.
   With the flag opt-in available now, B′ can be deferred until a real
   cargo-level need appears.
4. Minor factual fixes: `crt1.o` references four `moto_rt_*` symbols
   (`start`/`get_args`/`get_env`/`fill_random_bytes`) — `log`/`proc_exit`/
   `tcb_set` are referenced by `libc.a`'s sysdeps, not `crt1.o`; `img_files` is
   ~325 MB (re-measured); the `/bin/cc` script's rationale comment ("the Motor
   ToolChain omits libc++abi for C links") describes the ToolChain as it was
   *before* the committed `Motor.cpp` fix and is now stale.

## Summary

Two independent causes, two independent fixes.

1. **~83% of the binary is DWARF, essentially all of it from mlibc's
   `libc.a`**, built `-O2 -g` because mlibc's `meson.build` pins
   `buildtype=debugoptimized` and neither build-llvm.md:299 nor
   build-llvm.sh:238 overrides it. Every CMake component in that build is
   explicitly `Release`; mlibc is the lone outlier. Fix: `-Ddebug=false`.
   Also reclaims ~14 MB of image space.
2. **mlibc is linked into pure-Rust programs at all**, because `/bin/cc`
   unconditionally appends `crt1.o` + the mlibc runtime group to *every* link.
   std does not pull in libc — rustc's link line is pure Rust. The `-l`
   archives are free (lazy extraction); **`crt1.o` alone costs 7.9 MB**: it is
   an object file (always linked whole), its strong `motor_start` overrides
   std's weak one, and its `U __mlibc_entry` cascades into `libc.a` →
   `libc++abi` → `libunwind`. Fix: make `/bin/cc` a pass-through and let
   clang's Motor ToolChain — which already gates the recipe on the standard
   flags — do the work.

With both fixed, a pure-Rust `hello.rs` on Motor is **~113 KB**.

Headline numbers (all measured, x86_64; ✓ = re-verified during review):

| binary | as built | stripped | `.text` |
|---|---|---|---|
| host, default (**dynamic**) | 4,462,680 | 386,464 | 279,219 |
| host, `-C target-feature=+crt-static` | 5,512,152 | 1,347,128 | 1,004,067 |
| **motor, today** | **8,006,160** ✓ | 1,085,568 ✓ | 871,561 |
| motor, no `crt1.o` (group still present) | 120,744 | — | — |
| motor, no mlibc group at all | 124,400 ✓ | — | — |
| motor, pass-through clang driver | **112,680** ✓ | — | — |
| motor, flag opt-in (mlibc entry, on purpose) | 8,006,144 ✓ | — | — |

Note rows three and four: the original "7.63M vs 4.3M" comparison was
dynamic-vs-static. Compared like-for-like, **Motor's static binary is smaller
than the host's static binary** (1,085,568 vs 1,347,128 stripped; 871,561 vs
1,004,067 of code). There is nothing wrong with the port's codegen.

## Reproducing on the host (no VM)

The on-image result reproduces exactly by cross-linking on the host:

```sh
export MOTORH=$HOME/motorh SYSROOT=$MOTORH/motor-sysroot

# what the image does (motor-rust-cc == /bin/cc's forced group):
rustc +dev-x86_64-unknown-motor -O --target x86_64-unknown-motor \
    -C linker=$SYSROOT/bin/motor-rust-cc hello.rs -o hello-motor      # 8,006,160

# what `make all` does for the OS's own Rust programs (plain host cc):
rustc +dev-x86_64-unknown-motor -O --target x86_64-unknown-motor \
    hello.rs -o hello-pure                                            # 124,400

# Option A′ analogue: clang's Motor ToolChain as the driver, nothing forced:
rustc +dev-x86_64-unknown-motor -O --target x86_64-unknown-motor \
    -C linker=$SYSROOT/bin/motor-clang hello.rs -o hello-passthru     # 112,680

# the stock-rustc opt-in: same driver, ToolChain recipe re-enabled:
rustc +dev-x86_64-unknown-motor -O --target x86_64-unknown-motor \
    -C linker=$SYSROOT/bin/motor-clang \
    -C link-self-contained=no -C default-linker-libraries=yes \
    hello.rs -o hello-optin                       # 8,006,144, T motor_start
```

Note: the mlibc *source* tree had been intentionally deleted from this host
(build-rustc.md: "the mlibc source tree is no longer needed and can be
deleted"); implementing Finding 1 re-cloned `moturus/mlibc` @ `motor-os-rustc`
to `$MOTORH/mlibc`. The clone's `.text` proved byte-identical to the old
sysroot's (871,561 bytes for hello) — the fork carries exactly the source the
sysroot was built from.

## Finding 1 — the DWARF comes from mlibc, not from Rust

| binary | `.debug_*` | share | CUs |
|---|---|---|---|
| motor | 6,656,940 | 83.1% | 54, **all mlibc** (`comp_dir=$MOTORH/mlibc/build`) |
| host | 3,952,245 | 88.6% | 13, all Rust (`/rustc/<hash>`, memchr, hashbrown) |

Both binaries are mostly debug info, but from opposite sources. On Motor, Rust
contributes almost none: `libstd.rlib` for motor is 1,372,440 bytes of objects
with **0 bytes of `.debug_*`** (bootstrap builds std without debuginfo).

The sysroot `libc.a` is 18,287,414 bytes, of which **10,437,633 (59.3%) is
DWARF** across its 402 members. That flows into every binary linked on the
image — including plain C: a freshly linked `hello.c` is 8,060,560 bytes.

Root cause — mlibc's own `meson.build`:

```
project('mlibc',
    default_options: ['cpp_std=c++23', 'c_std=gnu11', 'buildtype=debugoptimized', ...])
```

`debugoptimized` = `-O2 -g`. Neither [build-llvm.md](build-llvm.md):299 (the
real static build; :293 is headers-only) nor `src/build-llvm.sh`:238 passes a
buildtype, so the project default wins. The cross-file sets `c_args`/`cpp_args`
but no buildtype either. Every CMake component in that guide is explicitly
`-DCMAKE_BUILD_TYPE=Release`, which is why `libc++.a`, `libc++abi.a` and
`libunwind.a` carry no DWARF at all.

**This is a size issue only, not a codegen issue.** Disassembly of the shipped
`libc.a` shows properly optimized code. An early hypothesis that meson's `-O0`
default applied was checked and is wrong.

Verified fix — strip debug from the sysroot archives and relink, no rustc flags
and no source change (re-verified: identical numbers):

```
libc.a                18,287,414 -> 3,856,718
hello                  8,006,160 -> 1,345,768
.text                    871,561 -> 871,561      (byte-identical)
symbols                                kept       (backtraces still work)
```

The minimal change is `-Ddebug=false` on mlibc's `meson setup` — that keeps
`-O2` exactly as today and only drops `-g`. `--buildtype=release` would also
work but silently moves to `-O3`, changing codegen. `llvm-strip --strip-debug
libc.a` achieves the same on an already-built sysroot but does **not** survive
an mlibc rebuild, so the meson flag is the durable half. It belongs in
build-llvm.md:299 *and* build-llvm.sh:238 — and note both now require
re-cloning mlibc, since the source tree was deleted per build-rustc.md.

The image stages the 18 MB `libc.a` at `/sys/tools/llvm/lib` (that directory is
31 MB of a ~325 MB `img_files` tree), so this also reclaims ~14 MB of image
space and shrinks every future native link on the VM. The already-staged
toolchain binaries (`llvm`, `rustc`, `lua`, `libc-smoke`) each carry ~6.6 MB of
mlibc DWARF and would shrink on their next relink; no urgency.

## Finding 2 — `crt1.o`, not `libc.a`, drags mlibc in

**std links no libc.** rustc's actual link line for `hello.rs` contains only
Rust rlibs — `panic_abort`, `std`, `moto_rt`, `hashbrown`, `alloc`, `core`,
`compiler_builtins`, … — plus `-e motor_start -u __rust_abort`, `-nostartfiles`,
`-nodefaultlibs`, `-static-pie`, `--gc-sections`. No `crt1.o`, no `libc.a`.
rustc explicitly says *"I own the runtime."* (`liblibc-*.rlib` in that list is
the Rust `libc` **crate** — see Finding 3 — not mlibc.)

Then `/bin/cc` adds the group anyway, on every link:

```sh
/sys/tools/llvm/bin/llvm clang "$@" \
    -nostartfiles -nodefaultlibs \
    -Wl,--start-group \
    /sys/tools/llvm/lib/crt1.o \
    -lmoto_rt_cabi -lc++ -lc++abi -lunwind -lc -lclang_rt.builtins-x86_64 \
    -Wl,--end-group
```

(`$SYSROOT/bin/motor-rust-cc`, the host wrapper x.py links rustc with, is the
same group. It is used only to build rustc itself — a genuine C++/LLVM binary —
and must keep `crt1.o`.)

The mechanism, and it is entirely `crt1.o` (re-verified with `nm`):

| symbol | `crt1.o` | `libstd.rlib` |
|---|---|---|
| `motor_start` | `T` (**strong**) | `W` (weak) |

`crt1.o` is an explicit **object file**: unlike the `-l` archives it is never
lazily extracted, it is always linked whole. So (a) its strong `motor_start`
overrides std's weak one regardless of link order — mlibc seizes the entry point
in a pure-Rust program — and (b) its `U __mlibc_entry` pulls mlibc's C runtime →
`libc.a` → (mlibc is C++ internally) `libc++abi`, `libunwind`.

Proof that the archives are blameless — drop *only* `crt1.o`, keep every `-l`:

| link | bytes |
|---|---|
| `crt1.o` + full group (today) | 8,006,160 |
| full group, **no `crt1.o`** | **120,744** |
| no group at all | 124,400 |

The linker takes nothing from `-lc`/`-lc++`/`-lunwind` because a pure-Rust
program has no undefined C symbols. **`crt1.o` costs the entire 7.9 MB** — 66×
the size of the program.

This is not an exotic configuration. All of the OS's own Rust programs already
link this way, with zero mlibc and std's weak `motor_start` (`rush` 538,176,
`httpd` 1,390,176, `kernel` 407,616, `red` 218,480, …), and `/bin/libc-smoke` —
a genuine C program — correctly has strong `T motor_start` and 426 mlibc
symbols. The no-mlibc `hello-pure`/`hello-passthru` binaries were verified to be
complete static-pies with std's weak `motor_start` as entry and zero
mlibc/`__cxxabi`/`_Unwind` symbols. **They have not been booted** — but their
link shape is identical to `rush`, which runs in production.

### Why `/bin/cc` was written this way — and why that reason is gone

The script's own comment says the group is forced because clang's Motor
ToolChain "omits libc++abi for C links". That was true when the script was
written; it is not true now. The committed `Motor.cpp`
(`llvm-project` 88ea5aa2a7b4) adds `-lc++abi` unconditionally, precisely so
`clang hello.c` links. The forced group is legacy belt-and-suspenders — and
build-llvm.sh even says so five lines below the heredoc: "the full link/include
recipe lives in the Motor ToolChain now".

## Finding 3 — the `libc` crate is inert on Motor, but not rare

- `sys/pal/motor`, `sys/process/motor`, `sys/fs/motor`, `sys/net/motor`,
  `sys/thread/motor`: **zero** uses of `libc::` (re-verified).
- The motor `liblibc-*.rlib` is **4,852 bytes** — pure declarations, and it
  declares no native library to link.

It is always in std's dependency graph via blanket
`cfg(not(all(windows, target_env = "msvc")))` deps in `library/std/Cargo.toml`
and `library/unwind/Cargo.toml`, and — the part the original missed — it also
shows up in *application* graphs for reasons that have nothing to do with
Motor: **`rush` depends on `libc = "0.2"` unconditionally** for its Linux dev
backend (`src/bin/rush/src/sys/unix.rs`, termios). Motor's target spec sets no
`target_family`, so `cfg(unix)` deps (tokio's, mio's) stay off — but any
*unconditional* `libc` dep anywhere in a graph is compiled-and-inert on motor.

Consequence: "the `libc` crate is in the dependency tree" is **not** a usable
signal for "this program wants mlibc", and no amount of gating std's copy
(the original Option B plan) makes it one. This kills Option B in its original
placement — see B′ below.

## Finding 4 (new) — the opt-in already exists in stock rustc

Where rustc's two suppression flags come from:

- `-nostartfiles` ⇐ `link_self_contained = LinkSelfContainedDefault::True` in
  `x86_64_unknown_motor.rs:18`;
- `-nodefaultlibs` ⇐ rustc's default `-C default-linker-libraries=no`.

Both have stock per-invocation overrides, verified with `--print link-args`:
default link line contains each flag exactly once; with
`-C link-self-contained=no -C default-linker-libraries=yes` both are **gone**,
and clang's Motor ToolChain supplies `crt1.o` + the full group itself.
Measured end-to-end (pass-through driver, rebuilt host clang):

| rustc flags | driver adds | entry | bytes |
|---|---|---|---|
| (default) | nothing | `W motor_start` (std) | 112,680 |
| `-C link-self-contained=no -C default-linker-libraries=yes` | `crt1.o` + group | `T motor_start` (mlibc) | 8,006,144 |

8,006,144 is byte-parity (±16, build-id) with today's forced link — same
member set, same entry, same init. So a **Rust + C program on the image is one
flag pair away** from a fully initialized mlibc, with no new crates, no fork
changes, and no driver heuristics. For cargo projects it is
`rustflags = [...]` under `[target.x86_64-unknown-motor]`. One gap: rustc
drives `cc` in C mode, so the ToolChain adds `libc++abi` but not `libc++`; a
Rust program linking real C++ additionally needs `-C link-arg=-lc++`.

## The options, revised

### Option A′ — `/bin/cc` becomes a pass-through (supersedes Option A)

Replace the script's link branch with nothing:

```sh
#!/bin/rush
# cc — Motor OS's system C compiler / linker driver. See docs/build-llvm.md.
/sys/tools/llvm/bin/llvm clang "$@"
```

The Motor ToolChain already does the right thing for every caller:

- `cc hello.c` → ToolChain adds `crt1.o` + group (`Motor.cpp:59-97`, gated on
  `-nostdlib`/`-nostartfiles`/`-nodefaultlibs`/`-r`). Verified on the host with
  the rebuilt clang: links, 8,060,560 bytes (1.3 MB after Finding 1).
- `rustc hello.rs` → rustc's `-nostartfiles -nodefaultlibs` suppress the
  recipe; pure Rust drops to **112,680** bytes. Verified.
- `rustc` + the Finding 4 flag pair → ToolChain recipe returns; mlibc owns
  entry, fully initialized. Verified.
- Compile-only (`-c`/`-S`/`-E`/`--version`) needs no special-casing anymore —
  the whole `compile_only` scanner in the script exists only because the script
  appends link inputs; a pass-through has nothing to guard.

Differences from the original Option A, deliberately:

- **Drop the `-l` group too, not just `crt1.o`.** The original kept the
  archives, so a Rust+C link would *succeed* and then run with uninitialized
  mlibc — silent misbehaviour. With the group also gone, that link **fails
  loudly** with undefined C symbols, and the remedy (the flag pair) is
  documentable in the error's vicinity. Silent-wrong is the only unacceptable
  state; A′ has none.
- **No conditional logic in the script.** The flags are interpreted by clang,
  where they already have exact, upstream-tested semantics, instead of being
  re-parsed by a rush script.

One real regression, accepted on purpose: today `cc foo.cpp` happens to link
(the forced group always carried `-lc++`). Under A′ it compiles as C++ but
fails at link with undefined `std::` symbols — which is exactly what `cc`
does on Linux. The conventional fix is a `/bin/c++` companion
(`/sys/tools/llvm/bin/llvm clang --driver-mode=g++ "$@"` — use the driver-mode
flag, `clang++` may not be a multicall subcommand name), staged by the same
build-llvm.sh block that writes `/bin/cc` (line 427).

Blast radius: nothing outside the image changes. `make all` links with the
host `cc`; rustc's own build links with `motor-rust-cc` (which keeps its
forced group — rustc genuinely is a C++ program). Only on-image links change.

### The flag pair — the Rust+C opt-in that ships with A′

Nothing to build (Finding 4). Document in build-rustc.md next to the `hello.rs`
example:

```
# Rust program that links C / uses mlibc:
rustc -C link-self-contained=no -C default-linker-libraries=yes foo.rs
```

This covers the only Rust+C consumer that exists on the image today
(single-file `rustc` invocations; there is no on-image cargo). It is also the
right escape hatch for host cross-links (`-C linker=$SYSROOT/bin/motor-clang`
plus the pair).

### Option B′ — a standalone opt-in crate (amends Option B; deferred)

The original validated this mechanism end-to-end and its numbers are trusted —
but note *what* it validated: a **standalone** crate (`extern crate
motorlibc`), not the `moturus/libc` fork it then recommended patching. Keep the
validated shape:

- A tiny `no_std` crate (say `moto-libc-start`) whose entire content is the
  `#[link]` block: `motorcrt1` with `+whole-archive,-bundle`, then
  `moto_rt_cabi`, `c++`, `c++abi`, `unwind`, `c`, `clang_rt.builtins-x86_64`,
  all `-bundle` (all four gotchas from the original validation apply: `+bundle`
  default copies 18 MB into the rlib; `#[link]` cannot name a bare `.o`, so
  build-llvm must emit `libmotorcrt1.a`; the *whole* group must be declared;
  lld needs no `--start-group`).
- Programs that want mlibc add one dependency. Cargo does the discrimination —
  per the *program author's* declaration, not per the accident of `libc`
  appearing in a dependency graph.
- Staged into the on-image rustc sysroot by build-rustc (next to the already-
  staged `liblibc-*.rlib`), so single-file `extern crate moto_libc_start;`
  works without cargo.

Why not the original placement inside `moturus/libc`:

- **rush falsifies the signal today** (Finding 3): unconditional `libc` dep,
  zero mlibc use on motor. Under original-B, rush's host `make all` link breaks
  (no `-lmotorcrt1` on plain cc's paths), and "fixing" the paths would instead
  silently hand rush's entry point to mlibc and grow it 8 MB.
- Original-B *requires* gating `libc` out of std/unwind in the rust fork to
  make the signal true — fork churn that B′ makes unnecessary. Inert `libc`
  stays inert and stays in the sysroot, so `extern crate libc` (types and
  constants) keeps working on-image.
- B′'s failure mode is loud (forgot the dep → undefined C symbols at link);
  original-B's is action-at-a-distance in both directions.

Cost of B′ vs original-B: a `-sys` crate cannot *automatically* bring the
runtime with it — the top-level program must declare the dependency. In an
ecosystem of exactly one C-linking Rust program (none exist yet), that is the
right trade. **Defer B′ until a real cargo-level consumer appears**; the flag
pair covers everything on the image today. The design above is validated and
ready when needed.

### Options C, D, E — rejected, agreeing with the original

The original's analysis of these is correct and its micro-experiments were
sound; condensed for the record:

- **C (strong `motor_start` in moto-rt + weak `libc_start`)** does not select
  anything: a weak definition *satisfies* the reference, so the linker never
  extracts mlibc's strong one from `libc.a` — the same trap already paid for
  once with `operator delete` (mlibc's strong stubs vs libc++abi's weak ops).
  It buys zero bytes over A′/B′, touches three repos including crates.io
  moto-rt, and `libc_start` *returns*, breaking the entry-block lifetime
  invariant (below). Its only real prize is "std's `motor_start` stops being
  weak" — small, and A′ already removes the surprise because `crt1.o` enters
  the link only when asked for.
- **D (weak `__mlibc_entry` in moto-rt)** is the worst seam: `__mlibc_entry`'s
  first parameter is a synthesized SysV ELF entry stack, and `crt1.c`'s 67
  lines exist precisely to build it (argc/argv/envp + `AT_PAGESZ`/`AT_SECURE`/
  `AT_RANDOM` auxv, the self-referential `__dso_handle`, the block-lifetime
  invariant). A weak `__mlibc_entry` in moto-rt moves mlibc's private entry ABI
  into the pure-Rust crates.io crate every Motor program links.
- **E (`.init_array`)** is the only mechanism that is automatic *and* exact
  (the linker builds `.init_array` from only the objects actually linked), but
  it requires restructuring mlibc's init away from upstream, has delicate
  constructor-priority ordering, and its one advantage — catching programs that
  link C without declaring it — is a case A′ turns into a loud link error
  anyway.

Ranking of the seams, unchanged: `+whole-archive crt1.o` (B′) > `libc_start`
(C) > `__mlibc_entry` (D). `crt1.o` already *is* the translation layer, it is
2,416 bytes, it is correct, and it encodes subtleties each paid for once
(found-the-hard-way `__dso_handle` teardown, the entry-block lifetime, the
stack-protector `AT_RANDOM` bytes). The problem was never its existence — only
that `/bin/cc` forced it on everyone.

### A correction to the record (kept from the original — it matters)

It was once claimed that "crt1.o is a C reimplementation of std's
`motor_start`", making "kill the duplicated startup" an argument for C/D. The
source says otherwise: the overlap is three lines (`moto_rt_start()`, call
`main`, exit). The other ~50 lines are genuine Motor→SysV translation that std
has no analogue for and does not need. crt1 must pass real argc/argv to a C
`main`; Rust reads args from the VDSO — two different jobs, not two copies of
one job.

## Recommendation — implementation status (2026-07-17)

1. **mlibc `-Ddebug=false`** — DONE. Flag added to build-llvm.md and
   build-llvm.sh; mlibc re-cloned and rebuilt (`debug=false`,
   `optimization=2` confirmed in the meson summary); sysroot and image
   restaged (image `lib/` 31 MB → 18 MB). `.text` byte-identical for C,
   Rust+mlibc, and pure-Rust links.
2. **Option A′** — DONE. `/bin/cc` is a pass-through (build-llvm.sh heredoc +
   staged `img_files/motor-os/bin/cc`); `/bin/c++` added
   (`--driver-mode=g++`); stale rationale comments replaced in both scripts
   and both guides.
3. **The flag pair** — DONE. Documented in build-rustc.md (intro + the
   link-flow bullet + stage R5).
4. **B′ deferred** (standalone `moto-libc-start` crate, design above) until a
   cargo-level Rust+C consumer exists. Do **not** put `#[link]` into
   `moturus/libc`, and do not bother gating `libc` out of std/unwind — B′
   makes both unnecessary.
5. **`motor_start` stays weak** in std; C/D/E rejected (agreeing with the
   original).
6. **Boot-verified on the VM** (rebuilt image, qemu): `rustc hello.rs` →
   112,720 bytes, runs (first boot of a pure-Rust rustc-produced binary —
   HashMap/sort/println/thread all correct); `rustc` + flag pair → 1,345,888,
   runs (mlibc entry, initialized, Rust std + spawned thread work under it);
   `cc hello.c` → 1,394,272, runs; `c++ hello.cpp` → 2,170,144, runs. The
   on-image rustc linked all of these through the new pass-through `cc`.
   (`/bin/libc-smoke` is not in the current img_files; the `cc hello.c` run
   covers the C-runtime path.)

## Traps

- **A weak definition prevents archive extraction.** The linker pulls a member
  only to resolve an *undefined* symbol. Any "weak default in A, strong
  override in archive B" design silently no-ops unless extraction is forced.
  Hit twice in this port already (`operator delete`; Option C's experiments).
- **`kind = "static"` defaults to `+bundle`** and copies the archive into the
  rlib (an 18,296,908-byte rlib was produced this way). Use `-bundle`.
- **`#[link]` cannot name a bare `.o`** — wrap `crt1.o` in `libmotorcrt1.a`,
  force it with `+whole-archive`.
- **`crt1.o` is an object, not an archive member**: always linked whole,
  `--gc-sections` cannot save you. Whoever adds it decides the entry point.
- **mlibc's DWARF does not survive a strip if mlibc is rebuilt** — fix the
  meson flag, not just the artifact.
- **Motor's `crt1.c` entry block lives in `motor_start`'s frame** and mlibc
  keeps pointers into it for the process lifetime. Any redesign where the hook
  *returns* must move that block to static storage.
- **An unconditional `libc = "0.2"` dependency is invisible dead weight on
  motor** (rush has one, for its Linux dev backend). Harmless today; the reason
  original-B is a landmine. Prefer `[target.'cfg(unix)'.dependencies]` for
  host-only libc use.
- **`cc foo.cpp` linking today is an accident** of the forced `-lc++`. Under
  A′, C++ needs `/bin/c++` (`--driver-mode=g++` — `clang++` may not exist as a
  multicall subcommand).

## Incidental findings

- **The stale host cross clang is fixed.** `Motor.cpp`'s committed recipe
  (88ea5aa2a7b4, 2026-07-13) postdated the Jul 5 host build, so host
  `clang hello.c --target=x86_64-unknown-motor` failed with undefined
  `operator delete` — confirming the original report. Rebuilt during this
  review (`ninja -C $MOTORH/llvm-project/build clang`); the C link now works
  on the host. The on-image `llvm` (built Jul 13) already carried the fix.
- **std's `motor_start` passes `main(0, null, 0)`** while crt1.o passes real
  argc/argv. Harmless (Rust reads args from the VDSO), but only crt1.o's path
  can serve a C `main`.
- The `/bin/cc` script comment that described the pre-fix ToolChain is gone
  with the rewrite. `motor-rust-cc`'s comment was already accurate and is
  unchanged — the host wrapper keeps its forced group (rustc itself is a
  C++/LLVM program).
