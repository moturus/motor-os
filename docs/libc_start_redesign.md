# The mlibc link seam: why `hello.rs` is 7.63 MB, and how to fix it

Status: **investigation complete, nothing implemented.** Every number below is
measured, on the host, without booting a VM. This document is a handoff: it
carries the evidence, the options that were considered (including the ones that
do *not* work, and why), and a recommended sequence.

The trigger: on the image,

```
rush:/sys/tools/rust$ bin/rustc -O src/hello.rs -o hello
rush:/sys/tools/rust$ ls -lh
f 7.63M   hello
```

`src/hello.rs` is the sample from [build-rustc.md](build-rustc.md) — HashMap,
sort, `println!`, one spawned thread. Pure Rust, no C.

## Summary

Two independent causes, two independent fixes.

1. **~83% of the binary is DWARF, essentially all of it from mlibc's
   `libc.a`**, which is built `-O2 -g` because mlibc's own `meson.build` pins
   `buildtype=debugoptimized` and build-llvm.md never overrides it. Every CMake
   component in that guide is explicitly `Release`; mlibc is the lone outlier.
   Fix: `-Ddebug=false`. Also reclaims ~14 MB of image space.
2. **mlibc is linked into pure-Rust programs at all**, because `/bin/cc`
   unconditionally appends `crt1.o` + the mlibc runtime group to *every* link.
   std does not pull in libc — rustc's link line is pure Rust. The `-l`
   archives are free (lazy extraction); **`crt1.o` alone costs 7.9 MB**, because
   it is an object file (always linked whole), its strong `motor_start`
   overrides std's weak one, and its `U __mlibc_entry` cascades into `libc.a` →
   `libc++abi` → `libunwind`.

With both fixed, a pure-Rust `hello.rs` on Motor is **~113 KB**.

Headline numbers (all measured, x86_64):

| binary | as built | stripped | `.text` |
|---|---|---|---|
| host, default (**dynamic**) | 4,462,680 | 386,464 | 279,219 |
| host, `-C target-feature=+crt-static` | 5,512,152 | 1,347,128 | 1,004,067 |
| **motor, today** | **8,006,160** | 1,085,568 | 871,561 |
| motor, no `crt1.o` (group still present) | **120,744** | — | — |
| motor, no mlibc group at all | 124,400 | — | 54,594 |
| motor, cargo opt-in, pure Rust | **112,872** | — | — |

Note the third and fourth rows: the original "7.63M vs 4.3M" comparison was
dynamic-vs-static. Compared like-for-like, **Motor's static binary is smaller
than the host's static binary** (1,085,568 vs 1,347,128 stripped; 871,561 vs
1,004,067 of code). There is nothing wrong with the port's codegen.

## Reproducing on the host (no VM)

The on-image result reproduces exactly by cross-linking on the host — 8,006,160
bytes, which is the 7.63 M the VM reports. This is what makes the whole
investigation cheap:

```sh
export MOTORH=$HOME/motorh SYSROOT=$MOTORH/motor-sysroot
export B=$MOTORH/llvm-project/build/bin

# what the image does (motor-rust-cc == /bin/cc's group):
rustc +dev-x86_64-unknown-motor -O --target x86_64-unknown-motor \
    -C linker=$SYSROOT/bin/motor-rust-cc hello.rs -o hello-motor      # 8,006,160

# what `make all` does for the OS's own Rust programs (plain host cc):
rustc +dev-x86_64-unknown-motor -O --target x86_64-unknown-motor \
    hello.rs -o hello-pure                                            # 124,400

# host baselines:
rustc -O hello.rs -o hello-host                                       # 4,462,680
rustc -O -C target-feature=+crt-static hello.rs -o hello-host-static  # 5,512,152
```

`llvm-dwarfdump` is not in `$B`; use
`$MOTORH/rust/build/x86_64-unknown-linux-gnu/llvm/bin/llvm-dwarfdump`.

## Finding 1 — the DWARF comes from mlibc, not from Rust

| binary | `.debug_*` | share | CUs |
|---|---|---|---|
| motor | 6,656,940 | 83.1% | 54, **all mlibc** (`comp_dir=$MOTORH/mlibc/build`) |
| host | 3,952,245 | 88.6% | 13, all Rust (`/rustc/<hash>`, memchr, hashbrown) |

Both binaries are mostly debug info, but from opposite sources. On Motor, Rust
contributes almost none: `libstd.rlib` for motor is 1,372,440 bytes of objects
with **0 bytes of `.debug_*`** (bootstrap builds std without debuginfo). The
host's shipped `libstd.rlib` is 12 MB and carries debuginfo.

The sysroot `libc.a` is 18,287,414 bytes, of which **10,437,633 (59.3%) is
DWARF** across its 402 members. That flows into every binary linked on the image.

Root cause — mlibc's own `meson.build`:

```
project('mlibc',
    default_options: ['cpp_std=c++23', 'c_std=gnu11', 'buildtype=debugoptimized', ...])
```

`debugoptimized` = `-O2 -g`. [build-llvm.md](build-llvm.md):299 — the real
static build, not the headers-only setup at :293 — runs `meson setup` with no
`--buildtype`, so the project default wins. The cross-file
(`$MOTORH/motor.cross-file`) sets `c_args`/`cpp_args` but no buildtype either.
Meanwhile every CMake component in that guide is explicitly
`-DCMAKE_BUILD_TYPE=Release` (lines 128, 191, 317, 391) — which is why
`libc++.a`, `libc++abi.a` and `libunwind.a` carry no DWARF at all.

**This is a size issue only, not a codegen issue.** Disassembling `__cosdf` from
the shipped `libc.a` shows properly optimized code (registers, no spills). An
early hypothesis that meson's `-O0` default applied was checked and is wrong.

Verified fix — strip debug from the sysroot archives and relink, no rustc flags
and no source change:

```
libc.a                18,287,414 -> 3,856,718
hello                  8,006,160 -> 1,345,768
.text                    871,561 -> 871,561      (byte-identical)
.debug_*                       — -> 0
symbols                                kept       (backtraces still work)
```

All archives together: 23,944,802 → 9,463,770 (saved 14,481,032, of which
`libc.a` is 14,430,696 and `libmoto_rt_cabi.a` 24,776; the rest are already
clean).

The minimal change is `-Ddebug=false` on mlibc's `meson setup` — that keeps
`-O2` exactly as today and only drops `-g`. `--buildtype=release` would also
work but silently moves to `-O3`, changing codegen. `llvm-strip --strip-debug
libc.a` achieves the same on an already-built sysroot but does **not** survive
an mlibc rebuild, so the meson flag is the durable half.

The image stages an 18 MB `libc.a` at `/sys/tools/llvm/lib` (that directory is
31 MB of a 357 MB `img_files` tree), so this also reclaims ~14 MB of image space
and fixes native compiles on the VM, which link against the on-image copy.

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
same group. It is used only to build rustc itself and must keep `crt1.o`.)

The mechanism, and it is entirely `crt1.o`:

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
link this way, with zero mlibc and std's weak `motor_start`:

```
rush 538,176   crossbench 378,128   httpd 1,390,176   httpd-axum 3,565,512
kernel 407,616   kibim 152,848   kloader 73,344   mdbg 341,208
mio-test 1,308,072   red 218,480   rnetbench 406,984   russhd 3,266,400
```

(`/bin/libc-smoke`, a genuine C program, correctly has strong `T motor_start`
and 431 mlibc symbols.)

`hello-pure` (124,400) was verified to be a complete, valid binary: static-pie,
entry = std's weak `motor_start` at 0xab10, zero mlibc/`__cxxabi`/`_Unwind`
symbols, program strings present, `.text` 54,594. **It has not been booted** —
but its link shape is identical to `rush`, which runs in production.

### Why `/bin/cc` was written this way

It is not gratuitous. rustc *itself* is a C++/LLVM binary that genuinely needs
mlibc's C runtime, and `cc hello.c` needs it too. `/bin/cc` cannot tell "linking
pure Rust" from "linking something with C in it", so it adds the group to
everything — and pure-Rust programs pay 7.5 MB for a runtime they never call.
Note `/bin/cc` passes `-nostartfiles` itself and then supplies a startfile,
i.e. it contradicts the flag rustc already passed.

## Finding 3 — the `libc` crate is inert on Motor

This is the linchpin for Option B.

- `sys/pal/motor`, `sys/process/motor`, `sys/fs/motor`, `sys/net/motor`,
  `sys/thread/motor`: **zero** uses of `libc::`.
- The motor `liblibc-*.rlib` is **4,852 bytes, 1 object member, 0 defined
  symbols** — pure declarations, and it declares no native library to link.

It is nonetheless always in the dependency graph, via blanket deps:

```toml
# library/std/Cargo.toml
[target.'cfg(not(all(windows, target_env = "msvc")))'.dependencies]
libc = { version = "0.2.185", default-features = false,
         features = ['rustc-dep-of-std'], public = true }

# library/unwind/Cargo.toml
libc = { version = "0.2.140", features = ['rustc-dep-of-std'], default-features = false }
```

`cfg(not(windows-msvc))` catches Motor. In the pure-Rust setup
([build.md](build.md) / `build-base.sh`) there is no mlibc at all, and std does
not need it — the dep rides along unused. Gating it out for motor makes "libc in
the dependency tree" a **true** signal. The port already does exactly this kind
of target-gating for `memmap2` in `rustc_data_structures`.

## The options

### Option A — `/bin/cc` honors the `-nostartfiles` it is handed

Skip `crt1.o` when the caller passed `-nostartfiles`; keep the `-l` archives
(proven free, and they still resolve C symbols). `cc hello.c` (no
`-nostartfiles`) still gets `crt1.o` from the clang ToolChain; `rustc hello.rs`
drops to ~120 KB.

- **Pro:** two lines, immediate 64× win, independently testable, no cross-repo
  changes.
- **Con:** on-image **Rust + C** regresses — without `crt1.o`, std's
  `motor_start` runs, `.init_array` never fires, mlibc's stdio/TCB stay
  uninitialized. Silent misbehaviour, not a link error.
- Requires the stale-host-clang fix below if C links are to be delegated to the
  ToolChain.

### Option B — cargo/`#[link]` opt-in — **validated end-to-end**

Express the opt-in on `crt1.o` (not on `libc.a` — the archive is already free).
Rust's native mechanism does the discrimination:

```rust
// motor module of moturus/libc
#[link(name = "motorcrt1", kind = "static", modifiers = "+whole-archive,-bundle")]
#[link(name = "moto_rt_cabi", kind = "static", modifiers = "-bundle")]
#[link(name = "c++",   kind = "static", modifiers = "-bundle")]
#[link(name = "c++abi", kind = "static", modifiers = "-bundle")]
#[link(name = "unwind", kind = "static", modifiers = "-bundle")]
#[link(name = "c",     kind = "static", modifiers = "-bundle")]
#[link(name = "clang_rt.builtins-x86_64", kind = "static", modifiers = "-bundle")]
extern "C" {}
```

Measured, with a `cc` that never forces `crt1.o`, two programs differing only in
the dependency:

| program | bytes | `motor_start` | mlibc syms | entry owner |
|---|---|---|---|---|
| pure Rust, no dep | **112,872** | `W` | 0 | std |
| `extern crate motorlibc` | **8,006,376** | `T` | 426 | mlibc's crt1.o |

The second reproduces today's 8,006,160 almost exactly. rustc emitted precisely
`libmotorlibc.rlib -Wl,--whole-archive -lmotorcrt1 -Wl,--no-whole-archive -lc …`,
driven purely by the dependency.

**Four gotchas found while building it:**

1. `kind = "static"` defaults to **`+bundle`**, which copies `libc.a` *into* the
   rlib — the first attempt produced an **18,296,908-byte rlib**. `-bundle`
   brings it to 6,386.
2. `crt1.o` must be wrapped in an archive (`libmotorcrt1.a`); `#[link]` cannot
   name a bare `.o`. `+whole-archive` force-links it.
3. The crate must declare the **whole group**, not just `-lc`: `crt1.o`
   references `moto_rt_start`/`get_args`/`get_env`/`fill_random_bytes`/`log`/
   `proc_exit`/`tcb_set`, and mlibc needs `c++abi`. Declaring only `-lc` fails
   with undefined `moto_rt_*`.
4. No `--start-group` was needed; plain ordering satisfied lld.

**Work required:** add the `#[link]` block to `moturus/libc`'s motor module;
gate the `libc` dep out of `std` + `unwind` for motor in `moturus/rust`; have
build-llvm emit `libmotorcrt1.a`; make `/bin/cc` stop forcing `crt1.o`
(Option A). `motor-rust-cc` keeps `crt1.o` explicitly — rustc is linked on the
host and genuinely needs it.

- **Pro:** cargo does the discrimination for free; zero mlibc changes; uses
  Rust's native mechanism; validated.
- **Con:** it is a **declaration**, so it can be wrong. A `-sys` crate that
  links a C library without depending on the `libc` crate gets its archive but
  no `crt1.o` → uninitialized mlibc → silent. (In practice nearly every `-sys`
  crate depends on `libc`.) rustc itself is unaffected (linked on the host).

### Option C — strong `motor_start` in moto-rt + weak no-op `libc_start`

moto-rt owns `motor_start` (strong); it calls `libc_start`, weak/no-op in
moto-rt, strong in mlibc.

**It does not select anything.** Measured, three linkage shapes:

| variant | mlibc init ran? |
|---|---|
| `libc_start` alone in its own member (today's crt1.o shape), program uses C | **NO** — silent no-op |
| `libc_start` co-located with the C code the program calls | yes |
| own member + `--whole-archive` (what Option B emits) | yes |

A linker extracts an archive member only to resolve an **undefined** symbol, not
because a stronger definition exists elsewhere. moto-rt's weak definition
*defines* the symbol, so mlibc's strong one is never consulted. Note row 1: a
program that genuinely uses C **still** got the no-op, because the member
defining `libc_start` was not the member that got pulled. This is the same trap
already documented for `operator delete` (mlibc's strong stubs vs libc++abi's
weak ops — "no link order can fix that").

`-u libc_start` also loses if the moto-rt archive is scanned first; it only wins
with `-u` **and** `libc.a` before the rlibs, which forces mlibc into every link
— the `crt1.o` problem relocated.

So `libc_start` is a **clean default that composes with Option B**, not a
replacement for it. Its value is architectural, and smaller than it first looks
(see the correction below).

- **Pro:** one owner of the entry point; std's `motor_start` stops being `weak`
  (no more "linking a library silently changes your entry point"); a duplicate
  `crt1.o` + moto-rt link becomes a loud duplicate-symbol error.
- **Con:** buys zero bytes over Option B; touches three repos, one of which is
  crates.io (moto-rt would carry a weak no-op that exists only for mlibc's
  benefit); `crt1.o` still cannot be deleted (a pure C program links no Rust, so
  moto-rt's `motor_start` is unavailable to it) — so mlibc ends up with two init
  entries; and `libc_start` **returns**, which breaks the block-lifetime
  invariant below (the block would have to become static).

### Option D — weak `__mlibc_entry` in moto-rt instead of a new symbol

Invent no symbol; declare mlibc's existing `__mlibc_entry` weak/no-op in
moto-rt. Attractive because mlibc might need **zero** changes.

The mechanism genuinely works: `__mlibc_entry` never returns, a weak no-op does,
so "call it; if it returns, do the Rust path" is self-consistent. But
`__mlibc_entry` is the **wrong seam**:

```cpp
// mlibc: sysdeps/motor/generic/entry.cpp
extern "C" void __mlibc_entry(uintptr_t *entry_stack,
                              int (*main_fn)(int argc, char *argv[], char *env[])) {
	__dlapi_enter(entry_stack);
	auto result = main_fn(mlibc::entry_stack.argc, mlibc::entry_stack.argv, environ);
	exit(result);
}
```

Its first parameter is a **SysV ELF entry stack**, which Motor does not have.
`sysdeps/motor/crt-src/crt1.c` (67 lines) exists precisely to synthesize one:

```c
void motor_start(void) {
	moto_rt_start();                       /* VDSO vtable; must be first */
	int argc = 0;
	char **argv = moto_rt_get_args(&argc);
	char **envp = moto_rt_get_env();
	int envc = 0; while (envp[envc]) envc++;
	static unsigned char random_bytes[16];
	moto_rt_fill_random_bytes(random_bytes, sizeof random_bytes);
	uptr block[1 + (argc+1) + (envc+1) + 8];
	/* [argc][argv...][NULL][envp...][NULL][AT_PAGESZ][AT_SECURE][AT_RANDOM][AT_NULL] */
	__mlibc_entry(block, main);
	__builtin_trap();                      /* __mlibc_entry calls exit() */
}
```

So a weak `__mlibc_entry` in moto-rt means **moto-rt must build that block** —
argc/argv/envp marshalling plus auxv (`AT_PAGESZ`/`AT_SECURE`/`AT_RANDOM`, the
last being why crt1 calls `moto_rt_fill_random_bytes`: 16 bytes for the stack
protector). That puts SysV auxv layout and mlibc's private entry ABI inside the
pure-Rust crates.io crate that **every** Motor program links.

Two more things live in that file and would need a home: the self-referential
`__dso_handle` (its comment records that without it, mlibc's
`__mlibc_do_finalize` tears down stdio before destructors that still print —
"found the hard way at M8"), and the invariant that the block sits in
`motor_start`'s frame, *"which never returns — mlibc keeps pointers into it for
the process lifetime."*

One point in Option D's favour: `__mlibc_entry` preserves that frame-lifetime
invariant for free, whereas `libc_start` breaks it.

Extraction is unchanged: still needs `+whole-archive`.

**Verdict: worst of the three seams.**

### Option E — `.init_array`

moto-rt's strong `motor_start` walks `.init_array`; mlibc's init becomes
constructors on the objects owning the state. The linker builds `.init_array`
from **only the objects actually linked**, so it is conditional by construction
— no weak symbols, no `-u`, no driver heuristics, and it cannot be silently
wrong. Verified: with an identical link line, a pure-Rust-analogue link had 1
`.init_array` entry and a C-using link had 2.

mlibc already uses this internally — `options/elf/generic/startup.cpp` has
`[[gnu::constructor]] void init_libc()`.

- **Pro:** the only mechanism that is both automatic and exact; handles `-sys`
  crates that Option B's declaration would miss.
- **Con:** requires restructuring mlibc's init and diverging from upstream;
  ordering is delicate (mlibc's core init must precede any constructor touching
  stdio → `constructor(priority)`). **And once cargo decides via Option B, its
  one advantage is redundant.**

## A correction to the record

During the discussion it was claimed that "crt1.o is a C reimplementation of
std's `motor_start`", which made "kill the duplicated startup" the strongest
argument for Options C/D. **Having read the source, that is wrong.** The overlap
with std's `motor_start`

```rust
#[linkage = "weak"]
pub extern "C" fn motor_start() -> ! {
    moto_rt::start();
    let result = unsafe { main(0, core::ptr::null(), 0) };
    moto_rt::process::exit(result)
}
```

is three lines — `moto_rt_start()`, call `main`, `exit`. The other ~50 lines of
crt1.c are genuine Motor→SysV translation that std has no analogue for and does
not need. The argc/argv difference (crt1 passes real args; std passes
`main(0, null, 0)`) is not drift between two copies of one thing: crt1 must pass
real args to a C `main`, while Rust reads args from the VDSO. So the
"duplication" argument for the C/D redesigns is much weaker than it appeared.

## Recommendation

1. **mlibc `-Ddebug=false`** (Finding 1). Independent of everything else. ~14 MB
   of image, ~6.6 MB per binary, no codegen change.
2. **Option A** — `/bin/cc` honors `-nostartfiles`. Two lines, immediate 64×
   win, independently testable.
3. **Option B** — the `#[link]` opt-in. The real fix; spans two forks; needs a
   VM boot to verify. Makes Option A's Rust+C regression go away, because a
   program that wants libc now says so.
4. **Leave `motor_start` weak.** Options C and D buy zero bytes over B and cost
   three-repo changes. If C/D is ever revisited, prefer `libc_start` (a seam you
   own) over `__mlibc_entry` (mlibc's private entry ABI), and know the prize is
   only "std's `motor_start` isn't weak any more" — real, but small, and
   Option B already removes the surprise because `crt1.o` then only enters the
   link when you asked for libc.

Ranking of the seams, for the record:
`+whole-archive crt1.o` (B) **>** `libc_start` (C) **>** `__mlibc_entry` (D).
`crt1.o` already *is* the translation layer, it is 2,416 bytes, it is correct,
and it encodes subtleties each paid for once already. Option B makes it
conditional, which was the entire problem.

## Traps

- **A weak definition prevents archive extraction.** The linker pulls a member
  only to resolve an *undefined* symbol. Any "weak default in A, strong override
  in archive B" design silently no-ops unless extraction is forced. Already hit
  once in this port (mlibc's strong `operator delete` stubs vs libc++abi's weak
  ops).
- **`kind = "static"` defaults to `+bundle`** and copies the archive into the
  rlib (18 MB rlib). Use `-bundle`.
- **`#[link]` cannot name a bare `.o`** — wrap `crt1.o` in an archive.
- **`crt1.o` is an object, not an archive member**, so `--gc-sections` cannot
  save you: it is always linked whole, and it is the sole cause of the cascade.
- **mlibc's `libc.a` DWARF does not survive a strip if mlibc is rebuilt** — fix
  the meson flag, not just the artifact.
- **Motor's `crt1.c` block lives in `motor_start`'s frame** and mlibc keeps
  pointers into it for the process lifetime. Any redesign where the hook
  *returns* must relocate that block to static storage.

## Incidental findings (unrelated to the redesign, worth fixing)

- **The host cross clang is stale.** `clang/lib/Driver/ToolChains/Motor.cpp`
  carries the "add `-lc++abi` unconditionally, even for C" fix (lines ~84-90,
  mtime 2026-07-13), but `$MOTORH/llvm-project/build/bin/clang` was built
  2026-07-05 — eight days earlier. So a bare
  `clang --target=x86_64-unknown-motor hello.c` still fails with
  `undefined symbol: operator delete(void*, unsigned long)`. Rebuild it; Option
  A wants the ToolChain to own C links.
- **std's `motor_start` passes `main(0, null, 0)`** while crt1.o passes real
  argc/argv. Harmless today (Rust reads args from the VDSO), but the two startup
  paths do genuinely differ, and only crt1.o's is usable by a C `main`.
