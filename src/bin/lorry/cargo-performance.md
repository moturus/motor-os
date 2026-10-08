# Lorry vs Cargo build performance on Linux

First measured on 2026-10-07 at `520cb274`, and again on 2026-10-08 at
`93ba0e3a` after the fixes below. Both tools use the same Motor toolchain rustc
(1.99), the dev profile, and default job counts on a 16-CPU host.
Dependencies were vendored for Lorry from this host's Cargo caches without
network access. Both tools build C code with clang. For Helix, both set
`HELIX_DISABLE_AUTO_GRAMMAR_BUILD=1`, so neither fetches grammars.

## Results

sys-io (`src/sys` workspace, built for `x86_64-unknown-motor`):

| Step | Cargo | Lorry `520cb274` | Lorry `93ba0e3a` |
| --- | --- | --- | --- |
| Cold build | 17.9 s | 36.7 s | 19.1 s |
| No-op build | 0.06 s | 0.9 s | 0.7 s |
| Edit a library (`moto-sys-io`) | 1.3 s | 7.4 s | 2.3 s |
| Edit the binary (`sys-io/src/main.rs`) | 1.2 s | 7.5 s | 2.2 s |
| Cold target, warm Lorry cache | — | 13.4 s | 12.5 s |

Helix (`hx`, 334 units, host build):

| Step | Cargo | Lorry `520cb274` | Lorry `93ba0e3a` |
| --- | --- | --- | --- |
| Cold build | 66.7 s | 145.6 s | 79.4 s |
| No-op build | 0.12 s | 2.5 s | 1.2 s |
| Edit a library (`helix-core`) | 8.1 s | 37.4 s | 10.4 s |
| Edit the binary (`helix-term/src/main.rs`) | 6.6 s | 28.0 s | 7.2 s |
| Cold target, warm Lorry cache | — | 56.2 s | 51.1 s |

## Fixed

- Lorry could not build Helix at all. Without `--target`, it planned a host
  and a target copy of 42 units with the same identity (`af5f41db`).
- Lorry's heap grew to 3.8 GB while it resolved the locked Helix workspace,
  and every rustc start had to fork it (`520cb274`).
- Source views were copied with one fsync per file: 16 s of a cold sys-io
  build. Every use already hashes a view, so a view torn by a crash is now
  quarantined and published again (`cd3b4e75`).
- Every build script ran again on every build. A run is now reused until
  something it tracks changes, by Cargo's `rerun-if` rules (`13efc58e`).
  `moto-netstack` writes its config in `HashMap` order, so each rerun used to
  rebuild it and everything above it.
- A member's units were keyed on the whole member directory. They now depend
  on the files in their rustc dep-info (`e29f6d3f`).
- Each compile used a new staging directory. rustc drops its incremental
  state when the output directory changes, so every edit was a full compile:
  4.5 s instead of 1.2 s for sys-io's binary. The staging name is now the
  same in every build (`58d5d6ef`).
- The resolver copied every package node at every step (`5b5b7a4f`).
- Ready units ran in plan order. Like Cargo, Lorry now runs first the unit
  that the most other units wait on (`2f9bd901`).
- Each worker copied its library into the cache, with fsync, before taking
  the next unit: 854 MB for Helix. Background threads do this now
  (`a3fa644a`).

## Remaining causes, largest first

1. **No pipelining.** Cargo starts a dependent as soon as rustc has written
   the dependency's metadata, while code generation continues. Lorry waits
   for the whole crate. On Helix's last chain (`helix-lsp-types`,
   `helix-lsp`, `helix-view`, `helix-term`, `hx`) this costs Lorry about 5 s.
   Lorry would have to let dependents read metadata from a crate that is
   still in staging.
2. **Admission is verified on every command.** This is most of a no-op build:
   0.6 s for sys-io and 1.1 s for Helix. It is resolver work: the complete
   lock, then one resolution per reviewed host/target context. Keeping a
   verified admission between commands would remove it, but the design now
   requires admission to be rebuilt before any reuse.
3. **Lorry starts compiling later.** Admission and checking the dependency
   sources take 2 s on a cold Helix build before the first rustc starts.
4. **A warm cache saves less than it could.** With a warm cache and an empty
   target, Lorry still compiles every member and every binary.

## Corrections

The first version of this page said two things that were wrong:

- "Pipelining is not a factor." That test set `CARGO_BUILD_PIPELINING=false`,
  which Cargo 1.99 ignores; `--timings` shows it still pipelined.
- "Cargo rebuilds only the binary after an edit to `helix-term/src/main.rs`."
  helix-term's build script names no `rerun-if` file, so Cargo reruns it and
  rebuilds the `helix-term` library and `hx`. Lorry now reruns the script,
  sees the same output, and rebuilds only `hx`.

## Where tools stage files

Cargo stages next to the destination. It even creates `target/` under a
temporary name and renames it into place. rustc stages inside its output
directories. During a Cargo build, only the C linker wrote to the temp dir.

Lorry stages each compiler unit in a sibling of the unit's directory, and the
source views in the cache. It no longer creates a directory per command in
the temp dir. The temp dir is used only to unpack a `.crate` archive whose
repository does not keep its sources (`keep-sources = false`), and for curl's
stderr when it grows large.

## Other observations

- Lorry prints a build script's probe compiler errors (for example
  `error[E0433]` from an `alloc` probe) on a successful build. Cargo hides a
  build script's output unless the script fails.
- GCC cannot run as a declared native tool: its driver starts `cc1`, which
  the build-script sandbox blocks. Clang works.
