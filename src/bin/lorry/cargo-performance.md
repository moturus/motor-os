# Lorry vs Cargo build performance on Linux

Date: 2026-10-07. Lorry at `520cb274`. Both tools use the same Motor
toolchain rustc (1.99), the dev profile, and default job counts on a 16-CPU
host. Dependencies were vendored for Lorry from this host's Cargo caches
without network access. Both tools build C code with clang. For Helix, both
set `HELIX_DISABLE_AUTO_GRAMMAR_BUILD=1`, so neither fetches grammars.

## Results

sys-io (`src/sys` workspace, built for `x86_64-unknown-motor`):

| Step | Cargo | Lorry |
| --- | --- | --- |
| Cold build | 17.9 s | 36.7 s |
| No-op build | 0.06 s | 0.9 s |
| Edit a library (`moto-sys-io`) | 1.3 s | 7.4 s |
| Edit the binary (`sys-io/src/main.rs`) | 1.2 s | 7.5 s |
| Cold target, warm Lorry cache | — | 13.4 s |

Helix (`hx`, 334 units, host build):

| Step | Cargo | Lorry |
| --- | --- | --- |
| Cold build | 66.7 s | 145.6 s |
| No-op build | 0.12 s | 2.5 s |
| Edit a library (`helix-core`) | 8.1 s | 37.4 s |
| Edit the binary (`helix-term/src/main.rs`) | 6.6 s | 28.0 s |
| Cold target, warm Lorry cache | — | 56.2 s |

Lorry is faster than Cargo only when its global cache already has the
dependencies.

## Fixed during this comparison

- Lorry could not build Helix at all. Without `--target`, it planned a host
  and a target copy of 42 units with the same identity. Both copies compiled
  into the same directory, and the second failed with "Directory not empty".
  Cargo builds such a unit once; Lorry now does too (`af5f41db`).
- Lorry's heap grew to 3.8 GB while it resolved the locked Helix workspace.
  The resolver kept a full copy of its state for every step, for backtracking
  that an exact lock never needs. Every later rustc start then had to fork a
  3.8 GB process. That took about 75 ms each and serialized the starts. Peak
  memory is now 38 MB and system time dropped from 78 s to 29 s (`520cb274`).

## Remaining causes, largest first

1. **Source views are copied with one fsync per file.** On a cold cache,
   Lorry copies every dependency's sources into its cache, one package after
   another. This costs 16 s for sys-io (2,200 files) and 66 s for Helix (8,700
   files). Cargo never fsyncs extracted sources. One flush per tree, or hard
   links from the repository object, would remove most of this.
2. **Build scripts run again on every non-fresh build.** A build-script run
   has no freshness check of its own, unlike Cargo's `rerun-if-changed` and
   `rerun-if-env-changed` handling. So any edit reruns all 33 Helix scripts. A
   script with unstable output then rebuilds its package and all dependents.
   `moto-netstack` writes its config from a `HashMap`, so its line order
   changes every run. That alone adds 6 s to every sys-io edit.
3. **A member's units are keyed on its whole directory.** Editing
   `helix-term/src/main.rs` rebuilds the `helix-term` library and build
   script, not just the binary. Cargo uses each unit's dep-info, so it
   rebuilds only the binary.
4. **Admission is verified on every command,** even a no-op build: 0.9 s for
   sys-io and 2.5 s for Helix. For Helix, 1.2 s of this is the resolver
   copying its whole state at each of about 2,000 steps.
5. **Every dependency output is copied into the global cache with fsync,**
   854 MB for Helix. This shows up as system time during cold builds.

Pipelining is not a factor: Cargo with pipelining disabled was as fast.

## Where tools stage files

Cargo stages next to the destination. It even creates `target/` under a
temporary name and renames it into place. rustc stages inside its output
directories. During a Cargo build, only the C linker wrote to the temp dir.

Lorry stages in the shared temp dir for admission, metadata, review, tree,
vendor, curl downloads, and strict cache checks. A killed command leaves an
empty staging directory there. Moving each one next to its destination would
match Cargo and keep renames on one filesystem.

## Other observations

- Lorry prints a build script's probe compiler errors (for example
  `error[E0433]` from an `alloc` probe) on a successful build. Cargo hides a
  build script's output unless the script fails.
- GCC cannot run as a declared native tool: its driver starts `cc1`, which
  the build-script sandbox blocks. Clang works.
