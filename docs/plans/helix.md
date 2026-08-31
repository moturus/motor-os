# Porting the Helix editor to Motor OS

2026-08-30. High-level outline from a feasibility review of Helix 25.7.1
(`../helix`) against the current tree and toolchain. This is a plan, not a
design: each phase below needs its own design pass before implementation.

## Verdict

The port is feasible with no `src/sys` or std changes. The heavy
infrastructure already exists: the Motor tokio/mio forks cover every runtime
feature Helix uses (`rt-multi-thread`, `process`, `fs`, `time`, `io-std`,
`net`); helix-tui retains a crossterm backend (today Windows-gated) that maps
onto the Motor crossterm fork, which has a Motor event source and the async
`EventStream`; the C toolchain and mlibc sysroot make tree-sitter's vendored C
runtime and grammar sources ordinary cross-compilation; and the rust-analyzer
work proved the link recipe (static PIE via `motor-rust-cc`, constructors run
by mlibc's crt1).

The one structural change: Motor has no dynamic loading, and Helix loads
tree-sitter grammars as shared libraries. Grammars must be statically linked;
tree-house already exposes the hook (`TryFrom<LanguageFn> for Grammar` behind
its `tree-sitter-language` feature).

Rough estimate: a running editor (no syntax highlighting) in days; a
full-featured port, statically linked grammars included, in two to three
weeks of focused work.

## Phases

1. **Workspace glue.** A Motor branch in a Helix fork, following the
   ripgrep-port pattern: `[patch.crates-io]` entries for the Motor tokio,
   mio, and crossterm forks; the git feature (gix) disabled initially; the
   upstream `rust-toolchain.toml` pin dropped in favor of the Motor
   toolchain.
2. **Terminal backend.** Extend Helix's existing `cfg(windows)` seams so
   Motor also takes the crossterm path: `CrosstermBackend`, crossterm's
   `EventStream`, an empty signal stream (Motor has no signals), `suspend`
   compiled out, and `enable_ctrl_c_events()` called during TUI setup so
   terminal Ctrl+C arrives as a key event instead of terminating the editor
   with status 130. Includes the mechanical crossterm 0.28→0.29 API delta in
   helix-tui/helix-view.
3. **Small platform fallbacks.** helix-stdx file-access checks, the
   tempfile-based document save path, a clipboard provider (internal
   registers first), a stub for the `open` (URL) crate, and `HOME`-based
   config/runtime directory resolution.
4. **tree-sitter core.** Compile the vendored tree-sitter C runtime against
   the mlibc sysroot via the `cc` crate; link the editor through
   `motor-rust-cc`; a small tree-house-bindings patch gates the libloading
   path off for Motor while keeping the `LanguageFn` path.
5. **Static grammar registry.** Cross-compile a curated grammar set
   (C++-scanner grammars are fine — libc++ with exceptions is available) and
   generate a name → `LanguageFn` table that grammar resolution consults on
   Motor instead of dlopen.
6. **rust-analyzer.** Helix ships rust-analyzer support out of the box over
   stdio pipes; point it at the native rust-analyzer and hand it the Lorry
   project graph through `languages.toml` initialization options. Align with
   the rust-analyzer integration design once it lands.
7. **Packaging.** Stage `hx` and its `runtime/` tree (themes, queries,
   tutor) into the development image; default config: `rush` as the shell,
   mouse off.

## Out of scope

- **Mouse support.** The Motor crossterm fork parses no mouse sequences and
  porting mouse support is explicitly out of scope; Helix runs
  keyboard-only with `mouse = false`.
- Suspend/job control (`C-z`) — no signals, no process groups; rmux is the
  answer to that need.
- Git integration (gix) — revisit after the core port.
- Kitty keyboard-enhancement protocol; Helix probes and degrades on its own.
- Upstreaming: the port stays a fork branch rebased per Helix release, like
  the other Motor application ports.
