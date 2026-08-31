# Porting the Helix editor to Motor OS

2026-08-30. Plan for porting Helix 25.7.1 to Motor OS, from a feasibility
review against the current tree and toolchain. Per AGENTS.md, this is the
planning step. The user's decisions are recorded in the Decisions section
below and are settled — do not re-litigate them.

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

## Ground rules

- **Where the code lives.** The port is a fork at `github.com/moturus/helix`,
  worked on in the sibling checkout `../helix`, based on the upstream
  `25.7.1` tag. Per decision 1, the port lives on a dated, version-qualified
  branch (tokio/mio fork style, e.g. `helix-motor-25.7.1_<date>`); `master`
  stays reserved for upstream PRs. The Motor OS repository receives only
  build, staging, and test glue (steps 10–11).
- **Minimize changes outside `../helix`.** The only external mechanism is
  `[patch.crates-io]` redirection onto Motor forks that already exist —
  tokio, mio, crossterm, libloading. No code changes to those forks are
  planned, and no new fork is created without stopping for review first
  (decision 6).
  Note that a `[patch]` applies to host builds of the fork too; the Motor
  tokio/mio branches are behavior-identical on Linux, so host test results
  remain meaningful.
- **AGENTS.md applies throughout**: 100–300 loc patches including tests; a
  larger patch only where splitting is genuinely hard (step 5 is flagged);
  comments sparse; stop on any non-obvious decision or preexisting bug; no
  new warnings from the fork's own diffs; `cargo fmt` with upstream Helix's
  rustfmt configuration; regular tests never reach the Internet — grammar
  and dependency acquisition happen in explicit, locked build steps, never
  in tests.
- **Helix is a non-core component.** It is gated by component tests plus the
  developer-image suite; per AGENTS.md the developer-image gate runs
  release-only (`src/tests/full-test-dev.sh --release`). If any step turns
  out to require a `src/sys` change, stop for review first.
- **Green at every step.** Each patch keeps the host build and Helix's own
  test suite passing; from step 6 on, it also keeps
  `cargo check --workspace --locked --offline --target x86_64-unknown-motor`
  clean (with `DISABLED_TS_BUILD=1` until step 7).
- The fork does not maintain Windows builds; upstream remains the source of
  truth for Windows.

## Step-by-step plan

### Stage 1 — fork bring-up (all in `../helix`)

1. **Fork setup.** Create the version-qualified Motor branch from the
   `25.7.1` tag (decision 1); remove the upstream
   `rust-toolchain.toml` pin; add `MOTOR.md` recording the build recipe as
   it evolves. Gate: upstream `cargo test` on the host is unaffected.
2. **Runtime dependency pins.** `[patch.crates-io]` for tokio and mio onto
   the same Motor branches `src/bin` uses, and libloading onto the Motor
   fork (`0.9.0+motor.1`) so tree-house-bindings' unconditional import
   compiles; regenerate `Cargo.lock`. Gate: host build and tests green on
   the patched runtime crates.
3. **helix-stdx fallbacks.** Motor implementations for the `cfg(unix)`
   surface (file-access checks via std metadata, plus whatever `env`/`which`
   gaps the cross-check exposes), with target-independent unit tests.
   Gate: host tests, and `cargo check -p helix-stdx --target
   x86_64-unknown-motor`.
4. **helix-view seams.** Bump crossterm to the Motor fork (0.29) and extend
   the `cfg(windows)` conversion seams (keyboard, input, graphics) to
   include `target_os = "motor"`; adjust for the 0.28→0.29 API delta.
5. **helix-tui backend.** Enable the crossterm backend for Motor and apply
   its 0.29 delta. Flagged as the step most likely to exceed 300 loc; split
   with step 4 differently if review prefers.
6. **helix-term.** Backend and event-type selection for Motor (crossterm
   `EventStream`), the empty signal stream, `suspend` compiled out,
   `enable_ctrl_c_events()` during TUI setup — Motor's documented Ctrl+C
   mechanism (docs/tui.md, decision 4) — so terminal Ctrl+C arrives as a
   key event instead of terminating the editor with status 130, and the
   `open` (URL) crate stubbed. Gate: the full-workspace Motor cross-check
   passes with `DISABLED_TS_BUILD=1`.
7. **Save path and clipboard.** A tempfile-free document save path on Motor
   and the internal-register clipboard provider (decision 5). Gate: cross-check clean
   without `DISABLED_TS_BUILD` exclusions in these crates; host save-path
   tests unchanged.

### Stage 2 — tree-sitter and grammars

8. **C core.** Build the vendored tree-sitter runtime for Motor via the `cc`
   crate (`CC_x86_64_unknown_motor=motor-clang`, `AR` from the assembly,
   linker `motor-rust-cc`), documented in `MOTOR.md` as environment supplied
   at invocation — no host-specific paths committed. First full `hx` link.
   Gate: the rust-analyzer plan's ELF checks (static PIE, no `NEEDED`
   entries, non-executable stack), then `hx --version` and `hx --health` in
   a Motor VM.
9. **Static grammar registry.** A new workspace crate whose build script
   compiles the curated grammar set (decision 2) from the
   `languages.toml`-pinned sources (decision 7), and exposes a
   name → `LanguageFn` table; grammar resolution
   consults it on Motor via tree-house's `tree-sitter-language` feature
   instead of dlopen. Two patches: the registry crate, then loader
   integration. Gate: `hx --health <lang>` green for each curated language
   on Motor; highlighting visible in a VM; the host dylib path untouched.

### Stage 3 — Motor OS repo glue

10. **Build and staging.** `update_helix_source`/`build_helix` in
    `src/build-motor-os.sh`, modeled on ripgrep's clone/build functions but
    pinned to the declared Motor branch rather than fast-forwarding `master`
    (decision 1), with the step-8 environment; stage `hx` (stripped) and its
    `runtime/` tree (queries, themes, tutor) into a generated image root,
    with `HELIX_DEFAULT_RUNTIME` baked at build time to the staged runtime
    path — Helix's supported packager mechanism, so no wrapper script or
    global environment variable is needed. Placement: the development image
    only, under `/devtools/helix/` (decision 3).
11. **VM tests.** `src/tests/test-helix.sh` on the established harness, in
    the style of `test-tui.sh`/`test-terminal-size.sh`: open/edit/save
    round-trip over an SSH pty and in an rmux pane; resize repaint with no
    key typed; terminal Ctrl+C delivered as a key event with the editor
    surviving; `:sh` through rush; clean exit restoring the pane. Wired into
    `full-test-dev.sh` (release-only).

### Stage 4 — rust-analyzer integration (after the native server lands)

12. **Language server defaults.** Motor `languages.toml` defaults pointing
    at the native rust-analyzer with the Lorry-generated project graph,
    following the updated rust-analyzer design once it is final. Gate: a
    diagnostic and a hover on a staged fixture inside a VM, driven from
    `test-helix.sh`.

## Out of scope

- **Mouse support.** The Motor crossterm fork parses no mouse sequences and
  porting mouse support is explicitly out of scope; Helix runs
  keyboard-only with `mouse = false`.
- Suspend/job control (`C-z`) — no signals, no process groups; rmux is the
  answer to that need.
- Git integration (gix) — revisit after the core port.
- Kitty keyboard-enhancement protocol; Helix probes and degrades on its own.
- Upstreaming: deferred until the target and its crate ecosystem exist
  upstream. The cfg-seam approach deliberately keeps the diff
  upstream-shaped for that eventuality.

## Decisions (user provided)

Answered by the user on 2026-08-30. These are settled inputs to this plan —
do not re-litigate or re-open them without new user input.

1. **Fork branch convention.** Dated, version-qualified branches, tokio/mio
   style (e.g. `helix-motor-25.7.1_<date>`). `master` is reserved for PRs;
   ripgrep's master-based convention is not the model here.
2. **Initial grammar set.** rust, toml, markdown + markdown-inline, c, cpp,
   json, yaml, bash, lua.
3. **Image placement.** Development image only, under `/devtools/helix/`.
4. **Ctrl+C.** Use Motor's documented terminal Ctrl+C handling
   ([tui.md](../tui.md)): the crossterm adapter `enable_ctrl_c_events()`
   called during TUI setup, as step 6 specifies. `C-c` reaches Helix as a
   key event; quitting is `:q`.
5. **Clipboard v1.** Internal registers only; OSC 52 pass-through is a
   follow-up once russhd/rmux behavior for it is verified.
6. **Dependency-fork contingency.** Not pre-approved. If tree-house-bindings
   fails to compile against the Motor libloading fork — or any other new
   fork starts to look necessary — stop for review.
7. **Grammar sourcing.** Compile grammars from the exact git revisions
   Helix's `languages.toml` pins, fetched on the host by the existing
   `hx --grammar fetch` machinery as an explicit, locked build step — never
   during tests. Rationale: the bundled `runtime/queries` are written
   against those revisions, so grammars and queries stay one source of
   truth that moves atomically with every Helix rebase; published
   `tree-sitter-*` crates would pin different commits and create a second
   pin set to re-verify at every rebase.
