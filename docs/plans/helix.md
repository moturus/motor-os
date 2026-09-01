# Porting Helix 25.07.1 to Motor OS

2026-08-31. This is the implementation plan for Stages 1-3 of the Helix
port, pinned to release tag `25.07.1`, commit
`a05c151bb6e8e9c65ec390b0ae2afe7a5efd619b`. Stage 4 remains deferred until
the native rust-analyzer port and its Lorry project description are final.

The release was committed on 2025-07-18. Its Cargo package version is
`25.7.1`, while `hx --version` reports `25.07.1` because the release build
script zero-pads a one-digit month. It is intentionally older than upstream
HEAD: the existing Motor Tokio 1.47.1 fork satisfies this release's Tokio 1.46
requirement, and this release still uses crossterm as its native terminal
backend. Builds and assembly provenance use full commit hashes, never a tag or
moving branch alone.

The deliverable is Helix running on Motor OS. Every Motor artifact is
cross-compiled on the Linux host with the repository-selected Motor
toolchain; compiling Helix natively on Motor OS is out of scope.

Per `AGENTS.md`, this document is the planning step. Do not change product
code while reviewing it. During implementation, keep each patch to roughly
100-300 lines including tests, run the gate listed for that patch, and stop
on a pre-existing defect or an unspecified non-obvious decision.

## Readiness verdict

- **Stages 1-3 are implementation-specified. The one new dependency fork was
  approved by the user on 2026-08-31.**
- Helix 25.07.1 locks `tree-house-bindings` 0.2.1. That release both depends
  unconditionally on `libloading ^0.8` and lacks the static
  `tree-sitter-language` constructor assumed by the previous plan.
- Update within tree-house 0.3.0's compatible `^0.2` range to
  `tree-house-bindings` 0.2.4, then use a small Motor fork of 0.2.4 which
  compiles out only its dynamic-loading constructor on Motor. Version 0.2.4
  already contains the required `TryFrom<LanguageFn>` implementation.
- The existing `libloading 0.9.0+motor.1` fork cannot satisfy `^0.8`, and
  Motor has no `dlopen`. Do not use that patch or add a dummy dynamic loader.
- No new Tokio fork is needed. Pin the existing Motor Tokio 1.47.1, mio
  1.0.4, and crossterm 0.29.0 commits exactly.

The remaining prerequisite is operational, not a design approval: a human
creates the GitHub forks before implementation. Agents work only in local
checkouts, and a human pushes completed sibling-repository work. After those
pushes, the agent replaces every local source reference with an exact GitHub
revision and repeats the remote-source gates.

## Reviewed baseline

The following facts were checked against the exact release commit and the
current Motor OS tree. Re-check them after any rebase; do not silently adapt
this plan to another Helix revision.

| Item | Required value or behavior |
| --- | --- |
| Upstream base | Tag `25.07.1`, commit `a05c151bb6e8e9c65ec390b0ae2afe7a5efd619b` |
| Upstream commit | 2025-07-18, `Release 25.07.1` |
| Reported product version | `25.07.1` (`Cargo.toml` package version `25.7.1`) |
| Motor branch | `helix-motor-25.7.1_2026-08-31`, based directly on the pinned commit |
| Rust toolchain | Release pins 1.82.0; update the fork pin to 1.90.0 because crossterm 0.29 requires Rust 1.85 or newer |
| Terminal backend | Crossterm 0.28.1 on all supported hosts; keep that architecture and update to the Motor crossterm 0.29.0 fork |
| Helix default features | `helix-term` defaults to `git`; every Motor invocation must use `--no-default-features` |
| Grammar auto-build | `helix-term/build.rs` fetches and builds grammars unless `HELIX_DISABLE_AUTO_GRAMMAR_BUILD=1` |
| Static linking | `.cargo/config.toml` adds `-C target-feature=-crt-static`; remove only that pair and retain `--cfg tokio_unstable` |
| crossterm | Motor branch `motor-os-support`, commit `94317189d1be68cd409d13380b8f4f94af9bc08c` (the branch head, also pinned by `src/sys/Cargo.lock`), crate version 0.29.0 |
| mio | Motor branch `mio-motor-v1.0.4_2025-10-07`, commit `907466acd6bd9fcccfb4f9c097dcda60c55157c4` |
| Tokio | Release locks 1.46.1 and requires `^1.46`; pin Motor branch `tokio-motor-1.47.1_2025-10-07`, commit `f9d26ea874753c0b5126401e77daee9e6222c359` |
| tree-house | Keep `tree-house = 0.3.0`; replace locked bindings 0.2.1 with the approved 0.2.4 fork |
| bindings base | Published `tree-house-bindings` 0.2.4 source commit `eba8670857365ff6dd4560d1f2e8df770c2c795a` |
| static grammar API | Bindings 0.2.4 provides `TryFrom<tree_sitter_language::LanguageFn> for Grammar` behind `tree-sitter-language` |
| random backend | `tempfile 3.20.0` gates its `getrandom 0.3.1` dependency to `cfg(any(unix, windows, target_os = "wasi"))`, which excludes Motor; no backend cfg is needed |
| image placement | Development image only: binary `/devtools/helix/hx`, runtime `/devtools/helix/runtime` |

Do not introduce Termina from newer Helix. This release already uses the
crossterm backend, event stream, styling, and conversion types throughout.
The only terminal capability dependency needing a Motor seam is Termini,
which is used for terminfo lookup and depends on the Unix-oriented `home`
crate.

## Invariants for all three stages

- No changes under `src/sys`, the Rust standard library, or `moto-rt`. If one
  appears necessary, stop and request review.
- Keep Linux, macOS, and Windows behavior unchanged. Motor-specific cfgs must
  not replace or weaken an existing host implementation.
- Motor artifacts are static PIE. Do not add `-crt-static`; the
  `motor-rust-cc` linker wrapper supplies the correct static-PIE link mode.
- All Motor builds are cross-builds on the Linux host. Do not add or test a
  native on-Motor Helix build path.
- No grammar fetch, Cargo registry access, or Git network access occurs in a
  regular test. Network acquisition is a distinct setup/build action, after
  which all Cargo test/build commands use `--locked --offline`.
- Never stage grammar Git checkouts, `.git` data, shared libraries, build
  directories, user configuration, or caches into an image.
- Do not enable Helix's `git` feature on Motor.
- Mouse support, suspend/job control, external URL launch, system clipboard,
  OSC 52, and LSP integration are unavailable in v1. Each must fail or
  default cleanly rather than partially activate.
- Do not add retries, longer timeouts, ignored failures, or fallback writes.
  A failed safety step must fail the build, test, or save operation visibly.
- Agents do not create GitHub forks, push branches, open pull requests, or
  otherwise mutate GitHub state. A human owns all remote publication.
- Agents may create local commits only if the user separately authorizes
  commits. Otherwise the human creates the publication commits at handoff;
  local editing and validation do not imply commit authorization.

## Repository ownership and publication workflow

The implementation uses three local working repositories:

| Path | Owner of changes | Purpose |
| --- | --- | --- |
| `./` | Agent edits locally | Motor OS assembly, image, and VM-test integration |
| `../helix` | Agent edits locally | Helix 25.07.1 Motor port and static grammars |
| `../tree-house` | Agent edits locally | Approved bindings 0.2.4 Motor cfg patch |

Do not assume those exact directories are disposable. Before cloning, inspect
any existing sibling path and its worktree status. Reuse a clean checkout or
ask before choosing a different path; never reset, clean, overwrite, or
delete an existing checkout.

### Human bootstrap before implementation

The human performs all GitHub mutations at the beginning:

1. Create `github.com/moturus/helix` from `helix-editor/helix`.
2. Create `github.com/moturus/tree-house` from
   `helix-editor/tree-house`.
3. Confirm that agents have read/clone access to both forks. No write token is
   required or to be requested by an agent.

After bootstrap, an agent may `git clone` or `git fetch` into the sibling
paths, create local branches, and modify files in `../helix`,
`../tree-house`, and `./`. The agent must not push any local branch.

### Local implementation before publication

The bindings commit does not exist on GitHub while local implementation is in
progress. During this phase:

1. Develop and test the approved bindings patch in `../tree-house`.
2. In `../helix`, use an explicitly temporary path override to
   `../tree-house/bindings`. Keep that override in the local working tree
   only; do not describe it as the final dependency pin and do not fabricate
   a Git revision in `Cargo.lock`.
3. Build and test Helix directly from `../helix`. Stage its output manually
   for Stage 2 VM smoke tests.
4. Implement Stage 3 glue and run its focused mocked tests, but defer the
   managed-GitHub-checkout, reusable assembly, and complete developer-image
   gates until the remote Helix revision exists.
5. Maintain a short handoff checklist of every temporary path, local source
   override, and deferred gate. No absolute sibling path may remain in a
   publication commit or generated manifest.

Local path testing is provisional. A stage is not finally complete until the
same source trees have been fetched through their GitHub URLs and the stated
remote-source gates pass.

### Human publication and agent cutover

Publication at the end is a deliberate handoff, with all pushes performed by
the human:

1. The human commits the completed `../tree-house` branch locally. With no
   tracked or staged changes left over, the agent reruns its focused gates
   against that commit and records both `git rev-parse HEAD` and
   `git rev-parse HEAD^{tree}`.
2. The human pushes that exact tree-house commit. The agent fetches the branch
   read-only from GitHub, verifies both the fetched commit and its tree match
   the recorded values, records the full bindings revision, replaces Helix's
   temporary path override with the final GitHub URL plus `rev`, regenerates
   `Cargo.lock`, and repeats the bindings and Helix Stage 1-2 gates.
3. The human commits the finalized `../helix` branch locally, including the
   GitHub bindings pin and lockfile. With no tracked or staged changes left
   over, the agent records its commit and tree identities and confirms the
   final Helix gates still pass. The human then pushes that exact commit.
4. As the agent's final implementation step after all sibling changes are on
   GitHub, fetch both branches read-only, verify the remote commits and trees
   against the recorded local values, set the Motor OS `HELIX_REV` to the
   pushed Helix commit, and remove every local-source override.
5. From a fresh managed checkout and a new assembly key/output directory,
   repeat the dependency graph, host checks, Motor build and ELF checks,
   assembly reuse/tamper checks, focused VM suite, and
   `src/tests/full-test-dev.sh --release`. This is the authoritative result;
   earlier local-source results are supporting evidence only.

If either pushed tree differs from the locally tested tree, stop before
updating downstream revisions. Review the diff, retest the changed tree, and
require the human to publish any resulting sibling-repository correction.

## Repeated command conventions

### Host commands

Run every Helix Cargo command with the sibling Helix checkout as the working
directory; Cargo does not discover `../helix/.cargo/config.toml` merely from
a `--manifest-path` passed while standing in the Motor repository. After
Patch 1.1, use the fork's 1.90.0 toolchain pin. All ordinary host checks run
without grammar acquisition:

```sh
HELIX_DISABLE_AUTO_GRAMMAR_BUILD=1 cargo +1.90.0 test --workspace --locked --offline
HELIX_DISABLE_AUTO_GRAMMAR_BUILD=1 cargo +1.90.0 clippy --workspace --all-targets --locked --offline
cargo +1.90.0 fmt --all --check
```

The initial dependency refresh and the explicit grammar fetch are allowed to
use the network. Once `Cargo.lock` and grammar checkouts exist, repeat all
build and test commands offline. Review clippy output for warnings introduced
by the fork; do not hide warnings with crate-wide `allow` attributes.

### Motor cross commands

Use the repository-selected Motor tools and an assembly-local target
directory. The variable values come from `src/build-motor-os.sh`; do not
commit absolute developer-machine paths to the Helix fork.

```sh
env \
  RUSTC="$MOTOR_RUSTC" \
  RUSTDOC="$MOTOR_RUSTDOC" \
  CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER="$SYSROOT/bin/motor-rust-cc" \
  CC_x86_64_unknown_motor="$SYSROOT/bin/motor-clang" \
  CXX_x86_64_unknown_motor="$SYSROOT/bin/motor-clang++" \
  CXXSTDLIB_x86_64_unknown_motor="c++" \
  AR_x86_64_unknown_motor="$B/llvm-ar" \
  ARFLAGS_x86_64_unknown_motor="" \
  CARGO_TARGET_DIR="$ASSEMBLY_BUILD_ROOT/helix" \
  HELIX_DEFAULT_RUNTIME=/devtools/helix/runtime \
  HELIX_DISABLE_AUTO_GRAMMAR_BUILD=1 \
  "$MOTOR_CARGO" build \
    --target x86_64-unknown-motor \
    --release --locked --offline --no-default-features \
    -p helix-term --bin hx
```

During Stage 1 cross-checks, add `DISABLED_TS_BUILD=1`. Remove that variable
from the full-link command after the static grammars land in Stage 2. Do not
use it in the final assembly build.

For a Stage 1 full-workspace check, use the same environment but replace the
last Cargo invocation with:

```sh
"$MOTOR_CARGO" check \
  --workspace --target x86_64-unknown-motor \
  --exclude xtask --locked --offline --no-default-features
```

The workspace includes `xtask`, host-only release tooling which depends on
`helix-term` with its default features. Exclude it unconditionally from every
Motor `--workspace` command: otherwise that dependency edge re-enables
Helix's `git` feature despite `--no-default-features`. Record the exclusion in
`MOTOR.md`; do not modify xtask itself. References below to a full-workspace
Motor check mean this workspace-minus-xtask command.

`DISABLED_TS_BUILD=1` only suppresses tree-house-bindings' vendored C build.
It does not remove its unconditional `libloading` import. Complete
Prerequisite 0 before the first full-workspace Motor check.

After Patch 1.1, `.cargo/config.toml` differs from upstream only by dropping
`-C target-feature=-crt-static`; its `cfg(all())` entry, including
`--cfg tokio_unstable`, applies to the Motor target unchanged. No getrandom
backend cfg exists: the locked `tempfile 3.20.0` gates its `getrandom 0.3.1`
dependency to `cfg(any(unix, windows, target_os = "wasi"))`, which excludes
Motor. `CXXSTDLIB_x86_64_unknown_motor=c++` is part of the convention
because `cc` otherwise emits `stdc++` link metadata for targets it does not
recognize, while the Motor sysroot provides libc++ — the library
`motor-rust-cc` already places in its default link group.

At the Stage 1 exit gate, save and inspect this target-filtered graph:

```sh
"$MOTOR_CARGO" tree \
  --target x86_64-unknown-motor --locked --offline \
  --no-default-features -p helix-term -e normal
```

During provisional local work, this graph may identify
`tree-house-bindings` as the `../tree-house/bindings` path dependency. That
result validates the code and target dependency shape, but is not a Stage 1
exit result. After the human publishes the bindings fork, repeat the command
with the temporary path override removed. The authoritative graph must show
only the exact pinned Tokio 1.47.1, mio 1.0.4, crossterm 0.29.0, and approved
tree-house-bindings 0.2.4 Git revisions. It must not contain a path or
registry copy of those packages, nor `libloading`, Termini, `home`,
`signal-hook`, `signal-hook-tokio`, or `open`. The graph must not contain
`getrandom 0.3.1` either: its only dependent, `tempfile`, gates that
dependency to `cfg(any(unix, windows, target_os = "wasi"))`, which excludes
Motor.

## Prerequisite 0 — approved bindings fork

The user approved this dependency-port task on 2026-08-31. A human creates
`github.com/moturus/tree-house`; the agent then works locally in
`../tree-house`, branching from upstream commit
`eba8670857365ff6dd4560d1f2e8df770c2c795a` (the source revision recorded by
the published `tree-house-bindings` 0.2.4 crate). Use local branch
`tree-house-bindings-motor-0.2.4_2026-08-31`. The agent must not create the
GitHub fork or push the branch.

The approved fork patch is limited to the following:

1. Keep the package version at 0.2.4 and all tree-sitter ABI/parser code
   unchanged.
2. Make `libloading` a dependency only for
   `cfg(not(target_os = "motor"))`.
3. In `bindings/src/grammar.rs`, cfg-gate `Library`, `Symbol`,
   `Path`/`PathBuf`, `Grammar::new`, and the `DlOpen`/`DlSym` error variants
   off Motor.
4. Keep the `tree-sitter-language` feature and
   `TryFrom<LanguageFn> for Grammar` available on Motor.
5. Retain and run upstream host tests for the dynamic constructor. Add a
   focused static-constructor test using a test grammar, and cross-check the
   crate for Motor with `DISABLED_TS_BUILD=1`.
6. Verify with `cargo tree --target x86_64-unknown-motor` that `libloading`
   is absent from the target graph.
7. Before publication, record the locally tested tree identity. After the
   human push, record the full 40-character GitHub commit and verify its tree
   matches before using it in Helix. If the work takes more than the
   cfg/dependency change above, stop and review the expanded scope.

Do not fork tree-house 0.3.0 itself and do not backport the static constructor
by hand to bindings 0.2.1. The compatible 0.2.4 release already supplies that
API and minimizes the dependency delta.

## Stage 1 — fork and editor bring-up

All patches in this stage are made in the sibling Helix fork checkout, not in
the Motor OS repository.

### Patch 1.1 — exact baseline and reproducible dependencies

Files: `rust-toolchain.toml`, `.cargo/config.toml`, root `Cargo.toml`,
`Cargo.lock`, `languages.toml`, and new `MOTOR.md`.

1. Confirm the sibling checkout is clean. Clone it if absent, or configure
   upstream and Moturus fork remotes in an existing clean checkout. Fetch
   read-only, verify
   `git rev-parse HEAD == a05c151bb6e8e9c65ec390b0ae2afe7a5efd619b`, and create
   `helix-motor-25.7.1_2026-08-31` directly from that commit. Do not reset,
   clean, or overwrite a dirty checkout, and do not push the local branch.
2. Change the upstream Rust pin from 1.82.0 to 1.90.0, retaining `rustfmt`,
   `rust-src`, and `clippy`. This is required by crossterm 0.29's Rust 1.85
   minimum and makes host formatting reproducible. Do not remove the pin.
3. In `.cargo/config.toml`, remove only
   `-C target-feature=-crt-static` from the existing `cfg(all())` flags,
   leaving `--cfg tokio_unstable` in place. Add no Motor-specific
   `rustflags` entry: `cfg(all())` matches the Motor target as well (Cargo
   joins matching cfg and exact-target entries; neither overrides the
   other), and no getrandom backend cfg is needed because the locked
   `tempfile 3.20.0` gates its `getrandom 0.3.1` dependency to
   `cfg(any(unix, windows, target_os = "wasi"))`, which excludes Motor. Do
   not add a linker path to this file:

   ```toml
   [target."cfg(all())"]
   rustflags = ["--cfg", "tokio_unstable"]
   ```
4. Pin Tokio to
   `f9d26ea874753c0b5126401e77daee9e6222c359` and mio to
   `907466acd6bd9fcccfb4f9c097dcda60c55157c4` through
   `[patch.crates-io]`. Tokio must resolve as 1.47.1 and mio as 1.0.4. Do not
   update the Motor repository's global Tokio pin as part of this port.
5. Keep `tree-house` exactly at 0.3.0 and update the resolved bindings version
   from 0.2.1 to 0.2.4. During local implementation, add a clearly marked
   temporary `[patch.crates-io]` path override to
   `../tree-house/bindings`. After the human publishes the bindings fork,
   replace that path override with
   `tree-house-bindings = { git = "https://github.com/moturus/tree-house.git", rev = "<full pushed revision>" }`.
   Reject any update to tree-house 0.4 or bindings 0.3, and reject a path,
   `file:` URL, branch-only source, or absolute local path in the finalized
   Helix tree.
6. In the local phase, regenerate only affected lockfile entries and permit
   Cargo's normal path-source representation only as provisional test state.
   Do not hand that lockfile to the human as publication-ready. After the
   bindings push, regenerate the affected entries during an explicitly
   online source-cutover step, then repeat all Cargo commands offline.
   Inspect both lock diffs and reject unrelated dependency churn. The final
   lockfile must record every full Git source revision; branch names are
   documentation, not build identity.
7. Change the top-level grammar selection to:

   ```toml
   use-grammars = { only = [
     "rust", "toml", "markdown", "markdown_inline", "c", "cpp",
     "json", "yaml", "bash", "lua",
   ] }
   ```

   `markdown_inline` is the grammar name; `markdown.inline` remains the
   language ID. Do not use `markdown-inline`.
8. Add `MOTOR.md` with the exact offline host and Motor command templates,
   the explicit grammar acquisition command from Stage 2, image paths, base
   and final commit terminology, unsupported v1 features, the
   cross-compile-only build scope (no native on-Motor builds), and the
   human-publication workflow. State that agents may clone/fetch and edit the
   three local repositories but may not create forks or push, and that no
   temporary path source is allowed in the published Helix commit.

Local gate: run the host command set with auto grammar building disabled and
the temporary bindings path override. No grammar source directory is
required and no test may access the network. Inspect `git diff --check` and
the provisional lockfile diff.

Post-bindings-publication gate: fetch the human-pushed bindings commit,
verify its Git tree equals the tested local tree, replace the path override
with its full GitHub revision, regenerate the lockfile, and repeat the host
and Motor Stage 1 gates offline. Inspect `git diff --check`, the final
lockfile diff, and the target-filtered graph; no local-source reference may
remain.

### Patch 1.2 — explicit no-dlopen seam and truthful health output

Files: `helix-loader/src/grammar.rs`, `helix-term/src/health.rs`, and focused
tests.

1. Keep `DYLIB_EXTENSION`, shared-library path construction, and
   `unsafe Grammar::new` under `cfg(not(target_os = "motor"))`.
2. On Motor, make `get_language` return `Ok(None)` temporarily. Patch 2.3
   replaces this branch with the static registry; Stage 1 must not imply that
   syntax highlighting already works.
3. On Motor, make `fetch_grammars` and `build_grammars` return a clear
   unsupported error. They must never attempt Git or shared-library creation
   in a Motor process. Preserve host fetch/build/load behavior.
4. Backport the release health fix exactly in behavior: only `Ok(Some(_))`
   prints `Tree-sitter parser: ✓`; `Ok(None)` and `Err(_)` print `None`.
   Release 25.07.1 currently matches `Ok(_)`, producing a false success for a
   missing grammar.
5. Factor only the small target-independent resolver/status helpers required
   for tests. Cover a loaded grammar, missing grammar, and loader error. Do
   not redesign the health command.

Gate: host command set, then the Motor check for `helix-loader` with
`DISABLED_TS_BUILD=1`. It must compile without a fake Motor dynamic-library
suffix.

### Patch 1.3 — make `helix-stdx` correct on Motor

Files: `helix-stdx/src/faccess.rs`, `helix-stdx/src/env.rs`, and unit tests.

1. Fix the generic non-Unix/non-Windows `faccess` implementation instead of
   treating it as working code: it contains `&path` (a nonexistent type) and
   omits `hardlink_count` entirely.
2. For Motor, implement `access` and `copy_metadata` with standard Rust
   metadata and permissions. `EXISTS` performs metadata lookup; `READ`
   attempts to open the path; `WRITE` rejects read-only permissions; and
   `EXECUTE` returns `Unsupported` because Motor's standard metadata does not
   expose executable bits. Apply every requested flag rather than returning
   after the first successful one. Metadata copying preserves the permission
   object. Helix's current runtime caller uses only the `WRITE` check for
   `readonly`.
3. Make Motor `hardlink_count` return an explicit `Unsupported` error. Do not
   invent a count. Patch 1.6 supplies a save path that does not call it.
4. Do not use the `which` crate on Motor: its generic backend considers every
   path non-executable. Add a small pure helper used by `env::which` and
   `binary_exists` on Motor:
   - if the input contains a path separator, test that exact path;
   - otherwise iterate a supplied PATH list with `std::env::split_paths`;
   - accept only `metadata.is_file()`;
   - return the existing `ExecutableNotFoundError` when no candidate exists.
5. Unit-test direct paths, PATH lookup order, directories being rejected,
   missing entries, and missing/empty PATH. Pass a synthetic PATH list to the
   helper so host tests do not mutate global environment concurrently.

Gate: host command set, then the Motor cross-check for `helix-stdx` with
`DISABLED_TS_BUILD=1`.

### Patch 1.4 — update the existing crossterm backend for Motor

Files: root `Cargo.toml`, `Cargo.lock`, `helix-tui/Cargo.toml`,
`helix-view/Cargo.toml`, `helix-term/Cargo.toml`,
`helix-tui/src/backend/crossterm.rs`, and the existing conversion tests.

1. Pin crossterm to
   `94317189d1be68cd409d13380b8f4f94af9bc08c`, the `motor-os-support` head
   that `src/sys/Cargo.lock` already pins, and update every direct
   requirement from 0.28 to 0.29. Use `default-features = false`. This
   branch has been rebased before; confirm the head still matches the
   Motor OS lockfile before pinning, and stop if they diverge.
2. Enable the common features actually used by Helix: `events`,
   `event-stream`, and `bracketed-paste`, with `event-stream` needed only by
   `helix-term`. Preserve crossterm's `windows` feature for Windows. Preserve
   the macOS `use-dev-tty` behavior, but remove the obsolete crossterm 0.28
   `libc` feature when moving to 0.29. Do not enable `windows`,
   `use-dev-tty`, `derive-more`, or OSC 52 for Motor unless a compile error
   proves an already-used API requires it.
3. Keep the existing crossterm backend and `cfg(feature = "crossterm")`
   conversion architecture. Unlike newer Helix, this release needs no
   platform backend-selection rewrite.
4. Make both Termini dependencies host-only with
   `cfg(not(target_os = "motor"))`. In the backend, cfg the `TermInfo` import,
   `term_program`, `vte_version`, `reset_cursor_approach`, and terminfo lookup
   off Motor.
5. On Motor, construct conservative capabilities directly: ANSI cursor reset,
   no terminfo-derived extended underline support, with the explicit
   `undercurl` editor configuration override still honored. Preserve the
   existing Termini behavior byte-for-byte on hosts.
6. Apply the 0.28-to-0.29 API changes narrowly in crossterm backend and
   conversion code. Do not import Termina or copy the newer HEAD backend.
7. Extend conversion/backend tests for key press/release, `C-c`, resize,
   paste, focus, colors, modifiers, underline fallback, claim, and restore.
   Factor pure capability helpers where necessary so host tests exercise the
   Motor-selected defaults.

Gate: host command set; focused `helix-view`/`helix-tui` tests; and Motor
checks for those packages with `DISABLED_TS_BUILD=1`, auto grammar building
disabled, and `--no-default-features`.

### Patch 1.5 — lifecycle, signals, true color, and external URLs

Files: `helix-term/Cargo.toml`, `helix-term/src/main.rs`,
`helix-term/src/application.rs`, `helix-term/src/commands.rs`,
`helix-term/src/lib.rs`, and focused tests.

1. Under `cfg(target_os = "motor")`, call
   `crossterm::event::enable_ctrl_c_events()` in `main_impl` immediately
   before `Application::new`. This follows argument-only exits, configuration
   loading, and grammar/health commands, but precedes backend claim,
   capability probes, event reads, and `EventStream::new`. Propagate failure
   with context; never ignore it.
2. Put `signal-hook`, `signal-hook-tokio`, and signal-only `libc` dependencies
   under `cfg(not(any(windows, target_os = "motor")))`.
3. Use the existing empty `Signals` stream for
   `cfg(any(windows, target_os = "motor"))`. Guard signal construction,
   imports, handlers, and integer signal matches with the complementary cfg,
   not only the imports.
4. Compile the `suspend` implementation which raises `SIGTSTP` only on
   non-Windows, non-Motor targets. On Motor the command returns a clear
   unsupported status/message and must not panic. Leave the default `C-z`
   mapping intact so the behavior is discoverable.
5. Move the `open` crate dependency off Motor with a target-specific manifest
   section. Add a Motor `open_external_url_callback` with the same return type
   as the host implementation which reports that URL launching is
   unsupported. Do not spawn a shell or guess a browser.
6. Split `true_color()` so the existing Windows and host Termini branches are
   unchanged. The Motor branch checks only
   `COLORTERM=truecolor|24bit`, otherwise returning false. User configuration
   may still force true color.
7. Preserve backend `claim`, `reconfigure`, `restore`, panic cleanup,
   synchronized drawing, cursor, and resize paths. Add no startup work outside
   `hx`; this port must not affect Motor boot latency.
8. Test Ctrl+C setup ordering through a small injectable helper, empty signal
   behavior, ignored key-release events, resize conversion, unsupported
   suspend/URL results, true-color environment parsing, and restore after an
   injected error.

Gate: host command set and the first full-workspace Motor cross-check with
the approved bindings fork, `DISABLED_TS_BUILD=1`, auto grammar building
disabled, and `--no-default-features`.

### Patch 1.6 — safe Motor saves

Files: `helix-view/src/document.rs` and focused save tests. Keep the existing
Unix and Windows tempfile/rename implementation unchanged.

The release save path silently proceeds without a backup when `tempfile`
fails, which it does on Motor. Add a Motor-only helper with these semantics:

1. Resolve the existing symlink and read-only checks before entering the
   helper, as current code does.
2. If the target does not exist or atomic-save is disabled, use the current
   direct write behavior. If an existing target must be protected, create a
   same-directory backup with `OpenOptions::create_new(true).write(true)`.
3. Construct one unambiguous backup name from the target filename, process
   ID, and a process-local `AtomicU64` sequence. Build it as an `OsString` so
   no lossy UTF-8 conversion changes the target name. Make one `create_new`
   attempt. A collision aborts without touching the target; do not retry or
   overwrite a pre-existing path.
4. Copy the original through the already-created backup file handle and
   `sync_all` that handle before modifying the original. Perform blocking
   `std::fs` creation/copy/restore work inside `tokio::task::spawn_blocking`;
   propagate both join and I/O failures.
5. Truncate, write, and sync the original inode. This deliberately preserves
   hardlink and metadata behavior without needing a link count.
6. On success, remove the backup. Failure to remove it is reported rather
   than hidden.
7. On write or sync failure, truncate and restore the original from the
   backup, then sync it. If restoration succeeds, remove the backup and
   return the original write error. If restoration fails, retain the backup
   and return an error containing both failures and the exact recovery path.
8. Factor the operation so host tests can inject the write and restore
   closures. Test successful replacement and cleanup; an existing backup-name
   collision without clobber; partial write followed by full restoration;
   restore failure retaining the backup; permissions preservation; and two
   hardlinked names still referring to the updated inode.

Gate: focused save tests first, then the host command set and full-workspace
Motor cross-check. Stop if Motor's standard filesystem behavior cannot meet
any step; never fall back to an unprotected write.

### Patch 1.7 — keyboard-only defaults and clipboard behavior

Files: `helix-view/src/editor.rs`, `helix-view/src/clipboard.rs`, and unit
tests.

1. Make the default editor config set `mouse = false` only on Motor. User
   configuration may explicitly enable it, but v1 acceptance uses a clean
   configuration and must emit no mouse-enable sequences.
2. Add a Motor-specific `Default for ClipboardProvider` returning
   `ClipboardProvider::None`, and exclude Motor from the generic
   non-Windows/non-macOS implementation. This prevents its `term` fallback
   from selecting OSC 52.
3. Put the `Termcode` variant, OSC 52 module, crossterm command
   implementation, and every associated match arm under
   `cfg(all(feature = "term", not(target_os = "motor")))`.
4. Do not create an internal clipboard provider. Helix's ordinary named and
   unnamed registers already work. System clipboard registers `+` and `*`
   retain their unsupported behavior.
5. Unit-test the Motor decisions through small target-independent helpers:
   mouse default is false, clipboard selection is `None`, and no Termcode or
   OSC 52 command is selected.

Gate: host command set and final Stage 1 full-workspace Motor cross-check with
`DISABLED_TS_BUILD=1`. Save and inspect the target-filtered dependency graph.

### Stage 1 exit criteria

- The human-pushed bindings commit has the same Git tree as the locally
  tested bindings tree, and Helix contains no path or `file:` source override.
- Host workspace tests pass offline with auto grammar building disabled.
- The Motor full-workspace check passes with grammar C compilation disabled,
  `--no-default-features`, and no new warning from the fork's changes.
- Tokio 1.47.1, mio 1.0.4, crossterm 0.29.0, and bindings 0.2.4 resolve only
  from their exact pinned Git revisions.
- The Motor graph contains none of the forbidden host-only dependencies.
- No link or health output has yet claimed syntax highlighting works.
- Ctrl+C setup, signals, URL failure, safe saves, PATH lookup, mouse default,
  clipboard default, and truthful missing-parser health output have focused
  coverage.

## Stage 2 — static tree-sitter grammars and a complete binary

The approved Prerequisite 0 code must already pass its focused tests. Stage 2
may be implemented locally while Helix resolves it through the explicitly
temporary `../tree-house/bindings` path. Do not change the dependency fork
while adding the static registry. Stage 2 is not finally complete until the
human-pushed bindings tree has been verified, Helix uses its exact GitHub
revision, and all Stage 1-2 gates have been repeated with that remote source.

### Patch 2.1 — explicit, revision-checked grammar acquisition

Files: `languages.toml`, `Cargo.lock`, `MOTOR.md`, and the validation table
introduced with the static registry in Patch 2.2.

First fetch Rust dependencies in an explicitly online setup action:

```sh
cargo +1.90.0 fetch --locked
```

Then run this release's `hx-loader` source fetcher. `--offline` prevents
Cargo network access; child Git operations are the intentional grammar source
acquisition:

```sh
HELIX_DISABLE_AUTO_GRAMMAR_BUILD=1 \
  cargo +1.90.0 run --locked --offline -p helix-loader --bin hx-loader
```

The selected sources must resolve to this exact release table:

| Grammar | Repository subpath | Commit |
| --- | --- | --- |
| `rust` | repository root | `1f63b33efee17e833e0ea29266dd3d713e27e321` |
| `toml` | repository root | `7cff70bbcbbc62001b465603ca1ea88edd668704` |
| `markdown` | `tree-sitter-markdown` | `62516e8c78380e3b51d5b55727995d2c511436d8` |
| `markdown_inline` | `tree-sitter-markdown-inline` | `62516e8c78380e3b51d5b55727995d2c511436d8` |
| `c` | repository root | `7175a6dd5fc1cee660dce6fe23f6043d75af424a` |
| `cpp` | repository root | `56455f4245baf4ea4e0881c5169de69d7edd5ae7` |
| `json` | repository root | `73076754005a460947cafe8e03a8cf5fa4fa2938` |
| `yaml` | repository root | `0e36bed171768908f331ff7dff9d956bae016efb` |
| `bash` | repository root | `487734f87fd87118028a65a4599352fa99c9cde8` |
| `lua` | repository root | `88e446476a1e97a8724dff7a23e2d709855077f2` |

The registry build must fail before compiling if a checkout is missing, its
`git rev-parse HEAD` differs, its configured subpath is absent, or
`src/parser.c` is absent. Report the grammar, expected revision, observed
revision/path, and acquisition command. This check is local and must not
fetch. Emit `cargo:rerun-if-changed` for the source and checkout HEAD. For a
grammar ID `G`, resolve from `runtime/grammars/sources/G`, append the table's
repository subpath when it is not `repository root`, and only then append
`src/parser.c`, `src/scanner.c`, or `src/scanner.cc`. Do not infer the two
Markdown layouts from their language IDs.

### Patch 2.2 — add `helix-static-grammars`

Files: root workspace `Cargo.toml`, new
`helix-static-grammars/{Cargo.toml,build.rs,grammar_definitions.rs,src/lib.rs}`,
and focused tests.

1. Add a workspace crate with `default = []` and a `static-grammars` feature.
   Without the feature, its build script performs no source validation or C
   compilation, its library declares no external grammar symbols, and
   `get` returns `None`. `NAMES` may still expose the curated name list for
   validation. This keeps an ordinary host workspace test and link
   independent of grammar acquisition.
2. Encode the ten grammar IDs, generated C symbol names, expected revisions,
   and source subpaths once in `grammar_definitions.rs`; include that file
   from the build script and library so they cannot drift. Expose only the
   names publicly. Keep `markdown` and `markdown_inline` separate even though
   they share a repository and revision.
3. With `static-grammars` enabled, compile each `src/parser.c` and optional
   `src/scanner.c` into a uniquely named static archive with `cc`. If a
   grammar has `src/scanner.cc`, compile it separately with
   `cc::Build::cpp(true)` and a second unique archive; never compile
   `parser.c` as C++. Add that grammar's `src` directory as the include path
   for `tree_sitter/parser.h`.
4. Do not let `cc` pick the C++ standard library for Motor: for a target it
   does not recognize it emits `stdc++` link metadata, and the Motor sysroot
   provides libc++, not libstdc++. The command convention's
   `CXXSTDLIB_x86_64_unknown_motor=c++` makes it emit `c++` instead, which
   `motor-rust-cc` already links in its default group; the duplicate is
   harmless. Do not hard-code a standard library in `build.rs`. Honor
   Cargo's profile optimization and the `CC_`, `CXX_`, `AR_`, `ARFLAGS_`,
   and `CXXSTDLIB_` environment from the command convention.
5. Never invoke the release's shared-library grammar builder for a Motor
   target. `helix-term/build.rs` must inspect `CARGO_CFG_TARGET_OS=motor` and
   skip its fetch/shared-build path; normal commands still set
   `HELIX_DISABLE_AUTO_GRAMMAR_BUILD=1` as defense in depth.
6. In `src/lib.rs`, declare each generated symbol as
   `unsafe extern "C" fn() -> *const ()`, and construct its value with the
   exact 0.1.5 API:
   `unsafe { tree_sitter_language::LanguageFn::from_raw(symbol) }`. The safety
   comment states that each symbol is emitted by the revision-checked
   tree-sitter parser and has that ABI. Do not transmute pointers.
7. Expose only `pub const NAMES: &[&str]` and
   `pub fn get(name: &str) -> Option<LanguageFn>`. Stop if the actual pinned
   API cannot represent the generated symbols as planned. Put every extern
   declaration and symbol-returning match arm behind `static-grammars`; an
   unused external declaration must not leak into the feature-free host link.
8. Enable `static-grammars` on the target-specific dependency from
   `helix-loader` only for Motor. A dedicated host grammar-test invocation
   also enables it; the ordinary host workspace remains feature-free.
9. After explicit acquisition, test exact names, unknown-name rejection,
   conversion of every function to `tree_house::tree_sitter::Grammar`, and
   parsing a short fixture without an error or missing node. Exercise both
   Markdown grammars.

Dedicated host gate after grammar acquisition:

```sh
HELIX_DISABLE_AUTO_GRAMMAR_BUILD=1 \
  cargo +1.90.0 test --locked --offline \
    -p helix-static-grammars --features static-grammars
```

### Patch 2.3 — select static grammars in `helix-loader`

Files: `helix-loader/Cargo.toml`, `helix-loader/src/grammar.rs`, and loader
tests.

1. Add an exact target-specific Motor dependency on
   `tree-house-bindings = "=0.2.4"` with `tree-sitter-language` enabled. This
   activates the conversion on the same package instance re-exported by
   tree-house 0.3.0; do not add a second bindings version.
2. Keep the host `DYLIB_EXTENSION`, path construction, and
   `unsafe Grammar::new` behavior-identical.
3. Replace the temporary Motor `Ok(None)` branch with lookup through
   `helix_static_grammars::get`, conversion using `Grammar::try_from`, and
   `Ok(Some(grammar))`. An unselected grammar returns `Ok(None)`, matching the
   host missing-library behavior, never a panic. Query loading remains in
   `helix-core/src/syntax.rs`; do not duplicate or move it into the registry.
4. Add target-independent resolver tests for every curated name and an
   unknown name. The direct parser tests are the primary correctness gate;
   later `hx --health` checks prove the same path in a Motor process.

Gate: ordinary host command set, dedicated static-grammar tests, then a
full-workspace Motor check without `DISABLED_TS_BUILD`.

### Patch 2.4 — full Motor link and ELF validation

Run the full Motor release build command with no `DISABLED_TS_BUILD`. Check
the unstripped binary, strip it with the assembly's LLVM strip tool, and
repeat the checks on the stripped result:

- ELF type is `DYN` (static PIE);
- there are no `NEEDED` dynamic-library entries;
- `GNU_STACK` is not executable;
- there is no `PT_TLS`/`TLS` program header, which the Motor loader rejects;
- there are no unresolved symbols, including `dlopen`, `dlsym`, grammar
  functions, or C++ runtime symbols.

Do not require `.init_array` merely because another port did; validate only
requirements established for this binary.

Before assembly integration, stage the binary and runtime into a temporary
directory with the final layout and boot a disposable development image.
Run `/devtools/helix/hx --version`, open one fixture for every selected
grammar, and save a file. Patch 3.4 owns the persistent VM acceptance test.

### Stage 2 exit criteria

- The temporary bindings path override has been replaced by the verified
  human-pushed GitHub revision, and no local source reference remains.
- The approved bindings fork and all existing Motor runtime forks are
  exact-pinned; the Motor target graph has no dynamic-loading or host terminal
  dependencies.
- Ordinary workspace tests require no grammar checkout and no network.
- Dedicated tests parse fixtures for all ten grammars.
- The stripped Motor `hx` passes every ELF check and starts in a VM.
- Runtime grammar resolution performs no shared-library filesystem lookup.

## Stage 3 — reproducible Motor OS assembly and acceptance tests

All changes in this stage are in the Motor OS repository. Helix is a
non-core component, so use focused tests and the release-only developer-image
gate. Do not run or add a debug developer-image gate without user approval.

Before the Helix fork is published, implement the assembly, imager, and test
logic and run focused tests with test-local fixture revisions and mocked
checkouts. A manual build from `../helix` may be staged only for disposable
VM smoke testing; do not add a permanent local-checkout mode to the Motor
build. The production `HELIX_REV`, managed-checkout gate, assembly reuse
gate, persistent VM acceptance test, and full developer-image gate wait for
the human-pushed Helix commit. No Stage 3 exit criterion is satisfied by the
fixture or manually staged result.

### Patch 3.1 — add Helix to assembly identity and provenance

Files: `src/toolchain-versions.sh`, `src/toolchain-assembly.sh`,
`src/toolchain-lib.sh`, and focused `src/tests/test-toolchain-*.sh` files.

1. Add validation and focused test fixtures for
   `HELIX_REPOSITORY=https://github.com/moturus/helix.git`,
   `HELIX_REF=refs/heads/helix-motor-25.7.1_2026-08-31`, and `HELIX_REV`.
   Test fixtures may inject a clearly test-only 40-character revision. Do not
   put a dummy, upstream-base, sibling-path, or guessed final revision in
   `src/toolchain-versions.sh`. After the human pushes Helix, set the
   production `HELIX_REV` to that exact 40-character Motor-fork commit and
   set the repository/ref above. Validate the repository/ref as nonempty and
   the revision as a full lowercase hash.
2. Bump `MOTOR_ASSEMBLY_KEY_SCHEMA` from `motor-assembly-key-v2` to
   `motor-assembly-key-v3` and include `HELIX_REV` explicitly in
   `toolchain_assembly_key`. Never key reusable output only by a branch.
3. Add `helix_repository`, `helix_ref`, `helix_rev`, and
   `helix_tree_sha256` to produced and consumed manifest checks. Compute the
   tree digest with `toolchain_content_tree_digest` over
   `images/helix/devtools/helix`, authenticating the binary, runtime files,
   symlinks, and executable modes. Recompute and compare it during consumed
   assembly validation; the scalar `hash_paths` loop is insufficient for a
   directory tree.
4. Add `helix` to generated-root iteration and require
   `helix/devtools/helix/hx` during producer completion and consumed assembly
   validation. A missing or tampered runtime tree must change the root hash.
5. Update focused tests:
   - `test-toolchain-versions.sh` for schema v3 and exact Helix variables;
   - `test-toolchain-assembly.sh` for fake root creation, manifest fields,
     tree-digest validation, and separate binary/runtime tamper rejection;
   - `test-toolchain-assembly-selection.sh` for selection and reuse;
   - `test-toolchain-keyed-paths.sh` for a key change when only `HELIX_REV`
     changes;
   - every other test enumerating generated roots or manifest fields, found
     with `rg`.

Local gate: run each changed `src/tests/test-toolchain-*.sh` directly with
its fixture revision. Confirm the mock selection reuses identical inputs and
rejects a changed Helix revision.

Post-Helix-publication gate: set the production GitHub repository, branch,
and pushed revision; fetch it read-only; verify its Git tree matches the
final local Helix tree; then repeat the focused tests. The real assembly
reuse gate is part of Patch 3.2 and must use this remote revision.

### Patch 3.2 — managed checkout, offline build, and staging

File: `src/build-motor-os.sh` and focused shell-test fixtures.

1. Add `HELIX`, `HELIX_IMG`, and `HELIX_TARGET_DIR` beside equivalent
   generated-root variables. Use assembly-scoped paths, never a global Cargo
   target directory.
2. On a non-reused producer path, obtain source through
   `toolchain_managed_checkout` and require `HEAD == HELIX_REV`. Do not
   fast-forward a branch and do not clone or fetch while reusing a validated
   assembly. Exercise this behavior with a mock local Git remote in focused
   tests before publication; do not point production variables at
   `../helix`.
3. Keep dependency and grammar acquisition explicit. Once dependencies and
   revision-checked grammar checkouts exist, invoke Cargo with
   `--locked --offline --no-default-features` and the exact Motor environment
   template above. The assembly build must not set `DISABLED_TS_BUILD`.
4. Set `HELIX_DEFAULT_RUNTIME=/devtools/helix/runtime` at compile time.
5. Re-run ELF checks on the unstripped binary, strip it, and re-run them
   before staging.
6. Stage only:
   - `hx` as `/devtools/helix/hx`, executable;
   - `runtime/queries` as `/devtools/helix/runtime/queries`;
   - `runtime/themes` as `/devtools/helix/runtime/themes`;
   - `runtime/tutor` as `/devtools/helix/runtime/tutor`.
7. Do not add `/devtools/helix` to PATH or install a wrapper/symlink. Tests
   and documentation use the full binary path. Never copy grammar sources,
   `.git` data, or built shared libraries.
8. Add the binary to required assembly outputs before publishing the
   manifest. The generated `helix` root participates in normal atomic
   assembly publish; never write into an already-published root.

Local gate: shell syntax check and focused mocked build/assembly tests. A
manual `../helix` build may support the disposable Stage 2 VM smoke, but it
does not satisfy this patch's assembly gate.

Post-Helix-publication gate: from a new assembly key/output directory, let
`toolchain_managed_checkout` fetch the exact GitHub revision, produce a
release assembly twice, and confirm the second run validates and reuses it.

### Patch 3.3 — development image configuration

Files: `src/imager/motor-os-dev.yaml`, `src/imager/src/main.rs`, and imager
tests. The main-image YAML remains unchanged.

1. Add `helix` to the development image's `assembly_dirs` and
   `helix/devtools/helix/hx` to `assembly_required_executables`.
2. Add `/devtools/helix` and `/devtools/helix/runtime` to development-image
   directory expectations if the YAML requires explicit parents.
3. Update tests asserting exact development-image assembly roots, executable
   count/list, and required directories.
4. Add a negative assertion that the main image does not select the Helix
   root or contain its executable.

Gate: run focused imager tests offline:

```sh
cargo test --manifest-path src/imager/Cargo.toml --locked --offline
```

### Patch 3.4 — VM acceptance in the existing TUI harness

File: `src/tests/test-tui.sh`; add small fixtures only if inline creation
would obscure assertions.

`src/tests/full-test.sh` already invokes `test-tui.sh`, and
`full-test-dev.sh` sets `FULL_TEST_VERIFY_DEV_SOURCES=1`. Put Helix tests in
the existing script under that condition so they reuse one VM and existing
`start_pty`, `wait_pty_output`, `finish_pty`, SSH, and rmux helpers. Do not
add a standalone VM script.

Set `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, and `TMPDIR` to fresh directories
under `/devtools/tmp` so user configuration cannot affect keymaps or
defaults. Invoke `/devtools/helix/hx` by its full path. Add these assertions:

1. `hx --version` exits zero, reports product version 25.07.1 (the release
   build script zero-pads the `25.7.1` Cargo package version's one-digit
   month), and includes the final pinned Motor fork hash. Compare the short
   hash to `HELIX_REV`; do not accept the upstream release hash after Motor
   commits exist.
2. General `hx --health` output includes `/devtools/helix/runtime`. For each
   curated language ID (`rust`, `toml`, `markdown`, `markdown.inline`, `c`,
   `cpp`, `json`, `yaml`, `bash`, and `lua`), run language health and require
   the exact `Tree-sitter parser: ✓` line. Zero status alone is insufficient
   because optional language-server diagnostics are not fatal. Capture these
   health commands without a pty so crossterm does not add color escapes to
   the line being compared.
3. In a forced SSH pty, open a known fixture, enter text, `:wq`, and compare
   the saved file byte-for-byte on the guest.
4. Start a clean session, send literal Ctrl+C, and prove the editor remains
   alive and produces a later redraw/status response before `:q!`. Release
   25.07.1 maps normal-mode `C-c` to `toggle_comments`; do not expect status
   130 or remap the key merely to make the test pass.
5. Start at one pty size, issue a window-size change through the existing
   mechanism, and observe new frame output before sending another key. This
   distinguishes resize handling from a key-triggered repaint.
6. Run `:sh echo HELIX_SHELL_OK` and wait for the unique marker, proving the
   default `sh -c` path works through Rush.
7. With clean configuration, assert the startup stream has none of the mouse
   enable sequences `?1000h`, `?1002h`, `?1003h`, or `?1006h`.
8. On clean exit, assert alternate-screen leave (`ESC[?1049l`) and restoration
   of enabled modes, including bracketed paste when present. The pty process
   must exit zero.
9. Repeat edit/save/clean-exit inside an rmux pane and compare the saved file
   on the guest.

Use existing bounded marker waits and keep `test-tui.sh`'s hard 600-second
self-timeout unchanged. Keep the outer release-suite timeout unchanged as
well. If measured legitimate work cannot fit either existing budget, stop and
report per-phase timings for separate review; do not change a timeout as part
of this patch. Do not add retries, ignore a missing escape sequence, or accept
multiple exit statuses.

Focused gate against the already-built development image:

```sh
FULL_TEST_IMG_TARGET=dev.img \
FULL_TEST_IMAGE=motor-os-dev.qcow2 \
FULL_TEST_IMAGE_PREBUILT=1 \
FULL_TEST_VERIFY_DEV_SOURCES=1 \
  src/tests/test-tui.sh --release
```

Then run the complete required gate:

```sh
src/tests/full-test-dev.sh --release
```

This work is not explicitly Lorry work and changes no `src/sys` component,
so no debug developer-image run and no three-times debug/release core gate is
required. If implementation unexpectedly changes `src/bin/lorry`, ask before
adding a debug developer-image run.

### Stage 3 exit criteria

- The final agent cutover fetched both sibling repositories through GitHub,
  verified that their pushed trees match the locally tested trees, and used
  a fresh managed Helix checkout rather than either `../` worktree.
- No path dependency, `file:` URL, sibling path, test fixture revision, or
  other local-only source reference remains in Helix, `Cargo.lock`, Motor
  version declarations, assembly manifests, or build/test configuration.
- Assembly reuse is keyed by and records the exact Helix revision and full
  staged-tree hash; tampering and revision changes are rejected.
- Only the development image contains `/devtools/helix`.
- The runtime contains queries, themes, and tutor, but no grammar sources,
  Git metadata, or shared objects.
- The release developer-image suite covers SSH pty and rmux editing, safe
  save, resize, Ctrl+C, shell execution, keyboard-only startup, and terminal
  restoration.
- `git diff --check`, relevant shell tests, imager tests, and
  `src/tests/full-test-dev.sh --release` pass with no new warnings.

## Diagnosed release issues

These issues exist at the exact upstream release commit and are now known
inputs, not discoveries to conceal during implementation:

1. `helix-stdx/src/faccess.rs`'s generic non-Unix/non-Windows block uses the
   nonexistent type `&path` and omits `hardlink_count`. Patch 1.3 is the
   narrow compile repair with explicit Motor semantics.
2. `hx --health` treats `Ok(None)` from grammar lookup as success. Patch 1.2
   backports the later corrected match and adds focused coverage.
3. The save path treats backup creation, restoration, metadata copy, and
   backup deletion as best-effort. Motor's tempfile implementation returns
   `Unsupported`, allowing an unprotected truncate. Patch 1.6 supplies a
   Motor-only recovery-safe path and preserves host behavior.
4. The previous release plan proposed patching `libloading` 0.9 over a
   `^0.8` dependency and assumed bindings 0.2.1 had a static constructor.
   Neither is true. Prerequisite 0 uses compatible bindings 0.2.4 and removes
   dynamic loading only on Motor.

If any fix needs behavior beyond what is specified here, stop and report the
expanded scope before continuing.

## Stop conditions

Stop and report evidence before continuing if any of these occurs:

- the bindings patch requires more than the approved cfg/dependency change in
  Prerequisite 0;
- Tokio 1.47.1 does not satisfy the exact release feature union or requires a
  new mio/moto-rt API;
- a standard library, `moto-rt`, kernel, boot-time, or `src/sys` change seems
  necessary;
- any selected grammar source or revision differs from the release table;
- Motor needs `libloading`, a shared object, a runtime dynamic loader, or a
  new unapproved dependency fork;
- the save helper cannot restore data or preserve hardlink semantics;
- the linker emits `NEEDED`, executable stack, `PT_TLS`, or unresolved
  symbols;
- either human-pushed sibling tree differs from its locally tested tree, or a
  downstream file would need to name an unpushed, guessed, or local-only
  revision;
- a pre-existing non-test bug is found beyond the diagnosed issues above;
- an implementation choice is not fixed by this plan and has meaningful
  security, correctness, image-layout, or compatibility consequences.

## Stage 4 — deferred rust-analyzer integration

After native rust-analyzer lands, add Motor language-server defaults and the
Lorry-generated project graph, then test one diagnostic and one hover inside
a VM. Do not guess server path, project format, or staging layout in Stages
1-3.

## Settled user decisions

Answered by the user by 2026-08-31. Do not re-open them without new input.

1. Use a dated, version-qualified Motor branch; reserve `master` for upstream
   PRs.
2. Initial grammars: Rust, TOML, Markdown plus Markdown inline, C, C++, JSON,
   YAML, Bash, and Lua.
3. Package Helix only in the development image under `/devtools/helix/`.
4. Call Motor crossterm's `enable_ctrl_c_events()` before event reading so
   `C-c` reaches Helix; quit with `:q`.
5. V1 has ordinary internal registers only. System clipboard and OSC 52 are
   deferred.
6. The narrow bindings 0.2.4 fork in Prerequisite 0 is approved. Any other
   dependency fork requires separate review and approval.
7. Compile grammars from exact `languages.toml` revisions in an explicit
   source-acquisition step, never a regular test.
8. Base the port on Helix release 25.07.1, pinned exactly to
   `a05c151bb6e8e9c65ec390b0ae2afe7a5efd619b`; never build from a moving ref.
9. A human creates GitHub forks and performs every push. Agents clone/fetch
   read-only, work locally in `../tree-house`, `../helix`, and `./`, then
   replace local refs with pushed GitHub revisions and perform the final
   clean remote-source retest.

## Definition of done for Stages 1-3

Stages 1-3 are complete only when every stage exit criterion is met, the
approved dependency and final Helix revisions are exact-pinned, all patches
remain reviewable, the release developer-image gate passes, and working
trees contain no unrelated changes. Both exact revisions must fetch from
GitHub and match the locally tested trees; no local source override or
temporary revision may remain. Stage 4 is expressly excluded.
