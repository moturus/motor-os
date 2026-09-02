# Helix 25.07.1 on Motor OS — implementation record

Stages 1-3 of the Helix port are complete. They were implemented and validated
between 2026-08-31 and 2026-09-02. Stage 4, local rust-analyzer integration,
remains deliberately deferred.

The result is a cross-compiled, static-PIE `hx` with eleven statically linked
tree-sitter grammars. It is staged only in the Motor OS development image at
`/devtools/helix`; it is not part of the base or standard image and is not
added to `PATH`.

## Status

| Stage | Result |
| --- | --- |
| 1 — fork and editor bring-up | Complete |
| 2 — vendored static grammars and full Motor binary | Complete |
| 3 — assembly, development image, and VM acceptance | Complete |
| 4 — rust-analyzer and Lorry project graph | Deferred |

No Rust standard-library, `moto-rt`, kernel, or boot-time code was changed.
The only `src/sys` change is an exact dependency override to the Motor
`parking_lot` fork, plus its Tokio regression test. That change was required
after the initial port exposed an idle-spin latency defect and is covered by
the core-OS gates below.

## Published and pinned source state

| Component | Branch or base | Exact revision |
| --- | --- | --- |
| Upstream Helix base | tag `25.07.1` | `a05c151bb6e8e9c65ec390b0ae2afe7a5efd619b` |
| Moturus Helix | `helix-motor-25.7.1_2026-08-31` | `af99cdcece46ac897672dd2d2b2238be835d2018` |
| Moturus Helix tree | — | `b45897570c0571599cbecb862a6c8b6f14f9cfd2` |
| tree-house bindings base | release 0.2.4 | `eba8670857365ff6dd4560d1f2e8df770c2c795a` |
| Moturus tree-house | `tree-house-bindings-motor-0.2.4_2026-08-31` | `06744f59815246da0d9a77fbca3d071cfe447be1` |
| Moturus tree-house tree | — | `b88394b1ab5beb10041a44d4f30cf6211a52c0d7` |
| Moturus parking_lot | `master` | `bae5531d97330ee51ce59e4cb4322f5d4e426305` |
| Moturus parking_lot tree | — | `5727d31616e043d0502b4782b33395226ff0d822` |

The three Moturus revisions above were fetched from GitHub and matched the
locally tested commits and trees. The finalized Cargo and Motor assembly
configuration contains no sibling path, `file:` URL, branch-only dependency,
or fixture revision.

The important exact Cargo patches in the Helix fork are:

| Crate | Revision |
| --- | --- |
| crossterm 0.29.0 | `94317189d1be68cd409d13380b8f4f94af9bc08c` |
| mio 1.0.4 | `907466acd6bd9fcccfb4f9c097dcda60c55157c4` |
| Tokio 1.47.1 | `f9d26ea874753c0b5126401e77daee9e6222c359` |
| parking_lot and parking_lot_core | `bae5531d97330ee51ce59e4cb4322f5d4e426305` |
| tree-house-bindings 0.2.4 | `06744f59815246da0d9a77fbca3d071cfe447be1` |

The fork uses Rust 1.90.0. Motor builds use `--locked`, `--offline`, and
`--no-default-features`, leave Helix's `git` feature disabled, and set the
compiled runtime path to `/devtools/helix/runtime`.

## Stage 1 implementation

### Dependency and platform seams

The tree-house bindings fork keeps the static
`TryFrom<tree_sitter_language::LanguageFn>` constructor available on Motor
while compiling out `libloading` and the dynamic constructor. Its build script
declares the Motor target cfg, and its vendored endian header recognizes
`defined(__motor__)` beside `defined(__redox__)`. Host dynamic-loading behavior
and tests remain intact.

Helix's non-Motor behavior is unchanged. Motor-specific work is selected with
`target_os = "motor"` and includes:

- standard-Rust filesystem access, metadata, path normalization, and `PATH`
  lookup in `helix-stdx`;
- crossterm event, style, cursor, terminal-size, and lifecycle support;
- Ctrl+C event enablement before event reading, with no Unix signal-hook
  dependency;
- clean alternate-screen and terminal-mode restoration on normal exit and
  startup failure;
- true-color enablement without Unix terminfo probing;
- a clear unsupported result for external URL launching and suspend;
- keyboard-only defaults, with no mouse-enable sequences at startup;
- ordinary internal registers while system clipboard and OSC 52 providers
  remain unavailable.

### Central URI compatibility layer

`helix-core/src/uri.rs` owns URI-to-path conversion through the small
`helix-core/src/uri/file_url.rs` submodule. Non-Motor targets delegate to the
`url` crate. Motor implements the same local-file surface for absolute UTF-8
paths, including percent encoding, directory URLs, `localhost`, normalization,
and round trips. It rejects relative paths, remote hosts, non-file schemes,
and invalid UTF-8.

All relevant document, completion, file-event, and LSP call sites use this
layer. This was retained even though Stage 3 has no language server: a local
rust-analyzer in Stage 4 will use ordinary `file://` document URIs and is
compatible with it. There is no need to cfg URI support out on Motor.

### Recovery-safe saves

Motor atomic saves preserve the existing inode, and therefore hardlink
semantics, instead of depending on unsupported tempfile behavior. Before an
existing file is truncated, Helix creates an exclusive same-directory backup,
copies the original data, and syncs it. A successful write is synced before
the backup is removed. A failed write restores and syncs the original data;
if restoration or cleanup fails, the error reports the retained backup path.
Focused tests cover success, write failure, restoration failure, cleanup
failure, name collisions, and hardlinks.

## Stage 2 implementation

### Vendored grammar set

Generated parser sources, required headers, revision markers, and licenses are
checked into `vendor/grammars` in the Helix fork. The working-tree cost is
about 42 MiB; Git pack compression reduces the repository impact. Git
metadata, upstream tests, bindings, documentation, and build products were not
vendored.

| Grammar | Exact upstream revision |
| --- | --- |
| Rust | `77a3747266f4d621d0757825e6b11edcbf991ca5` |
| TOML | `7cff70bbcbbc62001b465603ca1ea88edd668704` |
| Markdown | `62516e8c78380e3b51d5b55727995d2c511436d8` |
| Markdown inline | `62516e8c78380e3b51d5b55727995d2c511436d8` |
| HTML | `cbb91a0ff3621245e890d1c50cc811bffb77a26b` |
| C | `7175a6dd5fc1cee660dce6fe23f6043d75af424a` |
| C++ | `56455f4245baf4ea4e0881c5169de69d7edd5ae7` |
| JSON | `73076754005a460947cafe8e03a8cf5fa4fa2938` |
| YAML | `0e36bed171768908f331ff7dff9d956bae016efb` |
| Bash | `487734f87fd87118028a65a4599352fa99c9cde8` |
| Lua | `88e446476a1e97a8724dff7a23e2d709855077f2` |

HTML was added on 2026-09-02 after the initial ten-grammar image omitted its
parser. Its existing runtime queries required no changes.

The Rust grammar was intentionally advanced from the release's
`1f63b33efee17e833e0ea29266dd3d713e27e321` pin. The generated parser kept the
same integration ABI; only a small Rust highlight-query update was needed for
the newer node names and shebang node. Dedicated parser tests pass without
error or missing nodes, so the newer grammar added no runtime or build-system
complexity.

### Static registry and network behavior

`helix-static-grammars` verifies each vendored `REVISION`, compiles the eleven
parsers into the Motor binary, and exposes a feature-gated name-to-`LanguageFn`
registry. `helix-loader` converts that function through tree-house and never
constructs a shared-library path on Motor. Unknown or unselected grammars
return the same missing-parser result as a missing host library. `hx --health`
reports success only when a parser actually resolves.

Grammars are not downloaded during tests or builds. They change only through
an explicit Helix-fork update to the vendored source and recorded revision.
After Cargo dependencies have been acquired, regular Helix tests and builds
are offline. A host build may produce ignored shared grammar libraries from
the same vendored sources; the Motor build always uses the static registry.

The raw and stripped Motor binaries are checked as static PIE executables:
ELF type `DYN`, no `NEEDED` entries, no executable stack, no TLS program
header, and no unresolved loader, grammar, or C++ runtime symbols.

## Latency defect and parking_lot fix

The first working editor rendered slowly, and the file picker was extremely
slow. The cause was not terminal output: Motor selected parking_lot's generic
fallback parker, which busy-spins while Tokio workers are idle.

`src/sys/tests/tokio-tests/src/rt_idle.rs` reproduces the defect by measuring
process CPU while a multi-thread Tokio runtime waits on a timer; it requires
idle CPU consumption below half of one CPU. The Moturus parking_lot fork adds
a Motor parker backed by `moto_rt::Futex`, including timed waits and a retained
`Arc` across deferred wakeup. Helix and the Motor `src/sys` workspace pin both
`parking_lot` packages to that exact revision. The regression and interactive
Helix VM coverage pass with the fix.

## Stage 3 implementation

Motor assembly identity is now schema `motor-assembly-key-v3`. It includes the
exact `HELIX_REV`, repository, ref, and a content-tree digest covering the
staged binary, runtime files, symlinks, and executable modes. Producer and
consumer validation require the Helix root and reject binary or runtime
tampering.

A new assembly producer uses `toolchain_managed_checkout` to obtain the exact
GitHub revision. On a fresh producer path, Cargo performs `fetch --locked` as
the explicit online dependency-acquisition step, then builds Helix with
`--locked --offline --no-default-features`. A validated reusable assembly
skips the checkout, fetch, build, and staging work entirely.

Only these paths are staged:

- `/devtools/helix/hx`;
- `/devtools/helix/runtime/queries`;
- `/devtools/helix/runtime/themes`;
- `/devtools/helix/runtime/tutor`.

The image contains no grammar sources, `.git` directory, shared object, build
directory, user configuration, or cache. `motor-os-dev.yaml` selects the
Helix assembly root and executable; the standard image explicitly does not.

The existing TUI harness tests the development image without adding another
VM boot. With isolated XDG and temporary directories it verifies the exact
`25.07.1` version and fork revision, runtime discovery, all eleven health/parser
results, SSH editing and saving, literal Ctrl+C behavior, resize redraw,
`:sh`, absence of mouse enablement, terminal restoration, and edit/save/exit
inside an rmux pane.

## Validation record

The authoritative validation used the published GitHub revisions and a fresh
managed checkout. It passed:

- Helix host workspace tests, dedicated static-grammar parser tests, clippy
  (no new Motor warnings), Motor workspace cross-check, release link, and raw
  plus stripped ELF validation;
- tree-house host/static-constructor tests and Motor target graph/check with
  no `libloading` target dependency;
- a fresh production assembly and all release images, followed by a second
  build that reported a validated assembly reuse and did not fetch or rebuild
  Helix;
- the imager unit test with `RUSTFLAGS='--cfg tokio_unstable'` and
  `cargo test --manifest-path src/imager/Cargo.toml --locked --offline` — 21
  tests;
- the focused prebuilt release development-image TUI gate, including all
  Helix cases;
- `src/tests/full-test-dev.sh --release`, including developer sources and the
  complete Lorry product/self-host suite;
- `src/tests/full-test.sh` three consecutive times in debug mode;
- `src/tests/full-test.sh --release` three consecutive times in release mode;
- shell syntax checks and `git diff --check`.

The `RUSTFLAGS` on the imager command is required because that crate uses the
repository's `tokio_unstable` LocalRuntime configuration. The earlier
prospective command without it was incomplete.

## Motor OS implementation commits

| Commit | Purpose |
| --- | --- |
| `d928222d` | include Helix in the development image |
| `5898ef18` | reproduce Tokio/parking_lot idle spin |
| `f98e7a24` | key assemblies and provenance on Helix |
| `cfb157c2` | managed build, ELF validation, staging, and shell coverage |
| `074d7ab5` | pin the Motor parking_lot parker in `src/sys` |
| `766a248b` | cover Helix in the development-image TUI suite |

## Current limitations and Stage 4

Version one intentionally has no mouse input by default, suspend/job control,
external URL launch, system clipboard, OSC 52 clipboard access, dynamic
grammar loading, or language-server integration. These capabilities fail or
default cleanly rather than partially activating.

Stage 4 will add the local rust-analyzer binary and Lorry-generated project
graph, then test at least one diagnostic and hover in a VM. It should use the
central local-file URI layer already present. The server path, graph format,
staging layout, and Stage 4 acceptance details remain future work.
