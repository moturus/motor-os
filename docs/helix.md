# Helix on Motor OS

The developer image includes the Motor port of Helix 25.07.1, native
rust-analyzer, and native rustfmt. Helix runs on the console, over SSH, and
inside an rmux pane. The base and standard images do not include it.

## Using the editor

Boot with `vm_images/release/run-dev.sh`, which defaults to 8 GiB of guest
RAM. In Motor OS, try the packaged example; it needs no downloads:

```sh
cd /devtools/src/helix-rust-demo
hx src/main.rs
```

Starting `hx` without arguments and opening the file with `:o src/main.rs`
also works. Wait for initial source loading and indexing to finish (the LSP
spinner stops) before semantic navigation. The first compiler check can
finish before the project and standard-library sources have loaded.

| Command | Action |
|---|---|
| `Space k` on `ANSWER` | Show hover documentation |
| `g d` on `ANSWER` | Open the definition in `greeting.rs` |
| `Ctrl-o` | Return from navigation |
| `Ctrl-x` in insert mode | Request completion |
| `Space d` | Open document diagnostics |
| `:format` | Format the buffer without saving |
| `:w` | Format, save, and run the compiler check |
| `:log-open` | Open the editor log |
| `:lsp-restart` | Restart the language server |

Changing the example's `answer` binding from `u32` to `bool` and saving
produces a compiler diagnostic; restoring `u32` and saving clears it.
Navigation on `rt_version` opens the installed Motor standard library.

For another project, open an admitted Lorry package and prepare its
dependencies explicitly with `lorry vendor`. A virtual workspace root is
not a Lorry package. Build scripts and checks run with the invoking user's
authority; opening a project is not a sandbox boundary.

## Native Rust integration

The packaged configuration is
[`img_files/motor-os-dev/user/.config/helix/languages.toml`](../img_files/motor-os-dev/user/.config/helix/languages.toml),
installed at `/user/.config/helix/languages.toml`. Normal Helix project
overrides in `.helix/languages.toml` still apply. A custom `XDG_CONFIG_HOME`
needs the native settings copied into its own `helix/languages.toml`.

Helix starts `/devtools/rust/bin/rust-analyzer` directly over stdio. Its
environment selects `/devtools/bin/lorry` through `CARGO` and
`/devtools/rust/bin/rustfmt` through `RUSTFMT`, includes `/devtools/bin` in
`PATH`, and sets `TMPDIR=/devtools/tmp`. These belong in the server's own
environment: `cargo.extraEnv` only affects its children and cannot select
the metadata/check executable.

`MOTURUS_STDIO_NO_TERMINAL=true` in the server's launch environment is
required to keep its terminal-input relay from taking Helix's keyboard
stream. Motor consumes this instruction before the server starts; see
[foreground forwarding](tui.md#foreground-forwarding).

The server targets `x86_64-unknown-motor`, discovers the matching installed
sysroot, and uses Lorry's Cargo-compatible metadata and check commands.
Build scripts are enabled without a rustc wrapper; procedural-macro
expansion in the analyzer is disabled. The client reports file changes.
Lorry's compiler-side procedural-macro support is separate. General server
configuration is documented in [build-rustc.md](build-rustc.md#native-motor-rust-analyzer).

The pinned integration can log a Lorry version-string warning and an
unsupported `workspace/diagnostic/refresh` response from Helix. Push
diagnostics and their clearing are covered by the native acceptance tests.

Rust formatting runs through the LSP formatting feature, including
format-on-save. `hx --health rust` checks server discovery, but its external
formatter entry remains `None`: no Helix external formatter is configured.
A parser error yields no formatting edits; saving can still write the
unformatted source. Repair the source and format or save again.

rustfmt searches the source directory and its ancestors for `rustfmt.toml`
or `.rustfmt.toml`, then `/user`, then `/user/cfg/rustfmt`. It ignores
`HOME` and `XDG_CONFIG_HOME` on Motor. This formatter lookup is separate
from Helix's own configuration lookup above.

## Port behavior

Helix is a static PIE at `/devtools/helix/hx`; the developer overlay's
`/devtools/bin/hx` launcher forwards quoted arguments, including paths with
spaces. Its runtime is `/devtools/helix/runtime`.

Ten tree-sitter grammars are linked into the binary: Rust, TOML, Markdown,
Markdown inline, C, C++, JSON, YAML, Bash, and Lua. Their generated sources,
headers, licenses, and exact `REVISION` markers live in `vendor/grammars`
in the Helix fork. `helix-static-grammars` checks those revisions and
resolves parsers through tree-house's static `LanguageFn` constructor.
Unknown grammars report a missing parser. Adding or updating a grammar
requires a fork update and rebuild; builds and tests never download grammars.

Motor uses keyboard input and true color without Unix terminfo or signal
hooks. Ctrl+C reaches the editor as an input event. Normal exit and startup
failure restore terminal modes and the alternate screen. Mouse input is
disabled by default. Suspend/job control, external URL launching, system
clipboard access, OSC 52, and dynamic grammar loading are unavailable;
ordinary internal registers work. The build leaves Helix's `git` feature
disabled.

Local-file URI conversion is centralized in the fork's
`helix-core/src/uri/file_url.rs`. It handles absolute UTF-8 paths, percent
encoding, directory URLs, `localhost`, and normalization for document and
LSP operations. It rejects relative paths, remote hosts, non-file schemes,
and invalid UTF-8.

### Saves and recovery

Saving an existing file preserves its inode and hardlinks. Before
truncation, Helix creates an exclusive backup in the same directory, copies
the original bytes, and syncs them. It syncs a successful write before
removing the backup. A failed write restores and syncs the original data;
if restoration or cleanup fails, the error identifies the retained backup
path. Fork tests cover write, restoration, and cleanup failures, collisions,
and hardlinks.

## Build and regression coverage

Helix is a userspace add-on, not a part of the toolchain.
[`src/build-motor-os.sh`](../src/build-motor-os.sh) declares the Helix fork
and the branch to follow; no commit is declared. Dependency patches and
grammar revisions live in that fork. After the toolchain and its assembly are
complete, the [producer](build-motor-os.md) updates the checkout in
`$MOTORH/helix`, explicitly fetches locked Cargo dependencies, then builds
with the Motor compiler using `--locked`, `--offline`, and
`--no-default-features`. The built commit is recorded in the assembly's
`ADDON-helix` file, and Helix is rebuilt alone when the branch head differs;
it is no part of the assembly's key, manifest, or validation. The image
contains only the binary, queries, themes, and tutor; raw and stripped
binaries undergo ELF checks.

The Motor `parking_lot` fork parks idle Tokio workers with `moto_rt::Futex`.
Its generic fallback used to spin, causing editor and file-picker latency.
[`rt_idle.rs`](../src/sys/tests/tokio-tests/src/rt_idle.rs) guards idle CPU
consumption. The framed child-pipe regression in
[`process.rs`](../src/sys/tests/tokio-tests/src/process.rs) guards writable
readiness after partial writes, which previously stalled LSP initialization.

Salsa cancellation uses `resume_unwind`. The standard Motor sysroot supplies
real unwinding; an abort-only analyzer exits on ordinary cancellation.
The former private analyzer library has been retired. The
[toolchain runtime contract](toolchain.md#rust-runtime-and-native-formatting)
and [`test-unwind.sh`](../src/tests/test-unwind.sh) cover this requirement.

`src/tests/test-tui.sh` and its `test-helix-lsp.sh` helper cover parser health,
editing, saves, terminal restoration, resize, rmux, native semantic requests,
formatting, and clean server shutdown. The LSP cases include empty editor
startup, opening a file afterward, edits during loading, paths with spaces,
Motor std navigation, and formatter-error recovery. The readiness helper's
host tests guard waiting for source scans and indexing before semantic
assertions. These tests run through `src/tests/full-test.sh`; developer
coverage is reached with `src/tests/full-test-dev.sh --release`.

The unrelated, unresolved sys-io abort observed during integration is
recorded in [future work](plans/future-work.md#unresolved-sys-io-abort-during-listener-exhaustion-2026-09-10).
