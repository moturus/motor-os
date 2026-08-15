# Lorry Stage 3 design

Status: active for the two approved first increments below. The remaining
Stage 3 capabilities are still design for review and should not be implemented
until their relevant option is accepted.

Stage 3 targets `src/bin/httpd-axum`, but the four capabilities considered
here are independent. They should not become one large implementation merely
because they are being reviewed together.

## Approved first increments

These precede the package capabilities discussed later in this document:

1. Add `lorry clean`. With no selection options it removes the complete
   Lorry-owned `target` directory, matching the primary `cargo clean`
   contract. Selection options should follow only Lorry's supported profile
   and target surface; unsupported Cargo package, workspace, documentation,
   and custom-profile selection remains explicitly rejected.
2. Make an unchanged `lorry build` genuinely fresh and make an unchanged
   `lorry run` start the program promptly. After one successful build, a
   second invocation with identical manifest, lock, sources, configuration,
   toolchain, target, profile, and environment inputs must not invoke rustc,
   native tools, build scripts, or the linker. It may revalidate the bounded
   dependency/admission inputs needed to fail closed, but that check must not
   reconstruct or republish unchanged artifacts.

The second increment needs a focused timing assertion only as a regression
guard with generous machine-independent headroom. Its correctness contract is
that no build process runs and the existing artifact is selected; elapsed time
alone must not be used as a substitute for that proof.

## Target audit

The current `httpd-axum` package has one binary and is not a workspace. Its
locked graph does contain procedural-macro packages, including `clap_derive`,
`serde_derive`, `tokio-macros`, and `tracing-attributes`, and its root manifest
has Git patches for `ring`, `mio`, and `tokio`.

| Capability | Needed to build `httpd-axum`? | Current Lorry boundary |
|---|---|---|
| Multiple binaries | No | The manifest stores a vector but parsing and root planning allow only its first entry. |
| Workspaces | No | Commands require one package manifest in the current directory. |
| Procedural macros | Yes | `proc-macro = true` is rejected and dependency units produce only libraries and build scripts. |
| Git sources | Yes, before materialization | Linux `vendor` handles root Git patches only; build remains offline and Motor can consume a project already materialized on Linux. |

`httpd-axum/Cargo.lock` contains 142 package records. That does not prove that
all 142 are selected in one host/target context, but the selected graph must be
measured against Lorry's default 64-package policy limit before calling the
Stage 3 target complete. A larger target is reason to review the limit, not to
silently remove it.

## Common boundaries

- `Cargo.toml`, `Cargo.lock`, and local source/repository objects remain normal
  Lorry inputs. Cargo is not an operational dependency of build, run, or test.
- Build, run, and test stay offline. `vendor` is the only command that acquires
  remote source or changes dependency state.
- New source kinds and executable-at-build-time capabilities must appear in
  the canonical review and compact admission state. Existing format versions
  must not silently acquire new meanings.
- Each capability should be delivered as a small independently testable
  increment. Cargo comparisons are validation oracles, not runtime services.

## Multiple-binary packages

Cargo discovers `src/main.rs`, `src/bin/*.rs`, and
`src/bin/*/main.rs` by default, merges those targets with explicit `[[bin]]`
tables, and permits discovery to be disabled with `package.autobins = false`.
With no target selector, `cargo build` builds every library and binary target.
`cargo run` requires `--bin NAME` when more than one binary exists unless
`package.default-run` selects one.

There are three reasonable scopes:

| Option | Scope | Tradeoff |
|---|---|---|
| M1: explicit targets only | Accept multiple `[[bin]]` tables and exact `--bin`. | Smallest, but rejects common Cargo layouts that use `src/bin`. |
| M2: bounded Cargo discovery | Add Cargo's normal binary discovery, `autobins`, exact `--bin`, and `default-run`. | Useful compatibility without implementing every Cargo target selector. |
| M3: full target CLI | Also support repeatable/glob selectors, `--bins`, `--all-targets`, and `required-features`. | Much broader and not needed for multiple ordinary binaries. |

M2 is the preferred first increment. Lorry may deliberately accept one exact
`--bin` rather than Cargo's repeatable glob syntax, provided the difference is
documented and ambiguous or unknown names fail clearly.

The root planner must stop using `.first()` and instead handle a deterministic
set of targets:

- `build` with no selector builds the library and every binary; `--bin NAME`
  builds the named binary and whatever library it needs;
- `run` selects explicit `--bin`, then `default-run`, then a sole binary, and
  rejects every ambiguous case;
- `test` builds a harness for every target whose `test` flag is true and makes
  every built program available to integration tests through its own
  `CARGO_BIN_EXE_<name>` value; and
- output names, cache identities, installation, and test bundles include the
  target name so binaries cannot overwrite each other.

Target-count and total-output bounds are required, but their exact values
should be chosen from real fixtures during implementation. Examples, benches,
`required-features`, and general target-selection flags can remain deferred.

## Cargo workspaces

A Cargo workspace is more than a list of directories. Members share a root
`Cargo.lock`, target directory, profiles, patches, and resolver. The root may
be a package or a virtual manifest; commands select the current package,
`default-members`, `-p`, or the whole workspace. Members can also inherit
package metadata, dependencies, and lints from workspace tables.

Lorry currently uses the package root as its effective workspace root and
owns one root manifest, build result, and admission document. Supporting a
workspace therefore needs an explicit scope rather than renaming that path.

| Option | Scope | Tradeoff |
|---|---|---|
| W1: selected-member envelope | Discover the workspace root and shared lock/profile/patch state, but operate on the current member or one exact `-p`. Initially require explicit member paths and reject inheritance. | Small and immediately useful, but workspace-wide commands remain absent. |
| W2: bounded workspace | Add `default-members`, `--workspace`, and normalized `[workspace.package]`, `[workspace.dependencies]`, and `[workspace.lints]` inheritance. | Covers ordinary workspaces while still rejecting member globs, `exclude`, and implicit membership. |
| W3: Cargo-complete discovery | Add globs, exclusions, automatic path-member rules, external members, and Cargo's package-spec/glob CLI. | Large filesystem and selection surface with little Stage 3 value. |

The recommended order is W1 followed by only the W2 pieces demanded by a
real package. Workspace support is not a prerequisite for `httpd-axum` and
should not delay it.

Before W1 is implemented, admission ownership needs one reviewed decision:

- member admission files keep each selected package independent but duplicate
  review state and need a rule for workspace-wide commands; or
- one workspace admission file records member manifests, selected members,
  and their per-context graphs, which requires a new canonical review format.

The workspace-wide form is cleaner once Lorry can build several members in
one command. It is unnecessary machinery for a selected-member-only slice, so
the first implementation may keep admission beside that member and reject
workspace-wide operation.

## Procedural macros

A procedural macro is a compiler-host dynamic library declared by
`[lib] proc-macro = true`. It runs inside rustc while another crate is being
compiled. During a Linux-to-Motor build the macro and all of its normal
dependencies are Linux host units; during a native Motor build they are Motor
host units. Compiling the macro as a Motor target library during a cross build
would be incorrect.

The implementation choices are:

| Option | Scope | Tradeoff |
|---|---|---|
| P1: first-class host unit | Add a procedural-macro unit kind, compile it as `--crate-type proc-macro` for the compiler host, and pass the host artifact through `--extern`. | Matches Cargo's model and reuses Lorry's host/target graph split. |
| P2: treat it as a library | Reuse the current target-library path. | Incorrect for cross compilation and must not be used. |
| P3: require generated or prebuilt output | Avoid executing a macro by asking projects to commit expanded/prebuilt results. | Not Cargo-compatible, compiler-specific, and unsuitable as general support. |

P1 is the only viable implementation. It requires:

- parsing `proc-macro = true` and distinguishing the target in unit, artifact,
  dependency-edge, cache, and Cargo-identity data;
- compiling the macro and its normal/build dependencies for the host, while
  retaining resolver-v2 feature separation when the same package is also a
  target dependency;
- recording the compiler host and exact rustc identity because proc-macro
  dynamic libraries are compiler- and host-specific; and
- testing a small local derive crate on Linux-to-Linux, Linux-to-Motor, and
  native Motor before using the much larger `httpd-axum` graph.

Procedural macros have the same security concern as build scripts: they are
arbitrary dependency code executing during compilation with rustc's access.
The preferred policy is an explicit `proc-macro = true` capability grant and
the same filesystem/network restrictions as the rustc process that loads it.
Where Motor cannot enforce that restriction, Lorry must issue the same kind of
explicit unsandboxed-execution warning used for native build scripts; it must
not claim isolation. Adding the grant changes both compact admission syntax
and canonical review meaning, so both format versions must advance.

## Git sources and “git-light”

Two separate problems have previously been grouped under `git-light`:

1. Cargo semantics for Git dependencies and patches: parse them, preserve the
   locked commit, find the named package within a repository, resolve its
   graph, review it, and build from verified immutable source.
2. Git transport: obtain one commit over the network on Linux or Motor.

The first is Lorry package-management behavior. The second is only a backend
used by `lorry vendor`. Neither belongs in build, run, or test.

### Source-model options

| Option | Behavior | Tradeoff |
|---|---|---|
| G1: rewrite to paths | Extend the Stage 2 bridge to materialize direct Git dependencies and patches, then rewrite manifests and the lock to local paths. | Smallest resolver change, but destroys Cargo's Git source identity and is awkward when one repository contains several packages or internal path dependencies. |
| G2: first-class Git source | Keep `git+...#commit` lock nodes, map them to one verified commit snapshot plus a package-relative manifest path, and build offline from that object. | More resolver/admission work, but preserves Cargo semantics and handles multi-package repositories cleanly. |
| G3: keep patches only | Retain the current root-patch bridge and continue rejecting direct Git dependencies. | Enough for a pre-vendored `httpd-axum`, but not general Git dependency support. |

G2 is the preferred durable model. An immutable Git source identity should
contain a canonical URL, exact resolved commit, Git tree, canonical Lorry
source-tree SHA-256, and the selected package's path within that snapshot.
Branch, tag, or `rev` is update intent and provenance, not a substitute for
the locked commit. The canonical review needs Git direct-dependency, lock,
source-evidence, and per-context records, so this also requires a new review
format rather than pretending Git is crates.io or a path source.

G2 can be implemented and tested first with the existing controlled Linux
`git` invocation. A project vendored there remains buildable on Motor without
Git or a network. This separates source-model correctness from a new protocol
parser and is sufficient to determine whether `httpd-axum` builds.

### Transport options

| Option | Behavior | Tradeoff |
|---|---|---|
| T1: installed Git on Linux | Keep the current bounded, cleared-environment Git process and require projects to be materialized before transfer to Motor. | Already works; no native Motor vendoring. |
| T2: internal Git acquisition | Put the bounded smart-HTTP and pack reader in Lorry or a linked library. | No extra executable, but substantially increases Lorry's network/parser attack surface. |
| T3: `git-light` executable | A separate first-party program materializes one requested commit for Lorry. | Isolates the implementation, but becomes another installed operational dependency and requires a strict authenticated result protocol. |

T1 is the recommended Stage 3 starting point. T2 or T3 is justified only if
native Motor `lorry vendor` is itself an accepted Stage 3 requirement. The
name `git-light` should not predetermine a separate executable.

If native acquisition is accepted, its first scope should stay anonymous
HTTPS, one repository and revision, complete-tree materialization, and a
bounded SHA-1 repository. Git protocol v2 over smart HTTP still requires
reference discovery, POST requests, pkt-line and sideband parsing, and a pack
reader with both offset and reference deltas. Every size, object count, delta
depth, path, mode, object hash, pack checksum, commit, and tree traversal must
be bounded and verified. Authentication, pushes, submodules, LFS, partial
clones, working-copy commands, and reusable object databases remain outside
that increment. This is a separate security-sensitive project, not a small
appendix to Git manifest parsing.

## Recommended Stage 3 sequence

1. Implement the approved `lorry clean` contract.
2. Eliminate unchanged root rebuilds from `lorry build` and `lorry run`.
3. Measure the selected `httpd-axum` graph per supported context and review
   any policy-limit change.
4. Implement P1 procedural-macro host units and the associated admission
   format update.
5. Prove `httpd-axum` from a Linux-materialized repository on Linux-to-Motor
   and native Motor; fix only additional concrete manifest/unit gaps found.
6. Implement G2 Git source semantics while retaining T1 transport.
7. Add M2 multiple-binary support as an independent compatibility increment.
8. Add W1 workspace support when a selected package requires it.
9. Review native Git acquisition separately; implement T2 or T3 only if
   native Motor vendoring is required.

This order gets evidence from the Stage 3 target early and avoids making
multi-binary packages, workspaces, or a new Git client prerequisites when they
are not.

## References

- Cargo target discovery and target fields:
  <https://doc.rust-lang.org/cargo/reference/cargo-targets.html>
- Cargo build and run target selection:
  <https://doc.rust-lang.org/cargo/commands/cargo-build.html> and
  <https://doc.rust-lang.org/cargo/commands/cargo-run.html>
- Cargo clean behavior:
  <https://doc.rust-lang.org/cargo/commands/cargo-clean.html>
- Cargo workspaces:
  <https://doc.rust-lang.org/cargo/reference/workspaces.html>
- Cargo Git dependencies:
  <https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-dependencies-from-git-repositories>
- Rust procedural macros and their security model:
  <https://doc.rust-lang.org/reference/procedural-macros.html>
- Git protocol v2, smart HTTP, and pack format:
  <https://git-scm.com/docs/protocol-v2>,
  <https://git-scm.com/docs/gitprotocol-http>, and
  <https://git-scm.com/docs/pack-format>
