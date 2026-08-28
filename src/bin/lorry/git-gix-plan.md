# Gix-backed Git vendoring plan

## Goal

Make Lorry's Git-patch and direct Git-dependency vendoring flows work on Linux
and Motor OS without invoking the `git` executable. Use the local
`../gitoxide` checkout as the source of `gix`, port the smallest production
feature closure required by Lorry to `x86_64-unknown-motor`, and prove the
result with focused direct-dependency fixtures and the Git-backed `crossterm`
patch used by `src/bin/gears`.

All changes in both `motor-os` and `../gitoxide` will remain uncommitted.

This plan includes both Lorry's currently specified root `[patch.crates-io]`
Git entries and first-class direct dependency declarations such as
`dep = { git = "..." }`. Gears exercises the patch flow. Direct dependencies
also require the immutable source, repository, lockfile, resolution, review,
admission, and cache identities described in `design.md`.

## Current state

- `src/bin/lorry/src/git/linux.rs` shells out to an installed `git`, fetches a
  shallow commit, checks it out, records Git/source-tree identities, obtains
  approval, and rewrites the patch to `.lorry/vendor/<alias>/source`.
- `vendor.rs` performs a normal path-only `Manifest` load before calling that
  bridge. The load rejects the Git patch, so the bridge is unreachable for an
  unmaterialized project.
- Motor has an unconditional hard error in `git.rs`; it never enters a Git
  transport.
- Gears declares the crossterm patch from
  `https://github.com/moturus/crossterm.git`, branch `motor-os-support`, and its
  lock pins commit `bacb8c9703743dece42ccbe3fac96cbe50a6fa7c`.
- The local gitoxide checkout is clean at
  `c4426f034d5423c66cc5c15725587d9688deada3` on branch `main`.
- Motor's target has `target_os="motor"` but no `target_family="unix"`.
  Gix and its dependency closure must therefore compile through their portable
  paths or gain narrow Motor cfgs where the portable behavior is insufficient.
- Gix provides a backend-neutral blocking smart-HTTP `Http` trait. Motor's
  Rust curl executable already supports HTTPS GET, POST bodies, explicit
  headers, CA bundles, status metadata, and bounded transfers. Reusing that
  process boundary avoids introducing reqwest/Tokio or libcurl into Lorry.

## Constraints

- Use standard Rust and existing Motor/Lorry APIs; do not add another ambient
  network or credential mechanism.
- Anonymous canonical HTTPS remains the only accepted remote form.
- Preserve the configured curl executable, CA bundle, redirect trust policy,
  source limits, approval step, atomic publication, and exact provenance
  evidence.
- Git object/pack input must be bounded before it can consume unbounded disk,
  memory, time, or output.
- Builds, runs, tests, and review remain offline. Only `lorry vendor` may use
  the network.
- Regular automated tests must use local deterministic fixtures, not public
  Internet services. The explicit Gears acceptance runs may contact GitHub and
  crates.io only after review approval.
- Keep implementation increments near 100--300 lines including focused tests.
- Preserve the unrelated existing Motor OS modification in
  `src/sys/tests/systest/src/io_channel.rs`.

## Proposed design

### Gix dependency and feature boundary

Add a path dependency from Lorry to the local `../gitoxide/gix` crate, with
default features disabled. Enable only SHA-1, blocking fetch/protocol, and the
tree/worktree functionality required to materialize a selected commit. Add a
direct path dependency on `gix-transport` only if needed to instantiate its
generic smart-HTTP transport with Lorry's backend.

The expected relative checkout path from `src/bin/lorry` is
`../../../../gitoxide/gix`. This intentionally makes the requested local clone
part of the development build. VM validation will use an already linked Lorry
binary, so the gitoxide source tree need not be present beside Gears in the
guest.

The port target is the feature closure Lorry actually compiles, not the full
gitoxide CLI or every optional gix feature. Each upstream change must remain
portable and should prefer an existing `not(windows)` or generic fallback over
Motor-only code when the semantics match.

### HTTP transport

Implement Lorry's adapter to gix's blocking smart-HTTP interface on top of the
configured curl executable:

- accept only the already validated anonymous HTTPS URL;
- translate gix's GET/POST headers and request body without a shell;
- supply the configured CA bundle;
- enforce redirect trust at every hop and report the effective base URL back
  to gix;
- expose the response headers needed for gix's smart-protocol content-type
  validation;
- bound request/response bytes and wall time using policy-derived limits;
- keep credentials and ambient environment disabled; and
- retain useful diagnostics without leaking URL query data.

If the current curl control trailer cannot return response headers, extend the
small Motor curl and Lorry curl wrapper narrowly for the Git content type. Do
not weaken the existing archive/sparse download contract.

Gix should continue to own pkt-line negotiation, pack parsing, delta
resolution, object validation, reference selection, and worktree
materialization. Lorry continues to own trust policy, resource policy,
approval, source-tree hashing, provenance, and publication.

### Selected revision and lock behavior

Use the existing `Selector` and Cargo.lock pinning rules:

- fetch `HEAD`, `refs/heads/<branch>`, `refs/tags/<tag>`, or the requested
  revision;
- if Cargo.lock identifies a matching 40-hex commit, materialize that exact
  commit even if the requested ref has advanced;
- reject a fetched object that is not a commit;
- record the exact commit and its root tree ID from gix;
- materialize the complete tree without `.git` metadata;
- scan it through Lorry's existing `Tree` limits; and
- preserve the current deterministic `git.toml` and manifest rewrite.

No submodule, LFS, credential helper, filter process, hook, or Git config is
executed.

### Vendor ordering

Introduce a narrow preflight that locates the selected package/workspace and
loads enough installation configuration to acquire the project vendor lock and
materialize root Git patches before the normal path-only `Manifest` load.
Hold the vendor lock across materialization and the remaining vendor
transaction. Then reload the rewritten manifest and continue through the
ordinary resolver/repository/admission flow.

The preflight must retain current workspace selection semantics; it must not
become general parent package discovery. A failed or declined Git operation
may leave no published patch or manifest edit. Once the Git patch is
atomically published and the manifest is rewritten, a later crates.io failure
may leave that completed preliminary transaction, as currently specified.

### Platform-neutral Lorry Git module

Replace `git/linux.rs` with a shared gix implementation compiled on Linux and
Motor. Remove the Motor hard error and all installed-`git` discovery/process
code. Keep parsing, validation, approval, tree limits, provenance, and atomic
manifest replacement shared.

Documentation in `README.md`, `design.md`, and `spec.md` will describe the
gix-backed Linux/Motor behavior and remove the obsolete "Motor never invokes
Git" and known-ordering-defect statements.

### First-class direct Git sources

Extend dependency parsing for `git` with optional `branch`, `tag`, or `rev`,
plus the existing `package`, feature, and optionality keys. A direct Git
requirement has update intent but no semver selection requirement unless a
`version` compatibility assertion is also present. Cargo.lock remains the
authority for the exact commit and package graph.

Represent an immutable Git package with the canonical URL, exact locked
commit, Git tree, canonical source-tree digest, and package-relative path in
the fetched repository. One fetched repository may supply multiple packages;
acquire and attest its snapshot once, then verify each selected package
manifest below a canonical relative directory.

Add a distinct Git source variant throughout lock parsing/rendering,
resolution, repository lookup/publication, canonical review, policy evidence,
admission, logical source paths, and unit/cache identities. Bump generated
repository/admission formats where the old format cannot represent Git without
ambiguity. Do not rewrite direct dependencies to mutable path dependencies.
Build, run, test, and review remain offline and resolve the locked Git package
only through verified immutable repository objects.

## Incremental implementation

### 1. Establish the gix Motor feature closure

1. Add the local path dependency and generate Lorry's lockfile without
   changing unrelated versions.
2. Compile the exact feature closure for Linux and
   `x86_64-unknown-motor`.
3. Fix compile failures in `../gitoxide` one crate at a time with focused
   tests. Avoid changes to optional features outside the closure.
4. Add a small gix-side Motor compile/runtime test where a platform behavior
   needs code rather than a cfg-only correction.

Stop and report any required Rust standard-library, `moto-rt`, or core OS
change before making it, per repository policy.

### 2. Add a deterministic smart-HTTP adapter contract

1. Refactor the Lorry curl request surface to support bounded GET/POST bodies
   and the required response content type.
2. Implement the gix `Http` adapter with no public-network assumptions.
3. Test it against a local fixture process/server that supplies fixed Git
   advertisement and upload-pack responses, including malformed content type,
   redirect denial, oversized response, timeout, and failed POST cases.
4. Confirm ordinary crates.io sparse/archive requests are byte-for-byte
   unchanged by their focused curl contract.

If faithfully driving gix requires a new public extension point, add the
smallest backend-neutral API to the local gitoxide clone with its own Linux
test rather than embedding Lorry knowledge in gitoxide.

### 3. Replace the Git subprocess materializer

1. Fetch and select the requested/locked commit through gix.
2. Materialize the commit's complete tree into the existing atomic staging
   directory.
3. Preserve approval, source scanning, provenance, manifest rewrite, and
   rerun behavior.
4. Add focused unit tests for branch/tag/rev/HEAD selection, locked commits,
   wrong object kinds, unsafe tree entries, and interruption/error cleanup.

### 4. Repair vendor ordering and add a product contract

1. Move Git inspection/materialization ahead of the rejecting full manifest
   load while preserving workspace selection and locking.
2. Add a `tests/git-contract.sh` local fixture covering Linux `lorry vendor`,
   the rewritten path patch, lock reconciliation, repository/admission state,
   offline build, rerun behavior, and failure atomicity.
3. Include the contract transitively in `tests/test-all.sh` exactly once.

### 5. Add direct Git dependency identities

1. Extend manifest and Cargo.lock models with Git requirement and locked-source
   identities, including monorepo package paths and multiple packages at one
   commit.
2. Add immutable Git repository objects and evidence, then thread the new
   source variant through resolver, review/admission, policy, unit, and cache
   identities.
3. Make `vendor` fetch each unique locked/requested repository snapshot once,
   discover and verify selected package manifests, reconcile Cargo.lock, and
   publish objects before committing admission state.
4. Add local direct-Git contracts for an exact revision, branch locked to an
   older commit, renamed package, transitive Git dependency, monorepo packages,
   mixed registry/Git graphs, and offline rebuild/review.

### 6. Linux Gears acceptance

1. Copy Gears to scratch without `.git` or `target`.
2. Run the new Lorry `vendor` against its real crossterm Git patch and verify
   the locked commit/tree/source digest and rewritten manifest.
3. Run `lorry build` offline from the newly vendored state.
4. Retain command output and identity evidence for the handoff; do not modify
   the checked-in Gears source.

### 7. Motor Gears acceptance

1. Build a release developer image and start a VM with the repository's SSH
   harness.
2. Cross-build the changed Lorry for Motor, upload it and an unmaterialized
   scratch copy of Gears under `/user/src/`.
3. Run Motor-native `lorry vendor` so the guest itself fetches and
   materializes crossterm through gix.
4. Disable/remove network availability after vendoring where practical, then
   run Motor-native `lorry build` from the vendored Gears tree.
5. Run the resulting Gears binary with a noninteractive smoke argument if one
   exists; the required acceptance criterion is a successful native build.
6. Cleanly shut down the VM and retain logs on failure.

This explicit real-network acceptance is separate from the regular Lorry test
suite and will not be added to `full-test.sh` or `test-all.sh`.

## Validation gates

Run focused checks while developing, followed by:

```sh
cargo fmt --manifest-path src/bin/lorry/Cargo.toml --check
cargo test --manifest-path src/bin/lorry/Cargo.toml --locked --offline
src/bin/lorry/tests/git-contract.sh
src/bin/lorry/tests/curl-contract.sh
src/bin/lorry/tests/test-all.sh
```

Also run gitoxide formatting and the focused tests/checks for every modified
gitoxide crate, for both the Linux host and the exact Motor feature closure.
The final exact commands depend on which crates fail the initial target check
and will be recorded in the handoff.

Check both worktrees for compiler warnings and unintended files. Do not run
`cargo fmt` across unrelated gitoxide workspace crates, and do not
commit either worktree.

## Review decisions

1. Confirm that this task covers root `[patch.crates-io]` Git entries (the
   Gears case), while first-class direct `{ git = ... }` dependencies remain a
   separate follow-up.

NO: direct git dependencies are in scope.
  
2. Confirm that "port gix" means the minimal Lorry production feature closure,
   not every optional gix/gitoxide CLI feature.

YES

3. Approve the two explicit public-network acceptance runs: Linux Gears
   vendoring and Motor-native Gears vendoring. Automated regression tests will
   remain fully local and deterministic.

YES
