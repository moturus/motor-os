# Remove the Stage 2 dependency seed

Status: implementation complete; validation in progress

## Goal

Stop constructing, copying, and packaging dependency sources that shipped
Lorry can acquire with `lorry vendor`. A fresh Motor development image
will require network access for the first vendor operation and will build
offline after that operation populates its writable user repository and
project-local Git materializations.

This plan removes the Lorry dependency seed, not the native compiler
toolchains, installed Lorry/curl executables, Cargo lockfiles, dependency
admission records, or first-party Motor source snapshots. Those are either
needed to perform the online rebuild or are reviewed source/provenance rather
than rebuildable dependency payloads.

## Resulting developer workflow

The image will ship a small `/devtools/cfg/lorry.toml` that configures:

- the installed Motor curl, CA bundle, compiler, and archiver;
- the targets and package-count limit needed by the packaged projects; and
- only the explicit build-script, procedural-macro, and native-tool grants
  required by Lorry's security model.

The user layer, `/user/cfg/lorry.toml`, configures
`/user/cfg/lorry/vendor` as the writable dependency repository.

It will not configure a system dependency repository or pre-approve ordinary
package identities. From a newly booted image, each supported native source
project will use:

```sh
lorry vendor
lorry build
```

`vendor --accept-all` remains available for a new graph, but it cannot replace
the explicit executable-code grants in the installed configuration.

## Incremental changes

### 1. Make every production source independently vendorable

1. Replace curl's generated path patches for `cc` and `ring` with their pinned
   Motor Git patch declarations. Cross-build curl with Linux-hosted Cargo,
   which performs ring's host-only Git source-generation step.
2. Keep curl installed as Lorry's network transport, but do not ship its source
   as part of the Motor-native Lorry surface.
3. Verify the canonical Red, Gears, and Lorry source trees can all vendor their
   crates.io and Git inputs without a preinstalled repository. In particular,
   Gears exercises a Git patch and Lorry exercises direct Git dependencies.

### 2. Remove seed payloads and Python from normal image construction

1. Add tracked Motor system and user configurations containing the writable
   user repository, native tools, network locations, limits, and minimal
   capability grants described above.
2. Stop `src/build-motor-os.sh` from checking for or invoking the Stage 2 seed
   installer. The generated Rust toolchain root will contain rustc and its
   sysroot, but no `/devtools/lorry/vendor` payload or generated Lorry policy.
3. Eliminate `prepare_dev_sources.py`. Point the imager directly at the
   supported canonical source directories and preserve their repository-relative layout
   below `/devtools/src`, so their `moto-rt` and `moto-sys` paths need no Python
   rewriting. Do not materialize any `.lorry/vendor` directories in the image.
4. Remove the phony `dev-sources` Make target and its build staging directory.
5. Update the developer-image contract test to assert the seed repository,
   curl source, and materialized dependency trees are absent, perform online
   `lorry vendor` before each supported first build, and prove a natively built
   Lorry can rebuild Gears from the populated writable repository.

### 3. Retire the production bootstrap implementation

1. Delete the Stage 2 manifest, repository installer/generator, source-tree
   Python implementation, templates, and their production-specific tests.
2. Replace Lorry contracts that currently install the Python seed with
   deterministic local acquisition fixtures. Regular tests will remain
   Internet-free: the existing fake crates.io curl and local Git smart-HTTP
   fixture will provide the exact archives and Git objects needed by each
   contract.
3. Keep source-tree digest vectors only where they validate the Rust Lorry
   implementation; remove Python-oracle coverage and duplicate packaging
   behavior.
4. Rename remaining `build/lorry/stage2` paths that are merely host build or
   test workspaces so they no longer imply a dependency seed.

### 4. Update product documentation and acceptance claims

1. Remove the offline-from-first-boot and system-seed claims from Lorry's
   README, specification, and design documentation.
2. Document that `build`, `run`, `test`, and `review` remain offline, while a
   fresh image must run networked `vendor` once.
3. Update image-layout and native-build documentation to distinguish installed
   tools and first-party source snapshots from downloaded dependency state.
4. Treat historical plan documents as historical unless they are currently
   used as normative build instructions; update current assertions and test
   descriptions that would otherwise contradict the new contract.

## Validation

During implementation, use the focused Lorry Git, registry, curl, review, and
native contracts. Regular component contracts remain Internet-free; explicit
fresh-image acceptance gates contact crates.io and GitHub.

Before handoff:

1. Run `cargo fmt` for affected Rust sources.
2. Run the complete Lorry component gate, `src/bin/lorry/tests/test-all.sh`.
3. Build debug and release developer images.
4. Run `src/tests/full-test-dev.sh` against both images and verify a fresh
   image has no system seed, vendors successfully with explicitly enabled
   network fixtures/access, and then builds offline.
5. Run the broader debug and release repository gates required because the
   Makefile, imager, and image test harness change.

No changes will be committed.
