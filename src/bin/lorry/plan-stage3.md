# Lorry Stage 3 plan

Stage 2 is complete; Stage 3 has not started. Its detailed package and
sandbox scope remains subject to review; this file records the accepted
direction for Git acquisition so that the temporary Stage 2 bridge does not
become the permanent design by accident.

## Multiple binary selection

Stage 3 should support packages with multiple binary targets and add
`--bin NAME` to the commands for which Cargo defines it. A string
`package.default-run` must name a declared binary and should select that binary
when `lorry run` has no explicit `--bin`; without either selection, an
ambiguous multi-binary run must fail with an actionable diagnostic. The exact
build and test selection rules and their Cargo-compatibility gates require
review before implementation.

## Motor-native Git acquisition

Stage 3 should replace Stage 2's Linux-only use of the installed `git`
executable with a small Motor-native `git-light` program. Lorry needs source
materialization, not a general repository workbench, so the initial command
should fetch one requested revision and atomically publish its source tree:

```text
git-light materialize <https-url> <branch-or-tag-or-revision> <destination>
```

The bounded first implementation should support anonymous HTTPS, Git protocol
v2, SHA-1 repositories, one advertised branch/tag/revision, and a complete
checkout of the selected commit. It should emit the canonical URL, requested
revision, resolved commit, Git tree, and Lorry SHA-256 source-tree digest.
Authentication, pushes, working-copy commands, submodules, symbolic links,
Git LFS, alternates, partial repositories, and SHA-256 Git repositories remain
outside the first increment.

The network protocol is the smaller part: smart HTTP needs capability and
reference discovery, pkt-line framing, `ls-refs`, and `fetch`. The main risk is
the pack reader. It must bound and verify the pack header/trailer, object count,
inflated sizes, total bytes, delta depth, and both `OFS_DELTA` and `REF_DELTA`
resolution. It must reconstruct and hash every object before traversing the
selected commit and tree, and reject malformed modes, duplicate or unsafe
paths, links, submodules, missing bases, cycles, truncation, and trailing data.

Motor curl currently implements the fixed GET surface needed by Lorry. Smart
Git HTTP additionally needs bounded POST request bodies, caller-selected safe
headers, and binary response streaming. That transport work should remain in
the curl library rather than being duplicated in `git-light`. Reusing the
already reviewed Rust DEFLATE implementation is preferred; Git SHA-1 is small
enough to implement locally, while the published source receives Lorry's
stronger canonical SHA-256 tree identity before admission.

Tests must use deterministic local TLS fixtures, not a public forge. They need
valid base and deltified packs plus malformed, truncated, oversized,
hash-invalid, deeply nested, cyclic, unsafe-tree, link, and submodule cases.
Linux and Motor must materialize the same fixture to byte-identical canonical
source trees.

An initial bounded implementation is expected to be roughly 4,000–7,000 lines
and several weeks of work. A generally compatible `git clone` implementation,
including authentication, protocol fallbacks, reusable object stores and
normal working-copy behavior, is a separate multi-month project and is not a
Stage 3 prerequisite.

## Stage 2 compatibility bridge

Stage 2 build, run, and test commands continue to reject Git dependencies and
Git patches and never invoke the network. An actionable diagnostic directs an
unmaterialized root `[patch.crates-io]` Git entry to `lorry vendor`.

On Linux only, Stage 2 `lorry vendor` may invoke the locally installed `git`
executable with a cleared configuration and environment, bounded output, and a
deadline. It resolves the requested branch, tag, or revision to a commit,
materializes a private source tree, verifies it with Lorry's normal source-tree
limits, records its Git and SHA-256 provenance, and atomically replaces the Git
patch declaration with `.lorry/vendor/<patch>/source`. Direct Git dependencies
remain unsupported.

Motor `lorry vendor` continues to vendor ordinary crates.io graphs. It returns
an explicit unsupported diagnostic only when an unmaterialized Git patch
requires Git acquisition. A project vendored on Linux is therefore portable to
Motor and builds there without `git`, Cargo caches, or network access.

This bridge must be deleted when `git-light` supplies the same verified
materialization contract on both platforms.
